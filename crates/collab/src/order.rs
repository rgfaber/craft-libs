//! Per-author message ordering.
//!
//! Every message carries its author's sequence number, within this process's
//! epoch. Text updates are order-insensitive, but a command must be applied
//! after the messages its author sent before it, and exactly once: this
//! buffer delivers one author's messages in sequence, holding a gap until it
//! fills, and drops anything already delivered.
//!
//! A subscriber that joins mid-stream never sees seq 1: the first message
//! heard from an author and epoch sets the base, and order is enforced from
//! there. Messages from before the join are not recoverable (pubsub has no
//! replay); a joiner catches up through the document snapshot instead.
//!
//! Epochs separate a peer's sessions: a restarted process (same author id,
//! fresh epoch, seq back at 1) delivers as its own stream and neither
//! blocks nor is dropped by the old one.

use std::collections::{BTreeSet, HashMap};

use crate::message::Message;
use crate::session::now_ms;

/// How many messages one author may hold out of order before the oldest is
/// dropped (a peer that never fills its gap must not grow this without bound).
const HELD_LIMIT: usize = 512;

/// How long a stream may stay stalled before the session recovers it. Long
/// enough for an in-flight message to still arrive in order, short enough
/// that a person is not left editing into a void.
pub const STALL_DEADLINE_MS: u64 = 5_000;

/// One author+epoch stream.
type Stream = (String, u64);

/// Reorders messages by author, epoch and seq.
///
/// A gap that never fills used to hold that author's later messages forever:
/// one message lost on the way cost every later edit from that person, for
/// the rest of the session (rgfaber/craft-libs#2). The buffer now says how
/// long a stream has been stuck, and can give up on it, so the session can
/// recover by a state exchange and hear that author again.
#[derive(Default)]
pub struct OrderBuffer {
    /// The next seq awaited per stream, set from the first message heard.
    next: HashMap<Stream, u64>,
    /// Messages whose gap has not filled yet, per stream.
    held: HashMap<Stream, Vec<Message>>,
    /// When each stalled stream first failed to advance, in milliseconds.
    stalled: HashMap<Stream, u64>,
    /// Sequence numbers delivered out of band, per stream: the snapshot
    /// traffic skips the queue but still occupies its place in the author's
    /// sequence, so the stream moves through it in turn rather than jumping
    /// over the messages it is standing between (craft-libs#2, Uranus r1).
    filled: HashMap<Stream, BTreeSet<u64>>,
}

impl OrderBuffer {
    /// Adds `msg` and returns every message now deliverable, in order.
    pub fn push(&mut self, msg: Message) -> Vec<Message> {
        self.push_at(msg, now_ms())
    }

    /// [`push`](OrderBuffer::push), with the clock given: what the tests use,
    /// and what a caller replaying recorded traffic needs.
    pub fn push_at(&mut self, msg: Message, now_ms: u64) -> Vec<Message> {
        let stream: Stream = (msg.author.clone(), msg.epoch);
        let Some(&next) = self.next.get(&stream) else {
            // First message from this stream: its seq is the base.
            self.next.insert(stream, msg.seq + 1);
            return vec![msg];
        };
        if msg.seq < next {
            return Vec::new(); // already delivered
        }
        let held = self.held.entry(stream.clone()).or_default();
        if held.iter().all(|m| m.seq != msg.seq) {
            held.push(msg);
            if held.len() > HELD_LIMIT {
                held.remove(0);
            }
        }
        // A stream that already had a start keeps it: the wait is measured
        // from when the hole opened, not from the latest arrival.
        self.stalled.entry(stream).or_insert(now_ms);
        self.drain()
    }

    /// Notes a message that skipped the queue: it is delivered at once, but it
    /// keeps its place in the author's sequence. `next` does not move past a
    /// message that has not been delivered, so an earlier message arriving
    /// later is still delivered rather than being mistaken for a duplicate,
    /// and a later one still waits for the hole in front of it. Returns
    /// whatever became deliverable.
    pub fn observe(&mut self, author: &str, epoch: u64, seq: u64) -> Vec<Message> {
        self.observe_at(author, epoch, seq, now_ms())
    }

    /// [`observe`](OrderBuffer::observe), with the clock given.
    pub fn observe_at(&mut self, author: &str, epoch: u64, seq: u64, now_ms: u64) -> Vec<Message> {
        let stream: Stream = (author.to_string(), epoch);
        let Some(&next) = self.next.get(&stream) else {
            // The first thing heard from this stream sets its base, exactly as
            // a first queued message would.
            self.next.insert(stream, seq + 1);
            return Vec::new();
        };
        if seq < next {
            return Vec::new(); // already behind us
        }
        let filled = self.filled.entry(stream.clone()).or_default();
        filled.insert(seq);
        if filled.len() > HELD_LIMIT {
            filled.pop_first();
        }
        // A hole in front of it is a stall like any other: the stream cannot
        // move, and the session has to know so it can recover it.
        self.stalled.entry(stream).or_insert(now_ms);
        self.drain()
    }

    /// The messages held for authors whose gap has not filled.
    pub fn held(&self) -> usize {
        self.held.values().map(Vec::len).sum()
    }

    /// How many authors are waiting behind a gap.
    pub fn gaps(&self) -> usize {
        self.held.values().filter(|held| !held.is_empty()).count()
    }

    /// How long the longest-open gap has been open, in milliseconds:
    /// `None` when nothing is stuck.
    pub fn stalled_for(&self, now_ms: u64) -> Option<u64> {
        self.stalled.values().map(|since| now_ms.saturating_sub(*since)).max()
    }

    /// Whether any author has been stuck past [`STALL_DEADLINE_MS`].
    pub fn stalled_past_deadline(&self, now_ms: u64) -> bool {
        self.stalled_for(now_ms).is_some_and(|waited| waited >= STALL_DEADLINE_MS)
    }

    /// Moves every open stall back in time, so a test reaches the deadline
    /// without waiting for it.
    #[cfg(test)]
    pub(crate) fn backdate_stall(&mut self, by_ms: u64) {
        for since in self.stalled.values_mut() {
            *since = since.saturating_sub(by_ms);
        }
    }

    /// Gives up on every stalled stream: what it held is dropped and its
    /// sequence restarts from the next message heard, so an author whose one
    /// message was lost can be heard again. Returns how many messages were
    /// given up.
    ///
    /// The caller owes the document a state exchange for anything the hole
    /// swallowed: this restores hearing, not the missing edit.
    pub fn forget_stalled(&mut self) -> usize {
        let streams: Vec<Stream> = self.stalled.keys().cloned().collect();
        let mut dropped = 0;
        for stream in streams {
            dropped += self.held.remove(&stream).map_or(0, |held| held.len());
            self.next.remove(&stream);
            self.stalled.remove(&stream);
            self.filled.remove(&stream);
        }
        dropped
    }

    /// Every held message that now follows its stream's high-water mark, and
    /// every out-of-band sequence the stream can now move past.
    fn drain(&mut self) -> Vec<Message> {
        let mut out = Vec::new();
        loop {
            let mut progressed = false;
            let mut streams: Vec<Stream> = self.held.keys().cloned().collect();
            streams.extend(self.filled.keys().cloned());
            streams.sort_unstable();
            streams.dedup();
            for stream in streams {
                let next = *self.next.get(&stream).unwrap_or(&1);
                // Something delivered out of band sits in this place: the
                // stream moves through it and emits nothing.
                if self.filled.get_mut(&stream).is_some_and(|filled| filled.remove(&next)) {
                    self.next.insert(stream.clone(), next + 1);
                    progressed = true;
                    continue;
                }
                if let Some(held) = self.held.get_mut(&stream)
                    && let Some(pos) = held.iter().position(|m| m.seq == next)
                {
                    out.push(held.remove(pos));
                    self.next.insert(stream.clone(), next + 1);
                    progressed = true;
                }
            }
            if !progressed {
                break;
            }
        }
        // A stream with nothing left in front of it is no longer stuck; the
        // next hole in it is timed from its own start.
        let recovered: Vec<Stream> = self
            .stalled
            .keys()
            .filter(|stream| {
                let held_left = self.held.get(*stream).is_some_and(|held| !held.is_empty());
                let filled_left = self.filled.get(*stream).is_some_and(|filled| !filled.is_empty());
                !held_left && !filled_left
            })
            .cloned()
            .collect();
        for stream in recovered {
            self.stalled.remove(&stream);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Kind;

    fn msg(author: &str, seq: u64) -> Message {
        msg_epoch(author, 0, seq)
    }

    fn msg_epoch(author: &str, epoch: u64, seq: u64) -> Message {
        Message { doc: "d".into(), author: author.into(), epoch, seq, sent_at_ms: 0, kind: Kind::CursorMoved { position: None, name: None } }
    }

    #[test]
    fn one_authors_messages_deliver_in_order_once() {
        let mut b = OrderBuffer::default();
        let out = b.push(msg("a", 5));
        assert_eq!(out.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![5], "the first message heard sets the base");
        assert!(b.push(msg("a", 5)).is_empty(), "a repeat is dropped");
        assert!(b.push(msg("a", 7)).is_empty(), "7 waits for 6");
        let out = b.push(msg("a", 6));
        assert_eq!(out.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![6, 7], "the gap fills in order");
        let out = b.push(msg("a", 8));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq, 8);
    }

    #[test]
    fn authors_do_not_block_each_other() {
        let mut b = OrderBuffer::default();
        assert!(b.push(msg("a", 2)).len() == 1, "a's first delivers");
        let out = b.push(msg("c", 1));
        assert_eq!(out.len(), 1, "c's first delivers too");
        assert_eq!(out[0].author, "c");
    }

    #[test]
    fn a_new_epoch_is_its_own_stream() {
        let mut b = OrderBuffer::default();
        let out = b.push(msg_epoch("a", 1, 7));
        assert_eq!(out.len(), 1, "epoch 1's first delivers");
        assert!(b.push(msg_epoch("a", 1, 9)).is_empty(), "a gap in epoch 1 holds");
        // The peer restarts: same author, new epoch, seq back at 1.
        let out = b.push(msg_epoch("a", 2, 1));
        assert_eq!(out.len(), 1, "the new session delivers while the old epoch's gap is open");
        assert_eq!(out[0].seq, 1);
        let out = b.push(msg_epoch("a", 2, 2));
        assert_eq!(out.len(), 1, "and its sequence is enforced separately");
        assert_eq!(out[0].seq, 2);
    }

    #[test]
    fn a_stream_stuck_behind_a_gap_says_so_and_how_long() {
        let mut b = OrderBuffer::default();
        assert_eq!(b.push_at(msg("a", 5), 0).len(), 1, "in order, nothing is held");
        assert_eq!(b.stalled_for(0), None, "nothing is stuck");
        assert!(b.push_at(msg("a", 7), 1_000).is_empty(), "7 waits for the lost 6");
        assert_eq!(b.held(), 1);
        assert_eq!(b.gaps(), 1);
        assert_eq!(b.stalled_for(1_500), Some(500), "timed from when the hole opened, not the latest arrival");
        assert!(!b.stalled_past_deadline(5_000), "a second of waiting is not a stall");
        assert!(b.stalled_past_deadline(6_000), "past the deadline it is");
    }

    #[test]
    fn a_gap_that_fills_stops_being_a_stall() {
        let mut b = OrderBuffer::default();
        b.push_at(msg("a", 5), 0);
        b.push_at(msg("a", 7), 1_000);
        assert_eq!(b.push_at(msg("a", 6), 1_200).len(), 2, "the hole filled and both went out");
        assert_eq!(b.held(), 0);
        assert_eq!(b.stalled_for(60_000), None, "the stream is not stuck any more");
    }

    #[test]
    fn forgetting_a_stalled_stream_lets_its_author_be_heard_again() {
        let mut b = OrderBuffer::default();
        b.push_at(msg("a", 5), 0);
        assert!(b.push_at(msg("a", 7), 1_000).is_empty(), "7 waits for a 6 that was lost");
        assert!(b.push_at(msg("a", 8), 1_100).is_empty(), "and so does 8");
        assert_eq!(b.held(), 2);
        assert_eq!(b.forget_stalled(), 2, "both held messages are given up");
        assert_eq!(b.held(), 0);
        assert_eq!(b.gaps(), 0);
        let out = b.push_at(msg("a", 9), 20_000);
        assert_eq!(out.len(), 1, "the next message is heard instead of held");
        assert_eq!(out[0].seq, 9);
    }

    #[test]
    fn one_stuck_author_does_not_hide_another() {
        let mut b = OrderBuffer::default();
        b.push_at(msg("a", 5), 0);
        b.push_at(msg("a", 7), 1_000);
        assert_eq!(b.push_at(msg("c", 1), 1_000).len(), 1, "c is heard while a is stuck");
        assert_eq!(b.gaps(), 1, "only a is a gap");
        assert_eq!(b.forget_stalled(), 1, "giving up on a leaves c alone");
        assert_eq!(b.push_at(msg("c", 2), 30_000).len(), 1, "c keeps its sequence");
    }

    /// Uranus r1, probe (a): a message delivered out of band takes its place
    /// in the sequence, and does not run ahead of an earlier one still in
    /// flight. Jumping `next` would make the earlier one look delivered.
    #[test]
    fn a_message_delivered_out_of_band_does_not_jump_an_earlier_one() {
        let mut b = OrderBuffer::default();
        assert_eq!(b.push_at(msg("a", 5), 0).len(), 1, "5 is in order");
        assert!(b.observe_at("a", 0, 7, 100).is_empty(), "7 crosses, nothing to release yet");
        let out = b.push_at(msg("a", 6), 200);
        assert_eq!(out.len(), 1, "6 arrives late and is delivered, not mistaken for a duplicate");
        assert_eq!(out[0].seq, 6);
        assert_eq!(b.held(), 0);
    }

    /// Uranus r1, probe (b): an out-of-band message beyond a hole must not
    /// strand what is held behind that hole.
    #[test]
    fn a_message_delivered_out_of_band_does_not_strand_what_is_held() {
        let mut b = OrderBuffer::default();
        b.push_at(msg("a", 5), 0);
        assert!(b.push_at(msg("a", 7), 10).is_empty(), "7 waits for the lost 6");
        assert_eq!(b.held(), 1);
        assert!(b.observe_at("a", 0, 8, 20).is_empty(), "8 crosses while the hole is still open");
        let out = b.push_at(msg("a", 6), 30);
        assert_eq!(out.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![6, 7], "6 and the held 7 both come through");
        assert_eq!(b.held(), 0);
        assert_eq!(b.gaps(), 0);
    }
}
