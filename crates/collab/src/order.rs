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

use std::collections::HashMap;

use crate::message::Message;

/// How many messages one author may hold out of order before the oldest is
/// dropped (a peer that never fills its gap must not grow this without bound).
const HELD_LIMIT: usize = 512;

/// One author+epoch stream.
type Stream = (String, u64);

/// Reorders messages by author, epoch and seq.
#[derive(Default)]
pub struct OrderBuffer {
    /// The next seq awaited per stream, set from the first message heard.
    next: HashMap<Stream, u64>,
    /// Messages whose gap has not filled yet, per stream.
    held: HashMap<Stream, Vec<Message>>,
}

impl OrderBuffer {
    /// Adds `msg` and returns every message now deliverable, in order.
    pub fn push(&mut self, msg: Message) -> Vec<Message> {
        let stream: Stream = (msg.author.clone(), msg.epoch);
        let Some(&next) = self.next.get(&stream) else {
            // First message from this stream: its seq is the base.
            self.next.insert(stream, msg.seq + 1);
            return vec![msg];
        };
        if msg.seq < next {
            return Vec::new(); // already delivered
        }
        let held = self.held.entry(stream).or_default();
        if held.iter().all(|m| m.seq != msg.seq) {
            held.push(msg);
            if held.len() > HELD_LIMIT {
                held.remove(0);
            }
        }
        self.drain()
    }

    /// Every held message that now follows its stream's high-water mark.
    fn drain(&mut self) -> Vec<Message> {
        let mut out = Vec::new();
        loop {
            let mut progressed = false;
            let streams: Vec<Stream> = self.held.keys().cloned().collect();
            for stream in streams {
                let next = *self.next.get(&stream).unwrap_or(&1);
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
}
