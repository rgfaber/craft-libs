//! Per-author message ordering.
//!
//! Every message carries its author's sequence number. Text updates are
//! order-insensitive, but a command must be applied after the messages its
//! author sent before it, and exactly once: this buffer delivers one
//! author's messages in sequence, holding a gap until it fills, and drops
//! anything already delivered.
//!
//! A subscriber that joins mid-stream never sees seq 1: the first message
//! heard from an author sets that author's base, and order is enforced from
//! there. Messages from before the join are not recoverable (pubsub has no
//! replay); a joiner catches up through the document snapshot instead.

use std::collections::HashMap;

use crate::message::Message;

/// How many messages one author may hold out of order before the oldest is
/// dropped (a peer that never fills its gap must not grow this without bound).
const HELD_LIMIT: usize = 512;

/// Reorders messages by author and seq.
#[derive(Default)]
pub struct OrderBuffer {
    /// The next seq awaited per author, set from the first message heard.
    next: HashMap<String, u64>,
    /// Messages whose gap has not filled yet, per author.
    held: HashMap<String, Vec<Message>>,
}

impl OrderBuffer {
    /// Adds `msg` and returns every message now deliverable, in order.
    pub fn push(&mut self, msg: Message) -> Vec<Message> {
        let Some(&next) = self.next.get(&msg.author) else {
            // First message from this author: its seq is the base.
            self.next.insert(msg.author.clone(), msg.seq + 1);
            return vec![msg];
        };
        if msg.seq < next {
            return Vec::new(); // already delivered
        }
        let held = self.held.entry(msg.author.clone()).or_default();
        if held.iter().all(|m| m.seq != msg.seq) {
            held.push(msg);
            if held.len() > HELD_LIMIT {
                held.remove(0);
            }
        }
        self.drain()
    }

    /// Every held message that now follows its author's high-water mark.
    fn drain(&mut self) -> Vec<Message> {
        let mut out = Vec::new();
        loop {
            let mut progressed = false;
            let authors: Vec<String> = self.held.keys().cloned().collect();
            for author in authors {
                let next = *self.next.get(&author).unwrap_or(&1);
                if let Some(held) = self.held.get_mut(&author)
                    && let Some(pos) = held.iter().position(|m| m.seq == next)
                {
                    out.push(held.remove(pos));
                    self.next.insert(author.clone(), next + 1);
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
        Message { doc: "d".into(), author: author.into(), seq, sent_at_ms: 0, kind: Kind::CursorMoved { position: None, name: None } }
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
}
