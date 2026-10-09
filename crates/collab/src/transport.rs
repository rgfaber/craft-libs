//! What carries messages between peers.
//!
//! The mesh implementation lives in `macula-craft-collab` (macula-rust,
//! released crates only); tests use an in-memory implementation.

use crate::message::Message;

/// A two-way message transport bound to one document. `send` queues and
/// never blocks on the network; `poll` drains what arrived since the last
/// call.
pub trait Transport: Send {
    /// This node's author id (hex).
    fn author(&self) -> String;
    /// Queues `msg` for delivery to the document's other peers.
    fn send(&mut self, msg: Message) -> Result<(), String>;
    /// Takes the messages that arrived since the last poll.
    fn poll(&mut self) -> Vec<Message>;
}
