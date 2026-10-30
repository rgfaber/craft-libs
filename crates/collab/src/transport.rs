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
    /// This node's current realm membership UCAN, when the adapter renews
    /// one (macula-craft-collab does, every 10 minutes): what a joiner
    /// admitted by membership presents to have its grant extended. `None`
    /// keeps the membership the session joined with.
    fn membership(&self) -> Option<String> {
        None
    }
    /// How many publications this transport knows did not leave the machine:
    /// the ones it was asked to send and could not, whether because the share
    /// could not seal them or because no link would take them.
    ///
    /// What it counts is *unsent*, not *lost*: a message a lower layer
    /// accepted and then dropped is not in this number. An app shows the rise
    /// so a person is told their edit did not go out instead of watching it
    /// vanish (macula-craft-collab#39). `0` for a transport with no such
    /// notion, which is every in-memory one.
    fn refused_publications(&self) -> u64 {
        0
    }
}
