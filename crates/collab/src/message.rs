//! The op envelope: what peers exchange.

use serde::{Deserialize, Serialize};

/// One collaboration message. It names its document, its author and a
/// per-author sequence number; the [`Kind`] is what it carries.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// The document this message belongs to.
    pub doc: String,
    /// The author's stable id (the mesh node id, hex).
    pub author: String,
    /// Per-author sequence number, 1 upwards.
    pub seq: u64,
    /// What the message carries.
    pub kind: Kind,
}

/// A message's payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kind {
    /// A paragraph text change, as a CRDT update. The update is
    /// position-independent: peers may apply it in any order, once.
    TextEdit { para: String, update: Vec<u8> },
    /// Where the author's cursor is now: an app-encoded position, opaque to
    /// the mechanism.
    CursorMoved { position: Option<String> },
}
