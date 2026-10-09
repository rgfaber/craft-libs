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
    /// When the sender made it, milliseconds since the epoch: peer latency
    /// is the receiver's clock minus this (0 when unknown).
    #[serde(default)]
    pub sent_at_ms: u64,
    /// What the message carries.
    pub kind: Kind,
}

/// A message's payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Kind {
    /// A paragraph text change, as a CRDT update. The update is
    /// position-independent: peers may apply it in any order, once. When the
    /// sender knows the inserted text's formatting (its own typing), it
    /// carries it so the peer's runs match; `None` lets the receiver infer.
    TextEdit { para: String, update: Vec<u8>, props: Option<Vec<u8>> },
    /// Where the author's cursor is now: an app-encoded position, opaque to
    /// the mechanism, plus the display name to show next to it.
    CursorMoved { position: Option<String>, name: Option<String> },
    /// An app command to replay on the peers: its id, its params as the
    /// app's JSON, and the selection it ran under (app-encoded), so a
    /// position-carrying command can be applied as it was issued.
    Command { id: String, params: Vec<u8>, anchor: Option<String> },
    /// A peer joining asks for the shared document's current state.
    SnapshotRequest {},
    /// The document's current state, as the app's [`DocAdapter`] encodes it
    /// (stable ids included), plus this CRDT's every change, so a joining
    /// peer starts aligned and keeps merging.
    ///
    /// [`DocAdapter`]: crate::host::DocAdapter
    Snapshot { data: Vec<u8>, crdt: Vec<u8> },
}
