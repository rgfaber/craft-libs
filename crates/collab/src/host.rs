//! The app side of the seam: origin-aware dispatch and the document adapter.

use serde_json::Value;

/// Why a command runs: because the local user asked, or because a peer's
/// message applied it. Remote commands must not enter the local undo
/// history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Local,
    Remote { author: String },
}

impl Origin {
    pub fn is_local(&self) -> bool {
        matches!(self, Origin::Local)
    }
}

/// An app session's single dispatch point, origin-aware. Every app already
/// has this function (`Session::run` / `Session::execute`); adopting the
/// seam means adding the origin argument to it.
pub trait CollabHost {
    fn dispatch(&mut self, id: &str, params: &Value, origin: Origin) -> Result<Value, String>;
}

/// The per-app view of its document: stable paragraph ids to text, and
/// snapshots for a peer that joins. Implemented once per app (wordcraft
/// first).
pub trait DocAdapter {
    /// A full-fidelity snapshot a joining peer can load.
    fn snapshot(&self) -> Vec<u8>;
    /// Replaces the document from a snapshot.
    fn load_snapshot(&mut self, bytes: &[u8]) -> Result<(), String>;
    /// The text of the paragraph with stable id `para`.
    fn paragraph(&self, para: &str) -> Option<String>;
    /// Replaces the text of paragraph `para` with the merged CRDT text.
    fn set_paragraph(&mut self, para: &str, text: &str);
}
