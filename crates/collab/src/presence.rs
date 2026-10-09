//! Remote cursors: who else is in the document and where they are.

use std::collections::BTreeMap;

/// One other author in the document.
#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub author: String,
    pub name: String,
    /// Stable display colour, derived from the author id.
    pub color: [u8; 3],
    /// The peer's cursor as the app encoded it, `None` when the peer's
    /// cursor is unknown.
    pub position: Option<String>,
}

/// Everyone else in the document, by author id.
#[derive(Default)]
pub struct Presence {
    peers: BTreeMap<String, Peer>,
}

impl Presence {
    /// Records a peer, or updates its name/position when it is already known.
    pub fn set(&mut self, author: &str, name: &str, position: Option<String>) {
        let color = color_for(author);
        self.peers
            .entry(author.to_string())
            .and_modify(|p| {
                p.name = name.to_string();
                p.position = position.clone();
            })
            .or_insert_with(|| Peer { author: author.to_string(), name: name.to_string(), color, position });
    }

    /// Forgets a peer.
    pub fn remove(&mut self, author: &str) {
        self.peers.remove(author);
    }

    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// A stable colour for an author id: FNV-1a, kept out of the darkest range.
pub fn color_for(author: &str) -> [u8; 3] {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in author.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let r = 96 + (h & 0x5f) as u8;
    let g = 96 + ((h >> 16) & 0x5f) as u8;
    let b = 96 + ((h >> 32) & 0x5f) as u8;
    [r, g, b]
}
