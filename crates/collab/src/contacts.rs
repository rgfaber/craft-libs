//! The people this device has met through collaboration: a node id, the
//! display name they gave, when we last saw them and, when known, the realm.
//!
//! Local data with a JSON codec, so the seam stays wasm-clean and the
//! filesystem stays the app's business. The sources are the flows the apps
//! already run: a join request names its person, an approved grant names its
//! holder, and an invite names its host.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How many entries a store keeps: whatever arrives from the network, a
/// hostile file or an endless stream of joiners cannot balloon memory.
const MAX_CONTACTS: usize = 1024;

/// A display name is a label, not a document: cap what we keep.
const MAX_NAME_CHARS: usize = 120;

/// One remembered person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// The person's node id (hex).
    pub node: String,
    /// The display name they last gave (may be empty).
    pub name: String,
    /// When this device last saw them (ms since the epoch; 0 when unknown).
    pub last_seen_ms: u64,
    /// The realm name, when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

/// The remembered people, one entry per node id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contacts {
    entries: BTreeMap<String, Contact>,
}

impl Contacts {
    pub fn new() -> Contacts {
        Contacts::default()
    }

    /// Remembers a person: their node id, the name they gave (empty keeps
    /// the stored one), the realm when known, and when we saw them. A later
    /// sighting updates the entry in place; it never duplicates the person.
    pub fn upsert(&mut self, node: &str, name: &str, realm: Option<&str>, now_ms: u64) {
        let node = node.trim().to_ascii_lowercase();
        if node.is_empty() {
            return;
        }
        if !self.entries.contains_key(&node) && self.entries.len() >= MAX_CONTACTS {
            // At the cap, the least recently seen person makes room.
            if let Some(oldest) = self.entries.iter().min_by_key(|(_, c)| c.last_seen_ms).map(|(node, _)| node.clone()) {
                self.entries.remove(&oldest);
            }
        }
        let entry = self.entries.entry(node.clone()).or_insert_with(|| Contact { node, name: String::new(), last_seen_ms: 0, realm: None });
        let name = name.trim();
        if !name.is_empty() {
            entry.name = name.chars().take(MAX_NAME_CHARS).collect();
        }
        if let Some(realm) = realm.map(str::trim).filter(|realm| !realm.is_empty()) {
            entry.realm = Some(realm.to_string());
        }
        entry.last_seen_ms = now_ms.max(entry.last_seen_ms);
    }

    /// Forgets a person; true when one was known.
    pub fn remove(&mut self, node: &str) -> bool {
        self.entries.remove(&node.trim().to_ascii_lowercase()).is_some()
    }

    /// Whether this person is known.
    pub fn contains(&self, node: &str) -> bool {
        self.entries.contains_key(&node.trim().to_ascii_lowercase())
    }

    /// The known people, most recently seen first (ties by node id).
    pub fn list(&self) -> Vec<Contact> {
        let mut all: Vec<Contact> = self.entries.values().cloned().collect();
        all.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms).then_with(|| a.node.cmp(&b.node)));
        all
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The store as JSON (a JSON array of contacts).
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.list()).unwrap_or_default()
    }

    /// Reads a store from JSON. Malformed input yields an empty store: a
    /// local cache never takes collaboration down.
    pub fn from_json(text: &str) -> Contacts {
        let mut contacts = Contacts::new();
        let Ok(list) = serde_json::from_str::<Vec<Contact>>(text) else { return contacts };
        for entry in list.into_iter().take(MAX_CONTACTS) {
            contacts.upsert(&entry.node, &entry.name, entry.realm.as_deref(), entry.last_seen_ms);
        }
        contacts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_person_is_remembered_once_and_keeps_their_latest_name() {
        let mut contacts = Contacts::new();
        contacts.upsert("BBBB", "Bob", None, 100);
        contacts.upsert("bbbb", "Robert", None, 200);
        let all = contacts.list();
        assert_eq!(all.len(), 1, "one entry per node id, case-insensitive");
        assert_eq!(all[0].name, "Robert", "the latest name wins");
        assert_eq!(all[0].last_seen_ms, 200);

        contacts.upsert("bbbb", "  ", None, 300);
        let all = contacts.list();
        assert_eq!(all[0].name, "Robert", "an empty name keeps the stored one");
        assert_eq!(all[0].last_seen_ms, 300, "a later sighting moves the person up");
    }

    #[test]
    fn the_most_recently_seen_person_is_listed_first() {
        let mut contacts = Contacts::new();
        contacts.upsert("aaaa", "Alice", Some("io.macula"), 100);
        contacts.upsert("bbbb", "Bob", None, 200);
        let all = contacts.list();
        assert_eq!(all[0].name, "Bob", "most recent first");
        assert_eq!(all[1].realm.as_deref(), Some("io.macula"));
        assert!(contacts.contains("aaaa") && contacts.contains("AAAA"));
    }

    #[test]
    fn a_store_round_trips_and_a_malformed_file_is_simply_empty() {
        let mut contacts = Contacts::new();
        contacts.upsert("aaaa", "Alice", Some("io.macula"), 100);
        contacts.upsert("bbbb", "Bob", None, 200);
        let back = Contacts::from_json(&contacts.to_json());
        assert_eq!(back, contacts);

        assert!(Contacts::from_json("not json").is_empty(), "malformed input never errors");
        assert!(Contacts::from_json(r#"[{"node":"  ","name":"x","last_seen_ms":1}]"#).is_empty(), "an empty node id is skipped");
        assert!(Contacts::from_json("[]").is_empty());
    }

    #[test]
    fn a_person_can_be_forgotten() {
        let mut contacts = Contacts::new();
        contacts.upsert("aaaa", "Alice", None, 1);
        assert!(contacts.remove("AAAA"), "forgetting is case-insensitive");
        assert!(!contacts.remove("aaaa"), "a second forget is a no-op");
        assert!(contacts.is_empty());
    }

    #[test]
    fn the_store_stays_bounded_however_many_joiners_arrive() {
        let mut contacts = Contacts::new();
        for i in 0..(MAX_CONTACTS + 10) {
            contacts.upsert(&format!("{i:064x}"), "", None, i as u64);
        }
        assert_eq!(contacts.len(), MAX_CONTACTS, "the store keeps its cap");
        assert!(!contacts.contains(&format!("{:064x}", 0)), "the least recently seen made room");
        assert!(contacts.contains(&format!("{:064x}", MAX_CONTACTS + 9)), "the newest person is kept");
    }
}
