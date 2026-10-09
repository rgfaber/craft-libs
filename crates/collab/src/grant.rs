//! Per-document grants and the session's access table.
//!
//! An invite is a host-signed [`Grant`]: this document, this holder, one
//! role, an expiry. The host signs it with its identity key (the crypto
//! lives in the transport adapter, which owns the identity); every replica
//! checks on **every** message that its verified author is the holder of a
//! live grant, so a stranger (or a revoked holder) cannot edit.
//!
//! The envelope author a message carries must be the *verified* publisher
//! identity the transport attached (macula's publication signature); the
//! access check here is against that verified author, never a self-reported
//! one. Distributing grants to holders is the join flow's job; this module
//! is the grant and the check.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What a holder may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// May read and write.
    Editor,
    /// May read and move its cursor; no edits.
    Viewer,
}

impl Role {
    /// Whether this role may send `kind`.
    pub fn permits(self, kind: &crate::message::Kind) -> bool {
        use crate::message::Kind;
        match (self, kind) {
            // Either role may read, move its cursor and (re)join.
            (_, Kind::CursorMoved { .. }) | (_, Kind::SnapshotRequest {}) => true,
            (Role::Editor, Kind::TextEdit { .. }) | (Role::Editor, Kind::Command { .. }) => true,
            _ => false,
        }
    }
}

/// A host-signed permission for one holder on one document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    /// Layout version.
    pub v: u32,
    /// The document this grant is for.
    pub doc: String,
    /// The host's node id (hex), the signer.
    pub host: String,
    /// The holder's node id (hex).
    pub holder: String,
    pub role: Role,
    pub issued_ms: u64,
    /// After this the grant is no longer live and must be renewed.
    pub expires_ms: u64,
    /// Distinguishes otherwise identical grants.
    pub nonce: String,
}

impl Grant {
    /// Whether this grant is live at `now_ms`.
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.expires_ms > now_ms && self.issued_ms <= now_ms
    }

    /// The bytes a signature covers: the grant's canonical JSON. Both sides
    /// sign and verify exactly these (deterministic for this struct).
    pub fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| e.to_string())
    }
}

/// A grant with its host signature.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedGrant {
    pub grant: Grant,
    /// The host's signature over [`Grant::signed_bytes`].
    pub signature: Vec<u8>,
}

/// Who may act on this document, as every replica checks it: the host, plus
/// each holder with a live grant.
#[derive(Clone, Debug)]
pub struct Access {
    doc: String,
    host: String,
    holders: BTreeMap<String, Grant>,
}

/// What an access check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The verified author may send this message.
    Admitted,
    /// The author holds no grant for this document.
    UnknownHolder,
    /// The holder's grant has expired (it must be renewed).
    Expired,
    /// The holder's role does not permit this message.
    RoleRefused,
}

impl Admission {
    pub fn is_admitted(self) -> bool {
        self == Admission::Admitted
    }
}

impl Access {
    /// An access table for `doc` whose host is `host` (hex node id).
    pub fn new(doc: &str, host: &str) -> Self {
        Access { doc: doc.to_string(), host: host.to_string(), holders: BTreeMap::new() }
    }

    pub fn doc(&self) -> &str {
        &self.doc
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// Adds a verified grant: it must be for this document and name this
    /// host as its signer. The transport checks the signature before
    /// anything reaches this table.
    pub fn add(&mut self, grant: Grant) -> Result<(), String> {
        if grant.doc != self.doc {
            return Err("the grant names another document".into());
        }
        if grant.host != self.host {
            return Err("the grant names another host".into());
        }
        self.holders.insert(grant.holder.clone(), grant);
        Ok(())
    }

    /// Removes a holder (a revocation lands as removed grants).
    pub fn remove(&mut self, holder: &str) -> bool {
        self.holders.remove(holder).is_some()
    }

    /// Checks a message's **verified** author: the host is always admitted,
    /// a holder needs a live grant, and the role must permit the message.
    pub fn admits(&self, author: &str, kind: &crate::message::Kind, now_ms: u64) -> Admission {
        if author == self.host {
            return Admission::Admitted;
        }
        let Some(grant) = self.holders.get(author) else {
            return Admission::UnknownHolder;
        };
        if !grant.is_live(now_ms) {
            return Admission::Expired;
        }
        if !grant.role.permits(kind) {
            return Admission::RoleRefused;
        }
        Admission::Admitted
    }

    /// Whether `author` may receive a snapshot (a reader of any role, live).
    pub fn admits_reader(&self, author: &str, now_ms: u64) -> Admission {
        self.admits(author, &crate::message::Kind::SnapshotRequest {}, now_ms)
    }

    pub fn len(&self) -> usize {
        self.holders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.holders.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Kind;

    fn grant(doc: &str, host: &str, holder: &str, role: Role, issued: u64, expires: u64) -> Grant {
        Grant {
            v: 1,
            doc: doc.into(),
            host: host.into(),
            holder: holder.into(),
            role,
            issued_ms: issued,
            expires_ms: expires,
            nonce: format!("n-{holder}"),
        }
    }

    #[test]
    fn a_live_grant_admits_its_holder_and_the_host() {
        let mut access = Access::new("doc", "host");
        access.add(grant("doc", "host", "alice", Role::Editor, 100, 200)).expect("add");
        let edit = Kind::TextEdit { para: "1".into(), update: vec![1], props: None };
        assert!(access.admits("host", &edit, 150).is_admitted(), "the host always acts");
        assert!(access.admits("alice", &edit, 150).is_admitted(), "a live editor writes");
    }

    #[test]
    fn unknown_expired_and_role_refused_are_denied() {
        let mut access = Access::new("doc", "host");
        access.add(grant("doc", "host", "bob", Role::Viewer, 100, 200)).expect("add");
        let edit = Kind::TextEdit { para: "1".into(), update: vec![1], props: None };
        let cursor = Kind::CursorMoved { position: None, name: None };
        assert_eq!(access.admits("carol", &edit, 150), Admission::UnknownHolder);
        assert_eq!(access.admits("bob", &edit, 150), Admission::RoleRefused, "a viewer does not write");
        assert!(access.admits("bob", &cursor, 150).is_admitted(), "a viewer may move its cursor");
        assert_eq!(access.admits("bob", &cursor, 250), Admission::Expired);
        assert_eq!(access.admits_reader("bob", 250), Admission::Expired, "expiry also stops reads");
    }

    #[test]
    fn a_grant_for_another_doc_or_host_is_refused() {
        let mut access = Access::new("doc", "host");
        assert!(access.add(grant("other", "host", "erin", Role::Editor, 100, 200)).is_err());
        assert!(access.add(grant("doc", "other", "erin", Role::Editor, 100, 200)).is_err());
        assert!(access.add(grant("doc", "host", "erin", Role::Editor, 100, 200)).is_ok());
    }

    #[test]
    fn revocation_is_removal() {
        let mut access = Access::new("doc", "host");
        access.add(grant("doc", "host", "dave", Role::Editor, 100, 10_000)).expect("add");
        assert!(access.remove("dave"));
        assert_eq!(access.admits("dave", &Kind::CursorMoved { position: None, name: None }, 150), Admission::UnknownHolder);
    }
}
