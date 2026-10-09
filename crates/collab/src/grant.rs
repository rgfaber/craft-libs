//! Per-document grants and the session's access table.
//!
//! An invite is a host-signed [`Grant`]: this document, this holder, one
//! role, an expiry, signed over a domain-separated canonical encoding. The
//! crypto lives in the transport adapter (which owns the identity and the
//! host's carried key); it implements [`GrantVerifier`], and an [`Access`]
//! table **installs grants only through [`Access::install`]**, which calls
//! that verifier first. There is no unverified install path.
//!
//! Installs are monotonic: a holder's grant is replaced only by a strictly
//! newer one (`issued_ms`, then `nonce`), so an out-of-order or replayed
//! renewal can neither downgrade a role nor shorten an expiry.
//!
//! Every replica checks on **every** message that its verified author is
//! the holder of a live grant, so a stranger (or a revoked holder) cannot
//! edit. The envelope author a message carries must be the *verified*
//! publisher identity the transport attached (macula's publication
//! signature); the access check is against that verified author, never a
//! self-reported one.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// The version every grant and every signature carries.
pub const GRANT_VERSION: u32 = 1;

/// The signature's domain separation: a grant signature covers this context
/// followed by the grant's canonical JSON, so it can never be replayed as a
/// signature over anything else.
pub const GRANT_CONTEXT: &[u8] = b"craft-collab/grant/v1";

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
    /// Layout version, [`GRANT_VERSION`].
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
    /// Distinguishes otherwise identical grants; the tie-break for installs
    /// with equal `issued_ms`.
    pub nonce: String,
}

impl Grant {
    /// Whether this grant is live at `now_ms`.
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.expires_ms > now_ms && self.issued_ms <= now_ms
    }

    /// The bytes a signature covers: the domain context, then the grant's
    /// canonical JSON. Both sides sign and verify exactly these.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::with_capacity(GRANT_CONTEXT.len() + 256);
        bytes.extend_from_slice(GRANT_CONTEXT);
        bytes.extend_from_slice(&serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(bytes)
    }
}

/// A grant with its host signature.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedGrant {
    pub grant: Grant,
    /// The host's signature over [`Grant::signed_bytes`].
    pub signature: Vec<u8>,
}

/// Verifies a signed grant's signature and returns the grant it carries.
/// The adapter implements this with the host's carried key; a table without
/// one cannot install anything.
pub trait GrantVerifier: Send + Sync {
    /// Verifies `signed` at `now_ms`: the signature under the host key, the
    /// host id it derives, the version and the expiry.
    fn verify(&self, signed: &SignedGrant, now_ms: u64) -> Result<Grant, String>;
}

/// Who may act on this document, as every replica checks it: the host, plus
/// each holder with a live grant.
#[derive(Clone)]
pub struct Access {
    doc: String,
    host: String,
    verifier: Option<Arc<dyn GrantVerifier>>,
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
    /// An access table for `doc` whose host is `host` (hex node id), with
    /// `verifier` checking every installed grant.
    pub fn new(doc: &str, host: &str, verifier: Arc<dyn GrantVerifier>) -> Self {
        Access { doc: doc.to_string(), host: host.to_string(), verifier: Some(verifier), holders: BTreeMap::new() }
    }

    pub fn doc(&self) -> &str {
        &self.doc
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// Installs a signed grant: the verifier must accept its signature, it
    /// must be for this document and this host, and it must be strictly
    /// newer than any grant already held for the holder. Nothing enters the
    /// table unverified.
    pub fn install(&mut self, signed: &SignedGrant, now_ms: u64) -> Result<(), String> {
        let verifier = self.verifier.clone().ok_or_else(|| "this access table has no grant verifier".to_string())?;
        let grant = verifier.verify(signed, now_ms)?;
        if grant.v != GRANT_VERSION {
            return Err(format!("unsupported grant version {}", grant.v));
        }
        if grant.doc != self.doc {
            return Err("the grant names another document".into());
        }
        if grant.host != self.host {
            return Err("the grant names another host".into());
        }
        self.install_newer(grant)
    }

    /// The monotonic step: replace only on a strictly newer grant.
    fn install_newer(&mut self, grant: Grant) -> Result<(), String> {
        match self.holders.get(&grant.holder) {
            None => {
                self.holders.insert(grant.holder.clone(), grant);
                Ok(())
            }
            Some(current) => {
                let newer = grant.issued_ms > current.issued_ms || (grant.issued_ms == current.issued_ms && grant.nonce > current.nonce);
                if newer {
                    self.holders.insert(grant.holder.clone(), grant);
                    Ok(())
                } else {
                    Err("a stale grant does not replace a newer one".into())
                }
            }
        }
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

    /// A stand-in for the adapter's key check: accepts "sig" on ok- grants.
    struct FakeVerifier;

    impl GrantVerifier for FakeVerifier {
        fn verify(&self, signed: &SignedGrant, now_ms: u64) -> Result<Grant, String> {
            if signed.signature != b"sig" {
                return Err("bad signature".into());
            }
            if !signed.grant.is_live(now_ms) {
                return Err("not live".into());
            }
            Ok(signed.grant.clone())
        }
    }

    fn table(doc: &str, host: &str) -> Access {
        Access::new(doc, host, Arc::new(FakeVerifier))
    }

    fn signed(doc: &str, host: &str, holder: &str, role: Role, issued: u64, expires: u64, nonce: &str) -> SignedGrant {
        SignedGrant {
            grant: Grant {
                v: GRANT_VERSION,
                doc: doc.into(),
                host: host.into(),
                holder: holder.into(),
                role,
                issued_ms: issued,
                expires_ms: expires,
                nonce: nonce.into(),
            },
            signature: b"sig".to_vec(),
        }
    }

    #[test]
    fn a_live_verified_grant_admits_its_holder_and_the_host() {
        let mut access = table("doc", "host");
        access.install(&signed("doc", "host", "alice", Role::Editor, 100, 200, "n1"), 150).expect("install");
        let edit = Kind::TextEdit { para: "1".into(), update: vec![1], props: None };
        assert!(access.admits("host", &edit, 150).is_admitted(), "the host always acts");
        assert!(access.admits("alice", &edit, 150).is_admitted(), "a live editor writes");
    }

    #[test]
    fn an_unverified_grant_is_refused() {
        let mut access = table("doc", "host");
        let forged = SignedGrant {
            grant: Grant {
                v: GRANT_VERSION,
                doc: "doc".into(),
                host: "host".into(),
                holder: "mallory".into(),
                role: Role::Editor,
                issued_ms: 100,
                expires_ms: 200,
                nonce: "forged".into(),
            },
            signature: b"not a signature".to_vec(),
        };
        assert!(access.install(&forged, 150).is_err(), "a self-asserted grant never installs");
        assert_eq!(access.admits("mallory", &Kind::CursorMoved { position: None, name: None }, 150), Admission::UnknownHolder);
    }

    #[test]
    fn a_stale_renewal_cannot_downgrade_or_shorten() {
        let mut access = table("doc", "host");
        access.install(&signed("doc", "host", "bob", Role::Editor, 200, 10_000, "new"), 250).expect("newer");
        // An older grant arrives late (out of order): viewer, earlier expiry.
        assert!(access.install(&signed("doc", "host", "bob", Role::Viewer, 100, 300, "old"), 250).is_err());
        let edit = Kind::TextEdit { para: "1".into(), update: vec![1], props: None };
        assert!(access.admits("bob", &edit, 250).is_admitted(), "still the editor grant, not downgraded");
        assert!(access.admits("bob", &edit, 5_000).is_admitted(), "and not expired early");
    }

    #[test]
    fn equal_issued_grants_break_ties_on_nonce() {
        let mut access = table("doc", "host");
        access.install(&signed("doc", "host", "erin", Role::Viewer, 100, 10_000, "bbb"), 150).expect("first");
        assert!(access.install(&signed("doc", "host", "erin", Role::Editor, 100, 10_000, "aaa"), 150).is_err(), "smaller nonce is stale");
        assert!(access.install(&signed("doc", "host", "erin", Role::Editor, 100, 10_000, "ccc"), 150).is_ok(), "larger nonce replaces");
    }

    #[test]
    fn an_unsupported_version_is_refused() {
        let mut access = table("doc", "host");
        let mut s = signed("doc", "host", "erin", Role::Editor, 100, 10_000, "n");
        s.grant.v = 99;
        assert!(access.install(&s, 150).is_err(), "version is validated after verification");
    }

    #[test]
    fn unknown_expired_and_role_refused_are_denied() {
        let mut access = table("doc", "host");
        access.install(&signed("doc", "host", "bob", Role::Viewer, 100, 200, "n1"), 150).expect("install");
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
        let mut access = table("doc", "host");
        assert!(access.install(&signed("other", "host", "erin", Role::Editor, 100, 200, "n"), 150).is_err());
        assert!(access.install(&signed("doc", "other", "erin", Role::Editor, 100, 200, "n"), 150).is_err());
        assert!(access.install(&signed("doc", "host", "erin", Role::Editor, 100, 200, "n"), 150).is_ok());
    }

    #[test]
    fn revocation_is_removal() {
        let mut access = table("doc", "host");
        access.install(&signed("doc", "host", "dave", Role::Editor, 100, 10_000, "n"), 150).expect("install");
        assert!(access.remove("dave"));
        assert_eq!(access.admits("dave", &Kind::CursorMoved { position: None, name: None }, 150), Admission::UnknownHolder);
    }
}
