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
            // Either role may read: a reader asks for the document's state
            // and receives one (from the host or from any live holder that
            // carries it), moves its cursor and (re)joins.
            (_, Kind::CursorMoved { .. }) | (_, Kind::SnapshotRequest {}) | (_, Kind::Snapshot { .. }) => true,
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
    /// Distinguishes otherwise identical grants and breaks install ties.
    /// Mint it with [`mint_nonce`], whose zero-padded form orders
    /// lexicographically by `issued_ms`, so a later grant is also the
    /// "greater" nonce at equal timestamps.
    pub nonce: String,
}

/// The contract's nonce mint: a zero-padded `issued_ms`, then a salt that
/// persists per grant. Lexicographic order equals time order.
pub fn mint_nonce(issued_ms: u64, salt: u32) -> String {
    format!("{issued_ms:016x}-{salt:08x}")
}

/// How much wall-clock disagreement a grant's liveness tolerates: a host
/// whose clock is minutes ahead mints grants this peer sees as slightly
/// future-dated, a joiner whose clock trails sees them expire minutes early.
/// Five minutes absorbs both, deliberately loose for a real-time document.
pub const GRANT_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;

impl Grant {
    /// Whether this grant is live at `now_ms`, within
    /// [`GRANT_CLOCK_SKEW_MS`]. A receiver with no wall clock at all (wasm
    /// reports 0) sees nothing live, so a clockless peer is refused rather
    /// than silently trusted.
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.expires_ms.saturating_add(GRANT_CLOCK_SKEW_MS) > now_ms && self.issued_ms <= now_ms.saturating_add(GRANT_CLOCK_SKEW_MS)
    }

    /// An open invitation token: signed by the host with no holder yet; the
    /// host turns it into a per-holder grant when a joiner presents it.
    /// Never installable as a holder grant.
    pub fn is_open(&self) -> bool {
        self.holder.is_empty()
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

/// The host withdrawing one holder from one document. Signed like a grant
/// but under its own domain context; revocation is monotonic (a re-install
/// of a grant no newer than the revocation is refused, a newer grant is the
/// host re-inviting the holder).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    pub v: u32,
    pub doc: String,
    pub host: String,
    pub holder: String,
    pub issued_ms: u64,
    pub nonce: String,
}

/// The signature context for revocations.
pub const REVOCATION_CONTEXT: &[u8] = b"craft-collab/revocation/v1";

impl Revocation {
    /// The bytes a revocation signature covers.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::with_capacity(REVOCATION_CONTEXT.len() + 256);
        bytes.extend_from_slice(REVOCATION_CONTEXT);
        bytes.extend_from_slice(&serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(bytes)
    }
}

/// A revocation with its host signature.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedRevocation {
    pub revocation: Revocation,
    pub signature: Vec<u8>,
}

/// Verifies a signed grant's signature and returns the grant it carries.
/// The adapter implements this with the host's carried key; a table without
/// one cannot install anything, and cannot revoke.
pub trait GrantVerifier: Send + Sync {
    /// Verifies `signed` at `now_ms`: the signature under the host key, the
    /// host id it derives, the version and the expiry.
    fn verify(&self, signed: &SignedGrant, now_ms: u64) -> Result<Grant, String>;

    /// Verifies a revocation the same way (under the revocation context).
    fn verify_revocation(&self, signed: &SignedRevocation, now_ms: u64) -> Result<Revocation, String>;
}

/// Verifies a realm membership a joiner presents when the host shares a
/// document with a realm: the proof must be the caller's own (audience =
/// the verified node id) and must not be expired. The adapter implements
/// this over the realm's UCAN verification; the engine never sees a token.
pub trait MembershipVerifier: Send + Sync {
    /// Verifies that `ucan` is a live membership of the shared realm for
    /// `node_id`, and returns when the membership ends (ms since the epoch):
    /// a document grant issued on it must never outlive it, so a revoked or
    /// lapsed membership takes the document access down with it.
    fn verify_member(&self, ucan: &str, node_id: &str, now_ms: u64) -> Result<u64, String>;
    /// The role realm members are admitted with (the host's mapping).
    fn role(&self) -> Role;
    /// The shared realm, by name: what a realm invite names as its member
    /// realm. It need not be the host's own realm or the transport's.
    fn realm(&self) -> &str;
}

/// Mints grants, revocations and open tokens as the host. The adapter
/// implements this over the identity's key; a session without one is never
/// a host that can admit (it can still be a joiner).
pub trait GrantIssuer: Send + Sync {
    /// The host id the issuer signs as (hex): what grants name as `host`.
    fn node_id(&self) -> String;
    /// The host's carried public key: what its grants verify under.
    fn carried_key(&self) -> Vec<u8>;
    /// A concrete grant for one holder.
    fn issue(&self, doc: &str, holder: &str, role: Role, ttl_ms: u64, now_ms: u64) -> Result<SignedGrant, String>;
    /// A host-signed revocation of one holder.
    fn revoke(&self, doc: &str, holder: &str, now_ms: u64) -> Result<SignedRevocation, String>;
    /// An open invitation token: signed, no holder, so a joiner can present
    /// it and the host turns it into the concrete grant.
    fn open_token(&self, doc: &str, role: Role, ttl_ms: u64, now_ms: u64) -> Result<SignedGrant, String>;
    /// Signs raw envelope bytes as the host (the invite envelope and
    /// whatever else the seam signs later).
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, String>;
}

/// Who may act on this document, as every replica checks it: the host, plus
/// each holder with a live grant.
#[derive(Clone)]
pub struct Access {
    doc: String,
    host: String,
    verifier: Option<Arc<dyn GrantVerifier>>,
    holders: BTreeMap<String, Grant>,
    /// The signed grants as installed, so a restarted peer can re-learn its
    /// holders without new signatures from the host.
    signed: BTreeMap<String, SignedGrant>,
    /// Revocations by holder: the highest `issued_ms` revoked; a grant no
    /// newer than this cannot install, a newer one is the host re-inviting.
    revoked: BTreeMap<String, u64>,
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
        Access {
            doc: doc.to_string(),
            host: host.to_string(),
            verifier: Some(verifier),
            holders: BTreeMap::new(),
            signed: BTreeMap::new(),
            revoked: BTreeMap::new(),
        }
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
        if grant.is_open() {
            return Err("an open token is not a holder grant".into());
        }
        if self.revoked.get(&grant.holder).is_some_and(|at| grant.issued_ms <= *at) {
            return Err("the holder was revoked after this grant was issued".into());
        }
        self.install_newer(grant, signed.clone())
    }

    /// The monotonic step: replace only on a strictly newer grant.
    fn install_newer(&mut self, grant: Grant, signed: SignedGrant) -> Result<(), String> {
        match self.holders.get(&grant.holder) {
            None => {
                self.holders.insert(grant.holder.clone(), grant);
                self.signed.insert(signed.grant.holder.clone(), signed);
                Ok(())
            }
            Some(current) => {
                let newer = grant.issued_ms > current.issued_ms || (grant.issued_ms == current.issued_ms && grant.nonce > current.nonce);
                if newer {
                    self.holders.insert(grant.holder.clone(), grant);
                    self.signed.insert(signed.grant.holder.clone(), signed);
                    Ok(())
                } else {
                    Err("a stale grant does not replace a newer one".into())
                }
            }
        }
    }

    /// Removes a holder (a local revocation).
    pub fn remove(&mut self, holder: &str) -> bool {
        self.signed.remove(holder);
        self.holders.remove(holder).is_some()
    }

    /// The signed grants as installed, in holder order: what a restarted
    /// peer persists and re-installs.
    pub fn signed_grants(&self) -> Vec<SignedGrant> {
        self.signed.values().cloned().collect()
    }

    /// Applies a host-signed revocation: verified like a grant, then the
    /// holder is removed unless their grant is newer than the revocation
    /// (the host re-invited them after revoking).
    pub fn revoke(&mut self, signed: &SignedRevocation, now_ms: u64) -> Result<(), String> {
        let verifier = self.verifier.clone().ok_or_else(|| "this access table has no grant verifier".to_string())?;
        let revocation = verifier.verify_revocation(signed, now_ms)?;
        if revocation.v != GRANT_VERSION {
            return Err(format!("unsupported revocation version {}", revocation.v));
        }
        if revocation.doc != self.doc {
            return Err("the revocation names another document".into());
        }
        if revocation.host != self.host {
            return Err("the revocation names another host".into());
        }
        let entry = self.revoked.entry(revocation.holder.clone()).or_insert(0);
        *entry = (*entry).max(revocation.issued_ms);
        if self.holders.get(&revocation.holder).is_some_and(|grant| grant.issued_ms <= revocation.issued_ms) {
            self.holders.remove(&revocation.holder);
            self.signed.remove(&revocation.holder);
        }
        Ok(())
    }

    /// Checks an invitation token presented by `requester` in a join
    /// request: signed by this host and live, and either an open token or one
    /// pre-named for exactly this node (an invite-by-person). Returns the
    /// token's role and expiry.
    pub fn check_token_for(&self, signed: &SignedGrant, requester: &str, now_ms: u64) -> Result<Grant, String> {
        let grant = self.verified_token(signed, now_ms)?;
        if !grant.is_open() && grant.holder != requester {
            return Err("this invitation names another node".into());
        }
        Ok(grant)
    }

    /// Checks an open invitation token presented in a join request: signed
    /// by this host and live; returns the token's role and expiry.
    pub fn check_token(&self, signed: &SignedGrant, now_ms: u64) -> Result<Grant, String> {
        let grant = self.verified_token(signed, now_ms)?;
        if !grant.is_open() {
            return Err("not an open token".into());
        }
        Ok(grant)
    }

    /// The verified token, before the holder test: signed by this host, live,
    /// and for this document.
    fn verified_token(&self, signed: &SignedGrant, now_ms: u64) -> Result<Grant, String> {
        let verifier = self.verifier.clone().ok_or_else(|| "this access table has no grant verifier".to_string())?;
        let grant = verifier.verify(signed, now_ms)?;
        if grant.v != GRANT_VERSION {
            return Err(format!("unsupported grant version {}", grant.v));
        }
        if grant.doc != self.doc {
            return Err("the token names another document".into());
        }
        if grant.host != self.host {
            return Err("the token names another host".into());
        }
        Ok(grant)
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

    /// The holder ids, sorted (the UI's People list).
    pub fn holder_ids(&self) -> Vec<String> {
        self.holders.keys().cloned().collect()
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

        fn verify_revocation(&self, signed: &SignedRevocation, now_ms: u64) -> Result<Revocation, String> {
            if signed.signature != b"rsig" {
                return Err("bad signature".into());
            }
            let _ = now_ms;
            Ok(signed.revocation.clone())
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
        // Expiry is enforced once the clock skew can no longer explain it.
        let past_skew = 200 + GRANT_CLOCK_SKEW_MS + 1;
        assert_eq!(access.admits("bob", &cursor, past_skew), Admission::Expired);
        assert_eq!(access.admits_reader("bob", past_skew), Admission::Expired, "expiry also stops reads");
    }

    #[test]
    fn a_grant_for_another_doc_or_host_is_refused() {
        let mut access = table("doc", "host");
        assert!(access.install(&signed("other", "host", "erin", Role::Editor, 100, 200, "n"), 150).is_err());
        assert!(access.install(&signed("doc", "other", "erin", Role::Editor, 100, 200, "n"), 150).is_err());
        assert!(access.install(&signed("doc", "host", "erin", Role::Editor, 100, 200, "n"), 150).is_ok());
    }

    #[test]
    fn liveness_tolerates_minutes_of_clock_disagreement() {
        let table = || Access::new("doc", "host", std::sync::Arc::new(FakeVerifier));
        let grant = signed("doc", "host", "h", Role::Editor, 1_000_000, 2_000_000, "n");
        // A joiner whose clock trails by four minutes: the grant looks
        // future-dated but is accepted within the skew.
        let mut early = table();
        early.install(&grant, 1_000_000 - 4 * 60_000).expect("four minutes behind is tolerated");
        // Past the skew, the same grant is refused.
        let mut late = table();
        assert!(late.install(&grant, 1_000_000 - 6 * 60_000).is_err());
        // Clockless (wasm, 0): nothing is live, nothing installs.
        let mut clockless = table();
        assert!(clockless.install(&grant, 0).is_err(), "a peer with no clock trusts no grant");
    }

    #[test]
    fn a_token_named_for_one_node_is_refused_for_another() {
        let mut access = table("doc", "host");
        // An invite-by-person: a pre-named holder, not an open token.
        access.install(&signed("doc", "host", "bbbbbbbb", Role::Editor, 100, 10_000, "named"), 150).expect("a named token installs as a grant");
        let named = signed("doc", "host", "bbbbbbbb", Role::Editor, 100, 10_000, "named");
        assert!(access.check_token_for(&named, "bbbbbbbb", 150).is_ok(), "its own person may use it");
        assert!(access.check_token_for(&named, "cccccccc", 150).is_err(), "another node is refused");
        assert!(access.check_token(&named, 150).is_err(), "and it is not an open token");
        // An open token stays open for anyone.
        let open = signed("doc", "host", "", Role::Viewer, 100, 10_000, "open");
        assert!(access.check_token_for(&open, "dddddddd", 150).is_ok());
    }

    #[test]
    fn revocation_is_removal() {
        let mut access = table("doc", "host");
        access.install(&signed("doc", "host", "dave", Role::Editor, 100, 10_000, "n"), 150).expect("install");
        assert!(access.remove("dave"));
        assert_eq!(access.admits("dave", &Kind::CursorMoved { position: None, name: None }, 150), Admission::UnknownHolder);
    }

    fn revocation(doc: &str, host: &str, holder: &str, issued: u64) -> SignedRevocation {
        SignedRevocation {
            revocation: Revocation {
                v: GRANT_VERSION,
                doc: doc.into(),
                host: host.into(),
                holder: holder.into(),
                issued_ms: issued,
                nonce: mint_nonce(issued, 1),
            },
            signature: b"rsig".to_vec(),
        }
    }

    /// An invite for one person admits exactly that node: the pre-named
    /// token is checked against the verified requester.
    #[test]
    fn a_prenamed_token_admits_only_its_holder() {
        let access = table("doc", "host");
        let mut token = signed("doc", "host", "", Role::Editor, 100, 10_000, "n");
        token.grant.holder = "bob".into();
        assert!(access.check_token_for(&token, "bob", 150).is_ok(), "the named node is admitted");
        assert!(access.check_token_for(&token, "carol", 150).is_err(), "another node is refused");
        assert!(access.check_token(&token, 150).is_err(), "and it is not an open token");
        let mut open = token.clone();
        open.grant.holder = String::new();
        assert!(access.check_token_for(&open, "carol", 150).is_ok(), "an open token still admits anyone");
    }

    #[test]
    fn an_open_token_never_installs_but_checks() {
        let mut access = table("doc", "host");
        let mut token = signed("doc", "host", "", Role::Editor, 100, 200, "open");
        token.grant.holder = String::new();
        assert!(access.install(&token, 150).is_err(), "an open token is not a holder grant");
        let checked = access.check_token(&token, 150).expect("the host can check its own token");
        assert!(checked.is_open());
        assert_eq!(checked.role, Role::Editor);
        assert!(access.check_token(&token, 200 + GRANT_CLOCK_SKEW_MS + 1).is_err(), "an expired token is refused once past the clock skew");
    }

    #[test]
    fn revocation_removes_and_blocks_older_installs() {
        let mut access = table("doc", "host");
        let grant = signed("doc", "host", "fred", Role::Editor, 100, 10_000, "n");
        access.install(&grant, 150).expect("install");
        access.revoke(&revocation("doc", "host", "fred", 150), 150).expect("revoke");
        assert_eq!(access.admits("fred", &Kind::CursorMoved { position: None, name: None }, 150), Admission::UnknownHolder, "revoked");
        assert!(access.install(&grant, 150).is_err(), "the revoked grant cannot come back");
        // The host re-invites with a newer grant: that is allowed.
        let newer = signed("doc", "host", "fred", Role::Viewer, 200, 10_000, "n2");
        access.install(&newer, 250).expect("re-invite installs");
        assert!(access.admits("fred", &Kind::CursorMoved { position: None, name: None }, 250).is_admitted());
    }

    #[test]
    fn a_stale_revocation_keeps_a_newer_grant() {
        let mut access = table("doc", "host");
        access.install(&signed("doc", "host", "gina", Role::Editor, 200, 10_000, "n"), 250).expect("newer grant");
        access.revoke(&revocation("doc", "host", "gina", 150), 250).expect("late revocation");
        assert!(
            access.admits("gina", &Kind::CursorMoved { position: None, name: None }, 250).is_admitted(),
            "the grant is newer than the revocation"
        );
    }
}
