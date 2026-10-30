//! The session protocol, driven by a stand-in app whose document is one
//! string: what the app does with each [`Inbound`] event is its own
//! business; these tests pin the door, grants, snapshots and stores.

use std::sync::{Arc, Mutex};

use super::*;
use crate::grant::{GRANT_VERSION, Grant, GrantVerifier, Revocation, SignedRevocation, mint_nonce};
use crate::mem::MemoryTransport;
use crate::message::Message;
use crate::transport::Transport;

/// The app's side: a document as a string, snapshots as its bytes, and a
/// log of the commands it replayed.
struct App {
    doc: String,
    replayed: Vec<(String, String)>,
    collab: CollabSession,
}

impl App {
    fn new(collab: CollabSession, doc: &str) -> App {
        App { doc: doc.to_string(), replayed: Vec::new(), collab }
    }

    /// What an app does once per frame.
    fn tick(&mut self) {
        for event in self.collab.tick() {
            match event {
                Inbound::Command { author, id, .. } => self.replayed.push((author, id)),
                Inbound::SnapshotWanted => self.collab.answer_snapshot(self.doc.clone().into_bytes()),
                Inbound::Snapshot { data, crdt } => {
                    if self.collab.awaiting_snapshot() {
                        self.doc = String::from_utf8(data).unwrap_or_default();
                        self.collab.snapshot_loaded(&crdt);
                    }
                }
                Inbound::Text { .. } => {}
            }
        }
        self.collab.share_cursor(Some("0".into()));
    }

    fn stats(&self) -> Value {
        self.collab.stats()
    }
}

/// Accepts every signature: these tests exercise the protocol; the
/// adapter's tests exercise the crypto.
struct TestVerifier;

impl GrantVerifier for TestVerifier {
    fn verify(&self, signed: &SignedGrant, _now_ms: u64) -> Result<Grant, String> {
        Ok(signed.grant.clone())
    }

    fn verify_revocation(&self, signed: &SignedRevocation, _now_ms: u64) -> Result<Revocation, String> {
        Ok(signed.revocation.clone())
    }
}

/// One accepted membership string, one role, and when it ends.
struct TestMemberVerifier {
    accepts: String,
    role: Role,
    ends_ms: Option<u64>,
}

impl MembershipVerifier for TestMemberVerifier {
    fn verify_member(&self, ucan: &str, node_id: &str, _now_ms: u64) -> Result<u64, String> {
        if node_id.is_empty() {
            return Err("no node".into());
        }
        if ucan == self.accepts { Ok(self.ends_ms.unwrap_or(u64::MAX)) } else { Err("not a member".into()) }
    }

    fn role(&self) -> Role {
        self.role
    }

    fn realm(&self) -> &str {
        "test.realm-e"
    }
}

/// Mints real grant structures, unsigned.
struct TestIssuer {
    host: String,
}

impl GrantIssuer for TestIssuer {
    fn node_id(&self) -> String {
        self.host.clone()
    }

    fn carried_key(&self) -> Vec<u8> {
        vec![7; 32]
    }

    fn issue(&self, doc: &str, holder: &str, role: Role, ttl_ms: u64, now_ms: u64) -> Result<SignedGrant, String> {
        Ok(SignedGrant {
            grant: Grant {
                v: GRANT_VERSION,
                doc: doc.to_string(),
                host: self.host.clone(),
                holder: holder.to_string(),
                role,
                issued_ms: now_ms,
                expires_ms: now_ms.saturating_add(ttl_ms),
                nonce: mint_nonce(now_ms, 1),
            },
            signature: vec![],
        })
    }

    /// Names the holder it was minted for, so a test can see that a
    /// per-person invite binds the credential and an open one does not.
    fn group_grant(&self, _doc: &str, group: &str, holder: Option<&str>, _ttl_ms: u64, _now_ms: u64) -> Result<String, String> {
        Ok(format!("grant-for:{group}:{}", holder.unwrap_or("whoever-holds-the-line")))
    }

    fn revoke(&self, doc: &str, holder: &str, now_ms: u64) -> Result<SignedRevocation, String> {
        Ok(SignedRevocation {
            revocation: Revocation {
                v: GRANT_VERSION,
                doc: doc.to_string(),
                host: self.host.clone(),
                holder: holder.to_string(),
                issued_ms: now_ms,
                nonce: mint_nonce(now_ms, 1),
            },
            signature: vec![],
        })
    }

    fn open_token(&self, doc: &str, role: Role, ttl_ms: u64, now_ms: u64) -> Result<SignedGrant, String> {
        self.issue(doc, "", role, ttl_ms, now_ms)
    }

    fn sign(&self, _bytes: &[u8]) -> Result<Vec<u8>, String> {
        Ok(b"isig".to_vec())
    }
}

/// A store in memory, shared so a "restarted" session reads what the first
/// one wrote.
#[derive(Clone, Default)]
struct MemStore(Arc<Mutex<Option<String>>>);

impl TextStore for MemStore {
    fn read(&self) -> Option<String> {
        self.0.lock().ok()?.clone()
    }

    fn write(&self, text: &str) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(text.to_string());
        }
    }
}

const HOST: &str = "aaaaaaaa";

fn table() -> Access {
    Access::new("demo", HOST, Arc::new(TestVerifier))
}

fn token(host: &str, role: Role) -> SignedGrant {
    TestIssuer { host: host.to_string() }.open_token("demo", role, 60_000, now_ms()).unwrap()
}

/// A host sharing `doc`, with access control and its issuer.
fn host(transport: MemoryTransport, doc: &str, auto: bool) -> App {
    host_on(Box::new(transport), doc, auto)
}

/// The same, on any transport: a test that needs one to lose a message wraps
/// the in-memory one.
fn host_on(transport: Box<dyn Transport>, doc: &str, auto: bool) -> App {
    let mut collab = CollabSession::host("demo", "Host", transport, &[]);
    collab.set_access(table());
    collab.set_issuer(Box::new(TestIssuer { host: HOST.into() }));
    collab.set_auto_approve(auto);
    App::new(collab, doc)
}

/// A joiner presenting `token` and/or `membership`.
fn joiner(transport: MemoryTransport, name: &str, token: Option<SignedGrant>, membership: Option<&str>) -> App {
    let mut collab = CollabSession::join_requesting("demo", name, Box::new(transport), token, membership.map(str::to_string));
    collab.set_access(table());
    App::new(collab, "")
}

/// Ticks joiner, host, joiner, host, joiner: request, grant, snapshot
/// request, snapshot, landing.
fn admit(host: &mut App, joiner: &mut App) {
    joiner.tick();
    host.tick();
    joiner.tick();
    host.tick();
    joiner.tick();
}

fn pair() -> (MemoryTransport, MemoryTransport) {
    MemoryTransport::pair(HOST, "bbbbbbbb")
}

#[test]
fn a_join_with_an_invite_is_granted_and_receives_the_document() {
    let (ta, tb) = pair();
    let mut h = host(ta, "hello ", true);
    let mut bob = joiner(tb, "Bob", Some(token(HOST, Role::Editor)), None);
    admit(&mut h, &mut bob);
    assert_eq!(bob.stats()["joined"], true, "admitted end to end");
    assert_eq!(bob.stats()["awaitingGrant"], false);
    assert_eq!(bob.doc, "hello ", "the document arrived");
    assert_eq!(h.collab.holders(), vec!["bbbbbbbb".to_string()]);

    bob.collab.send_command("text.insert".into(), b"{}".to_vec(), None);
    h.tick();
    assert_eq!(h.replayed, vec![("bbbbbbbb".to_string(), "text.insert".to_string())], "a granted joiner's command reaches the app");
}

#[test]
fn a_token_for_another_host_is_refused_at_the_door() {
    let (ta, tb) = pair();
    let mut h = host(ta, "secret", true);
    let mut bob = joiner(tb, "Bob", Some(token("cccccccc", Role::Editor)), None);
    admit(&mut h, &mut bob);
    assert!(h.stats()["unauthorized"].as_u64().unwrap_or(0) >= 1, "the forged token is counted");
    assert_eq!(bob.stats()["awaitingGrant"], true, "the joiner still waits");
    assert_eq!(bob.doc, "", "and received nothing");
}

#[test]
fn the_host_approves_a_pending_joiner_by_hand() {
    let (ta, tb) = pair();
    let mut h = host(ta, "doc", false);
    let mut bob = joiner(tb, "Bob", Some(token(HOST, Role::Editor)), None);
    bob.tick();
    h.tick();
    assert_eq!(h.collab.pending(), vec![("bbbbbbbb".to_string(), "Bob".to_string())], "the request waits for a yes");
    assert_eq!(h.stats()["pending"][0]["name"], "Bob");

    h.collab.approve("bbbbbbbb").unwrap();
    assert!(h.collab.pending().is_empty());
    bob.tick();
    h.tick();
    bob.tick();
    assert_eq!(bob.doc, "doc", "the hand-approved joiner lands");
    assert!(h.collab.approve("bbbbbbbb").is_err(), "nothing left to approve");
}

#[test]
fn contacts_and_grants_survive_a_restart_through_the_stores() {
    let (contacts, grants) = (MemStore::default(), MemStore::default());
    {
        let (ta, tb) = pair();
        let mut h = host(ta, "doc", false);
        h.collab.set_contacts_store(Box::new(contacts.clone()));
        h.collab.set_grants_store(Box::new(grants.clone()));
        let mut bob = joiner(tb, "Bob", Some(token(HOST, Role::Editor)), None);
        bob.tick();
        h.tick();
        assert_eq!(h.collab.contacts().len(), 1, "a waiting joiner is remembered");
        h.collab.approve("bbbbbbbb").unwrap();
        assert_eq!(h.collab.contacts().len(), 1, "approving does not duplicate the person");
    }
    let mut restarted = host(MemoryTransport::pair(HOST, "x").0, "doc", false);
    restarted.collab.set_contacts_store(Box::new(contacts.clone()));
    restarted.collab.set_grants_store(Box::new(grants));
    assert_eq!(restarted.collab.contacts()[0].name, "Bob", "contacts persist");
    assert_eq!(restarted.collab.holders(), vec!["bbbbbbbb".to_string()], "the restarted host relearns its holders");

    assert!(restarted.collab.forget_contact("bbbbbbbb"));
    assert!(!contacts.read().unwrap_or_default().contains("Bob"), "forgetting writes through");
    assert!(!restarted.collab.forget_contact("bbbbbbbb"), "nobody left to forget");
}

#[test]
fn revoking_a_holder_stops_their_messages() {
    let (ta, tb) = pair();
    let mut h = host(ta, "doc", true);
    let mut bob = joiner(tb, "Bob", Some(token(HOST, Role::Editor)), None);
    admit(&mut h, &mut bob);
    h.collab.revoke("bbbbbbbb").unwrap();
    bob.tick();
    bob.collab.send_command("text.insert".into(), b"{}".to_vec(), None);
    h.tick();
    assert!(h.replayed.is_empty(), "a revoked holder no longer lands");
    assert!(h.stats()["unauthorized"].as_u64().unwrap_or(0) >= 1);
}

#[test]
fn a_realm_member_joins_and_a_viewer_cannot_write() {
    let (ta, tb) = pair();
    let mut h = host(ta, "shared", true);
    h.collab.set_member_verifier(Box::new(TestMemberVerifier { accepts: "member-good".into(), role: Role::Viewer, ends_ms: None }));
    let mut bea = joiner(tb, "Bea", None, Some("member-good"));
    admit(&mut h, &mut bea);
    assert_eq!(bea.doc, "shared", "a realm member lands with no token at all");
    assert_eq!(h.stats()["realmShare"], true);

    bea.collab.send_command("text.insert".into(), b"{}".to_vec(), None);
    h.tick();
    assert!(h.replayed.is_empty(), "a viewer's edit does not land");
    assert_eq!(h.stats()["unauthorized"], 1);
}

#[test]
fn a_bogus_or_ended_membership_admits_nobody() {
    for (presented, ends_ms) in [("member-bogus", None), ("member-ended", Some(now_ms().saturating_sub(1)))] {
        let (ta, tb) = pair();
        let mut h = host(ta, "doc", true);
        h.collab.set_member_verifier(Box::new(TestMemberVerifier { accepts: "member-ended".into(), role: Role::Editor, ends_ms }));
        let mut bea = joiner(tb, "Bea", None, Some(presented));
        admit(&mut h, &mut bea);
        assert!(h.collab.pending().is_empty(), "{presented}: nothing waits");
        assert!(h.collab.holders().is_empty(), "{presented}: no grant");
        assert!(h.stats()["unauthorized"].as_u64().unwrap_or(0) >= 1, "{presented}: counted");
        assert_eq!(bea.stats()["awaitingGrant"], true, "{presented}: still waiting");
    }
}

#[test]
fn a_member_grant_never_outlives_the_membership() {
    let grants = MemStore::default();
    let membership_end = now_ms() + 60_000;
    let (ta, tb) = pair();
    let mut h = host(ta, "doc", false);
    h.collab.set_grants_store(Box::new(grants.clone()));
    h.collab.set_member_verifier(Box::new(TestMemberVerifier { accepts: "m".into(), role: Role::Editor, ends_ms: Some(membership_end) }));
    let mut bea = joiner(tb, "Bea", None, Some("m"));
    bea.tick();
    h.tick();
    h.collab.approve("bbbbbbbb").unwrap();
    let saved: Value = serde_json::from_str(&grants.read().unwrap_or_default()).unwrap();
    let stored: Vec<SignedGrant> = serde_json::from_value(saved["grants"].clone()).unwrap();
    let grant = &stored[0].grant;
    assert_eq!(grant.role, Role::Editor);
    assert!(grant.expires_ms <= membership_end, "capped at the membership's end");
    assert!(grant.expires_ms > now_ms(), "but live now");
}

#[test]
fn an_invite_for_one_person_admits_only_that_node() {
    let (bob_id, carol_id) = ("bb".repeat(32), "cc".repeat(32));
    let mut bus = MemoryTransport::bus(&[HOST, &bob_id, &carol_id]);
    let (ta, tb, tc) = (bus.remove(0), bus.remove(0), bus.remove(0));
    let mut h = host(ta, "for one", true);
    let share = ShareContext {
        realm: "cc".repeat(32),
        realm_key: String::new(),
        seed: "station.example:4433:dd".into(),
        profile: "pq_pure".into(),
        group: String::new(),
    };
    let line = h.collab.mint_invite_for(Some(&share), None, &bob_id, "Bob", Role::Editor, 60_000).unwrap();
    let invite = Invite::decode(&line).unwrap();
    assert_eq!(invite.invitee.as_deref(), Some(bob_id.as_str()));
    assert_eq!(invite.signature, b"isig".to_vec(), "the envelope is signed by the host");
    let token = invite.token.unwrap();
    assert_eq!(token.grant.holder, bob_id);

    let mut carol = joiner(tc, "Carol", Some(token.clone()), None);
    admit(&mut h, &mut carol);
    assert_eq!(carol.doc, "", "another node's invite does not admit");

    let mut bob = joiner(tb, "Bob", Some(token), None);
    admit(&mut h, &mut bob);
    assert_eq!(bob.doc, "for one", "the named node is admitted");
    assert!(h.collab.mint_invite_for(Some(&share), None, "not-a-node", "X", Role::Editor, 1).is_err());
}

#[test]
fn a_realm_invite_names_the_shared_realm_and_the_hosts_own() {
    let mut h = host(MemoryTransport::pair(HOST, "x").0, "doc", true);
    assert!(!h.collab.can_invite(), "no mesh coordinates yet");
    assert!(h.collab.mint_realm_invite(None, None, 60_000).is_err(), "not shared with a realm");
    h.collab.set_share_context(ShareContext {
        realm: "r".into(),
        realm_key: "k".into(),
        seed: "s".into(),
        profile: "p".into(),
        group: String::new(),
    });
    h.collab.set_member_verifier(Box::new(TestMemberVerifier { accepts: "m".into(), role: Role::Viewer, ends_ms: None }));
    assert!(h.collab.can_invite());
    let invite = Invite::decode(&h.collab.mint_realm_invite(None, Some("io.macula"), 60_000).unwrap()).unwrap();
    assert_eq!(invite.member_realm.as_deref(), Some("test.realm-e"), "the realm whose members it admits");
    assert_eq!(invite.host_realm.as_deref(), Some("io.macula"), "the host's own realm");
    assert_eq!(invite.member_role, Some(Role::Viewer));
    assert!(invite.token.is_none(), "a realm invite carries no token");
    assert_eq!(invite.seed, "s", "the remembered coordinates");
}

#[test]
fn a_sealed_invite_binds_the_group_credential_to_the_person_named() {
    let (bob_id, carol_id) = ("bb".repeat(32), "cc".repeat(32));
    let mut bus = MemoryTransport::bus(&[HOST, &bob_id, &carol_id]);
    let (ta, _tb, _tc) = (bus.remove(0), bus.remove(0), bus.remove(0));
    let h = host(ta, "sealed", true);
    let share = ShareContext {
        realm: "cc".repeat(32),
        realm_key: String::new(),
        seed: "station.example:4433:dd".into(),
        profile: "pq_pure".into(),
        group: "io.macula/~aa/craft/9f9f9f9f".into(),
    };
    // The key pull happens before the knock, so the credential is the
    // distributor's whole test: it names Bob, and nobody else's line carries it.
    let named = Invite::decode(&h.collab.mint_invite_for(Some(&share), None, &bob_id, "Bob", Role::Editor, 60_000).unwrap()).unwrap();
    assert_eq!(named.group, "io.macula/~aa/craft/9f9f9f9f");
    assert!(named.group_grant.contains(&bob_id), "the credential is bound to the invitee: {}", named.group_grant);

    // An open invite cannot be sealed — there is no node to bind the
    // credential to, so it is refused rather than minted as a bearer.
    let err = h.collab.mint_invite(Some(&share), None, Role::Editor, 60_000).unwrap_err();
    assert!(err.contains("by name"), "the limit is named, not silent: {err}");

    // The same document, unsealed, still mints an open link.
    let plain = ShareContext { group: String::new(), ..share };
    let open = Invite::decode(&h.collab.mint_invite(Some(&plain), None, Role::Editor, 60_000).unwrap()).unwrap();
    assert!(open.group.is_empty() && open.group_grant.is_empty());
}

#[test]
fn a_realm_invite_is_refused_on_a_sealed_share() {
    let mut h = host(MemoryTransport::pair(HOST, "x").0, "doc", true);
    h.collab.set_member_verifier(Box::new(TestMemberVerifier { accepts: "m".into(), role: Role::Viewer, ends_ms: None }));
    let sealed = ShareContext {
        realm: "r".into(),
        realm_key: "k".into(),
        seed: "s".into(),
        profile: "p".into(),
        group: "io.macula/~aa/craft/9f9f9f9f".into(),
    };
    let err = h.collab.mint_realm_invite(Some(&sealed), None, 60_000).unwrap_err();
    assert!(err.contains("cannot be sealed"), "the limit is named, not silent: {err}");

    // The same document, unsealed, still admits a realm.
    let plain = ShareContext { group: String::new(), ..sealed };
    let invite = Invite::decode(&h.collab.mint_realm_invite(Some(&plain), None, 60_000).unwrap()).unwrap();
    assert_eq!(invite.member_role, Some(Role::Viewer));
    assert!(invite.group.is_empty() && invite.group_grant.is_empty());
}

#[test]
fn the_session_says_whether_its_share_is_sealed() {
    // A window asks the session, so what it shows and what minting does are
    // the same fact (Neptunus r=1 on macula-craft-collab#26).
    let mut h = host(MemoryTransport::pair(HOST, "x").0, "doc", true);
    assert!(!h.collab.sealed(), "no mesh coordinates yet: nothing is sealed");

    let plain = ShareContext { realm: "r".into(), realm_key: "k".into(), seed: "s".into(), profile: "p".into(), group: String::new() };
    h.collab.set_share_context(plain.clone());
    assert!(!h.collab.sealed(), "a transport that does not seal names no group");

    h.collab.set_share_context(ShareContext { group: "io.macula/~aa/craft/9f9f9f9f".into(), ..plain });
    assert!(h.collab.sealed(), "a group prefix is a sealed share");

    // And it is the same answer minting gives: sealed offers no open line.
    assert!(h.collab.mint_invite(None, None, Role::Editor, 60_000).is_err(), "sealed: by name only");
}

#[test]
fn a_joiner_that_has_not_caught_up_never_answers_a_snapshot_request() {
    let mut bus = MemoryTransport::bus(&[HOST, "bbbbbbbb", "cccccccc"]);
    let (ta, tb, tc) = (bus.remove(0), bus.remove(0), bus.remove(0));
    let mut h = App::new(CollabSession::host("demo", "Host", Box::new(ta), &[]), "real");
    let mut early = App::new(CollabSession::join("demo", "Early", Box::new(tb)), "");
    let mut late = App::new(CollabSession::join("demo", "Late", Box::new(tc)), "");
    late.tick(); // asks
    early.tick(); // sees the request before it has anything: stays quiet
    h.tick(); // the host answers
    late.tick();
    assert_eq!(late.doc, "real", "only the document holder's snapshot arrives");
}

#[test]
fn undo_local_shares_the_change_and_peers_and_cursors_show() {
    let (ta, tb) = MemoryTransport::pair(HOST, "bbbbbbbb");
    let mut a = App::new(CollabSession::host("demo", "Alice", Box::new(ta), &[]), "");
    let mut b = App::new(CollabSession::join("demo", "Bob", Box::new(tb)), "");
    assert!(a.collab.undo_local().is_none(), "nothing of Alice's to undo");
    b.tick();
    a.tick();
    assert_eq!(a.collab.peers().map(|p| p.name.clone()).collect::<Vec<_>>(), vec!["Bob".to_string()]);
    assert_eq!(a.stats()["peers"][0]["hasCursor"], true);
    assert_eq!(short("0123456789"), "01234567");
}

// macula-realm#46 step 3: a realm member's grant is extended while the
// membership is renewed, and never past what the host decided.

/// Several accepted memberships, each with its own end.
struct RenewingMemberVerifier {
    ends: Vec<(String, u64)>,
    role: Role,
}

impl MembershipVerifier for RenewingMemberVerifier {
    fn verify_member(&self, ucan: &str, _node_id: &str, _now_ms: u64) -> Result<u64, String> {
        self.ends.iter().find(|(u, _)| u == ucan).map(|(_, end)| *end).ok_or_else(|| "not a member".to_string())
    }

    fn role(&self) -> Role {
        self.role
    }

    fn realm(&self) -> &str {
        "test.realm-e"
    }
}

/// A memory transport whose membership the test renews, the way
/// macula-craft-collab's renewal loop does.
struct RenewedTransport {
    inner: MemoryTransport,
    membership: Arc<Mutex<Option<String>>>,
}

impl Transport for RenewedTransport {
    fn author(&self) -> String {
        self.inner.author()
    }

    fn send(&mut self, msg: Message) -> Result<(), String> {
        self.inner.send(msg)
    }

    fn poll(&mut self) -> Vec<Message> {
        self.inner.poll()
    }

    fn membership(&self) -> Option<String> {
        self.membership.lock().ok()?.clone()
    }
}

fn renewing_joiner(transport: MemoryTransport, first: &str) -> (App, Arc<Mutex<Option<String>>>) {
    let slot = Arc::new(Mutex::new(None));
    let transport = RenewedTransport { inner: transport, membership: slot.clone() };
    let mut collab = CollabSession::join_requesting("demo", "Bea", Box::new(transport), None, Some(first.to_string()));
    collab.set_access(table());
    (App::new(collab, ""), slot)
}

fn bea_grant(h: &App) -> Grant {
    let signed = h.collab.access.as_ref().and_then(|a| a.signed_grants().into_iter().find(|g| g.grant.holder == "bbbbbbbb"));
    signed.map(|s| s.grant).unwrap_or_else(|| panic!("Bea holds no grant"))
}

#[test]
fn a_renewed_membership_extends_the_grant_without_asking_the_host_again() {
    let (first_end, renewed_end) = (now_ms() + 60_000, now_ms() + 3_600_000);
    let (ta, tb) = pair();
    let mut h = host(ta, "doc", false);
    h.collab.set_member_verifier(Box::new(RenewingMemberVerifier {
        ends: vec![("m1".into(), first_end), ("m2".into(), renewed_end)],
        role: Role::Editor,
    }));
    let (mut bea, slot) = renewing_joiner(tb, "m1");
    bea.tick();
    h.tick();
    h.collab.approve("bbbbbbbb").unwrap();
    admit(&mut h, &mut bea);
    assert!(bea_grant(&h).expires_ms <= first_end);

    bea.doc = "edited".into();
    // A grant issued in the same millisecond is not newer: let the clock move.
    std::thread::sleep(std::time::Duration::from_millis(3));
    *slot.lock().unwrap() = Some("m2".into());
    bea.tick();
    h.tick();
    bea.tick();
    assert!(h.collab.pending().is_empty(), "the host is not asked again");
    let grant = bea_grant(&h);
    assert!(grant.expires_ms > first_end && grant.expires_ms <= renewed_end, "extended to the renewed membership's end");
    assert_eq!(grant.role, Role::Editor);
    assert!(!bea.collab.awaiting_snapshot(), "an extension never reloads the document");
    assert_eq!(bea.doc, "edited");
}

#[test]
fn an_extension_never_shortens_or_downgrades_a_grant() {
    let mut bus = MemoryTransport::bus(&[HOST, "bbbbbbbb", "bbbbbbbb"]);
    let (ta, tb, tb_again) = (bus.remove(0), bus.remove(0), bus.remove(0));
    let mut h = host(ta, "doc", true);
    h.collab.set_member_verifier(Box::new(RenewingMemberVerifier { ends: vec![("m".into(), now_ms() + 600_000)], role: Role::Viewer }));
    // Bob holds a 24 h editor grant from an invite...
    let mut bob = joiner(tb, "Bob", Some(token(HOST, Role::Editor)), None);
    admit(&mut h, &mut bob);
    let before = bea_grant(&h);
    // ...and his node then presents a shorter viewer membership. (The new
    // endpoint drops what the bus carried before it joined.)
    std::thread::sleep(std::time::Duration::from_millis(3));
    let mut tb_again = tb_again;
    tb_again.poll();
    let mut knock = joiner(tb_again, "Bob", None, Some("m"));
    knock.tick();
    h.tick();
    let after = bea_grant(&h);
    assert_eq!(after.expires_ms, before.expires_ms, "never shortened");
    assert_eq!(after.role, Role::Editor, "never downgraded");
}

#[test]
fn an_extension_keeps_the_role_the_host_gave() {
    let mut bus = MemoryTransport::bus(&[HOST, "bbbbbbbb", "bbbbbbbb"]);
    let (ta, tb, tb_again) = (bus.remove(0), bus.remove(0), bus.remove(0));
    let mut h = host(ta, "doc", true);
    // The realm admits its members as viewers, for longer than the grant Bob holds.
    h.collab.set_member_verifier(Box::new(RenewingMemberVerifier { ends: vec![("m".into(), now_ms() + 48 * 3_600_000)], role: Role::Viewer }));
    let mut bob = joiner(tb, "Bob", Some(token(HOST, Role::Editor)), None);
    admit(&mut h, &mut bob);
    let before = bea_grant(&h);
    std::thread::sleep(std::time::Duration::from_millis(3));
    let mut tb_again = tb_again;
    tb_again.poll();
    let mut knock = joiner(tb_again, "Bob", None, Some("m"));
    knock.tick();
    h.tick();
    let after = bea_grant(&h);
    assert!(after.expires_ms > before.expires_ms, "extended");
    assert_eq!(after.role, Role::Editor, "with the role the host gave, not the realm's");
}

#[test]
fn a_holder_the_host_revoked_is_never_readmitted_without_the_host() {
    let mut bus = MemoryTransport::bus(&[HOST, "bbbbbbbb", "bbbbbbbb"]);
    let (ta, tb, tb_again) = (bus.remove(0), bus.remove(0), bus.remove(0));
    let mut h = host(ta, "doc", true);
    h.collab.set_member_verifier(Box::new(RenewingMemberVerifier {
        ends: vec![("m1".into(), now_ms() + 60_000), ("m2".into(), now_ms() + 3_600_000)],
        role: Role::Editor,
    }));
    let (mut bea, slot) = renewing_joiner(tb, "m1");
    admit(&mut h, &mut bea);
    h.collab.revoke("bbbbbbbb").unwrap();
    *slot.lock().unwrap() = Some("m2".into());
    for _ in 0..3 {
        bea.tick();
        h.tick();
    }
    assert!(h.collab.holders().is_empty(), "the revoked joiner's renewal admits nothing");
    assert!(h.collab.pending().is_empty(), "and the revoked joiner does not knock");

    // A fresh join by membership from that node, under auto-approve, waits
    // for the host. (A session made in the same millisecond shares an epoch.)
    std::thread::sleep(std::time::Duration::from_millis(3));
    let mut tb_again = tb_again;
    tb_again.poll();
    let mut again = joiner(tb_again, "Bea", None, Some("m2"));
    again.tick();
    h.tick();
    assert!(h.collab.holders().is_empty(), "no grant without the host");
    assert_eq!(h.collab.pending(), vec![("bbbbbbbb".to_string(), "Bea".to_string())], "the host decides");
}

#[test]
fn a_per_person_invite_minted_after_the_revoke_is_the_hosts_yes() {
    let bob_id = "bb".repeat(32);
    let mut bus = MemoryTransport::bus(&[HOST, &bob_id, &bob_id, &bob_id, &bob_id]);
    let (ta, tb, mut tb_open, mut tb_old, mut tb_new) = (bus.remove(0), bus.remove(0), bus.remove(0), bus.remove(0), bus.remove(0));
    let mut h = host(ta, "doc", true);
    let mut bob = joiner(tb, "Bob", Some(token(HOST, Role::Editor)), None);
    admit(&mut h, &mut bob);
    let before_revoke = TestIssuer { host: HOST.into() }.issue("demo", &bob_id, Role::Editor, 60_000, now_ms()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));
    h.collab.revoke(&bob_id).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));

    // An open invite still waits for the host.
    tb_open.poll();
    let mut open = joiner(tb_open, "Bob", Some(token(HOST, Role::Editor)), None);
    open.tick();
    h.tick();
    assert!(h.collab.holders().is_empty(), "no grant without the host");
    assert_eq!(h.collab.pending().len(), 1, "the host decides");

    // So does Bob replaying a per-person invite from before the revoke.
    // (A session made in the same millisecond shares an epoch.)
    std::thread::sleep(std::time::Duration::from_millis(3));
    tb_old.poll();
    let mut old = joiner(tb_old, "Bob again", Some(before_revoke), None);
    old.tick();
    h.tick();
    assert!(h.collab.holders().is_empty(), "no grant without the host");
    assert_eq!(h.collab.pending(), vec![(bob_id.clone(), "Bob again".to_string())], "the host decides");

    // A per-person invite the host minted after the revoke is that yes.
    let share = ShareContext {
        realm: "cc".repeat(32),
        realm_key: String::new(),
        seed: "station.example:4433:dd".into(),
        profile: "pq_pure".into(),
        group: String::new(),
    };
    let line = h.collab.mint_invite_for(Some(&share), None, &bob_id, "Bob", Role::Viewer, 60_000).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));
    tb_new.poll();
    let mut invited = joiner(tb_new, "Bob", Invite::decode(&line).unwrap().token, None);
    admit(&mut h, &mut invited);
    assert_eq!(invited.doc, "doc", "admitted at once");
    assert_eq!(h.collab.holders().len(), 1);
    assert!(h.collab.pending().is_empty(), "and no longer pending");
}

#[test]
fn a_revoke_survives_the_host_restarting() {
    let grants = MemStore::default();
    let invite = token(HOST, Role::Editor);
    let mut bus = MemoryTransport::bus(&[HOST, "bbbbbbbb", HOST, "bbbbbbbb"]);
    let (ta, tb, ta_again, tb_again) = (bus.remove(0), bus.remove(0), bus.remove(0), bus.remove(0));
    {
        let mut h = host(ta, "doc", true);
        h.collab.set_grants_store(Box::new(grants.clone()));
        let mut bob = joiner(tb, "Bob", Some(invite.clone()), None);
        admit(&mut h, &mut bob);
        assert_eq!(h.collab.holders(), vec!["bbbbbbbb".to_string()]);
        std::thread::sleep(std::time::Duration::from_millis(3));
        h.collab.revoke("bbbbbbbb").unwrap();
    }

    // The host reopens the document from the same store, and Bob presents
    // the open invite he joined with, still live.
    std::thread::sleep(std::time::Duration::from_millis(3));
    let mut restarted = host(ta_again, "doc", true);
    restarted.collab.set_grants_store(Box::new(grants));
    assert!(restarted.collab.holders().is_empty(), "the revoked grant does not come back");
    let mut tb_again = tb_again;
    tb_again.poll();
    let mut again = joiner(tb_again, "Bob", Some(invite), None);
    again.tick();
    restarted.tick();
    assert!(restarted.collab.holders().is_empty(), "no grant without the host");
    assert_eq!(restarted.collab.pending(), vec![("bbbbbbbb".to_string(), "Bob".to_string())], "the host decides");
}

#[test]
fn a_revoke_ends_a_grant_issued_after_the_hosts_clock_stepped_back() {
    let (ta, _tb) = pair();
    let mut h = host(ta, "doc", true);
    // The grant was issued before the host's clock stepped back four minutes
    // (within the grants' clock tolerance, so it is live and installs).
    let ahead = now_ms() + 4 * 60 * 1_000;
    let grant = TestIssuer { host: HOST.into() }.issue("demo", "bbbbbbbb", Role::Editor, 3_600_000, ahead).unwrap();
    assert!(h.collab.access.as_mut().unwrap().install(&grant, now_ms()).is_ok());
    assert_eq!(h.collab.holders(), vec!["bbbbbbbb".to_string()]);

    h.collab.revoke("bbbbbbbb").unwrap();
    assert!(h.collab.holders().is_empty(), "the revoke ends the grant it was meant to end");
    let at = h.collab.access.as_ref().unwrap().revoked_at("bbbbbbbb").unwrap();
    assert!(at > ahead, "and is newer than it, so the grant cannot install again");

    // The host changes its mind before its clock passes the revocation: the
    // new grant is minted later than it, so it installs.
    h.collab.pending.insert("bbbbbbbb".into(), PendingJoin { name: "Bob".into(), role: Role::Editor, ends_ms: None });
    h.collab.approve("bbbbbbbb").unwrap();
    assert_eq!(h.collab.holders(), vec!["bbbbbbbb".to_string()], "the host's later yes is not swallowed");
}

/// A transport that loses one chosen message on the way, the way a packet is
/// lost: the sender is told nothing and nothing resends it.
struct Lossy {
    inner: MemoryTransport,
    /// The sequence number to lose, picked once the run knows it.
    drop_seq: Arc<Mutex<u64>>,
}

impl Lossy {
    /// Losing nothing until the shared slot names the sequence to go.
    fn on(inner: MemoryTransport, drop_seq: Arc<Mutex<u64>>) -> Lossy {
        Lossy { inner, drop_seq }
    }
}

impl Transport for Lossy {
    fn author(&self) -> String {
        self.inner.author()
    }

    fn send(&mut self, msg: Message) -> Result<(), String> {
        if self.drop_seq.lock().is_ok_and(|seq| *seq == msg.seq) {
            return Ok(());
        }
        self.inner.send(msg)
    }

    fn poll(&mut self) -> Vec<Message> {
        self.inner.poll()
    }

    fn membership(&self) -> Option<String> {
        self.inner.membership()
    }
}

/// One lost message must cost only itself: the receiver says it is missing
/// something, recovers by a state exchange, and hears that author again
/// (rgfaber/craft-libs#2).
#[test]
fn one_lost_message_is_recovered_by_a_state_exchange_and_the_author_is_heard_again() {
    let (ta, tb) = pair();
    // The host's first publication after admitting Bob is lost on the way;
    // which sequence number that is is only known once it is admitted.
    let loss: Arc<Mutex<u64>> = Arc::new(Mutex::new(u64::MAX));
    let mut h = host_on(Box::new(Lossy::on(ta, Arc::clone(&loss))), "abc", true);
    let mut bob = joiner(tb, "Bob", Some(token(HOST, Role::Editor)), None);
    admit(&mut h, &mut bob);
    assert_eq!(bob.doc, "abc", "admitted and caught up");
    if let Ok(mut slot) = loss.lock() {
        *slot = h.collab.seq + 1;
    }

    h.collab.send_command("lost".into(), b"{}".to_vec(), None);
    h.collab.send_command("held".into(), b"{}".to_vec(), None);
    bob.tick();
    assert!(bob.replayed.is_empty(), "the command behind the hole is not applied");
    assert_eq!(bob.stats()["order"]["held"], 1, "the session says what it is holding");
    assert_eq!(bob.stats()["order"]["gaps"], 1, "and that one author is behind");
    assert!(bob.stats()["order"]["stalled"].is_number(), "the hole has only just opened");

    // The deadline passes without the missing message ever arriving.
    bob.collab.order.backdate_stall(60_000);
    bob.tick();
    h.tick();
    bob.tick();

    assert_eq!(bob.stats()["order"]["gaps"], 0, "the stuck stream is given up");
    assert_eq!(bob.stats()["order"]["held"], 0);
    assert_eq!(bob.stats()["order"]["stalled"], Value::Null, "and the share says it is not stuck");
    assert_eq!(bob.doc, "abc", "recovered by the state exchange rather than stuck");

    // The author is heard again, which the stall used to prevent for good.
    h.collab.send_command("later".into(), b"{}".to_vec(), None);
    bob.tick();
    assert_eq!(bob.replayed, vec![("aaaaaaaa".to_string(), "later".to_string())], "a later command arrives");
}
