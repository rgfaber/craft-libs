//! The session protocol, driven by a stand-in app whose document is one
//! string: what the app does with each [`Inbound`] event is its own
//! business; these tests pin the door, grants, snapshots and stores.

use std::sync::{Arc, Mutex};

use super::*;
use crate::grant::{GRANT_VERSION, Grant, GrantVerifier, Revocation, SignedRevocation, mint_nonce};
use crate::mem::MemoryTransport;

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
    let mut collab = CollabSession::host("demo", "Host", Box::new(transport), &[]);
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
    let stored: Vec<SignedGrant> = serde_json::from_str(&grants.read().unwrap_or_default()).unwrap();
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
    let share = ShareContext { realm: "cc".repeat(32), realm_key: String::new(), seed: "station.example:4433:dd".into(), profile: "pq_pure".into() };
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
    h.collab.set_share_context(ShareContext { realm: "r".into(), realm_key: "k".into(), seed: "s".into(), profile: "p".into() });
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
