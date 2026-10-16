//! One shared document session: the collaboration protocol an app runs while
//! its document is shared, independent of the app's document model.
//!
//! [`CollabSession`] owns the transport, the text CRDT, per-author ordering,
//! presence, the access door (join requests, grants, revocation), invites,
//! contacts, the joiner's admission and snapshot retries, and latency
//! samples. What touches the document stays with the app: each
//! [`tick`](CollabSession::tick) hands back the [`Inbound`] events the app
//! applies in order (peer text, peer commands, snapshot traffic), and the app
//! sends its own edits through [`send_text`](CollabSession::send_text) and
//! [`send_command`](CollabSession::send_command).
//!
//! Persistence goes through [`TextStore`]: the seam names what to keep, the
//! app decides where (a file, browser storage, nothing).

use std::collections::{BTreeMap, HashMap};

use serde_json::{Value, json};

use crate::contacts::{Contact, Contacts};
use crate::grant::{Access, GrantIssuer, MembershipVerifier, Role, SignedGrant};
use crate::invite::{INVITE_VERSION, Invite};
use crate::message::{Kind, Message};
use crate::order::OrderBuffer;
use crate::presence::{Peer, Presence};
use crate::text::{BodyParagraph, TextMerge};
use crate::transport::Transport;

/// How long a grant issued on a join lasts.
const GRANT_TTL_MS: u64 = 24 * 60 * 60 * 1_000;

/// How many times a joiner asks for admission, and for the snapshot, before
/// giving up.
const MAX_ATTEMPTS: u32 = 5;

/// How long a joiner waits between two admission or snapshot requests.
const RETRY_MS: u64 = 2_000;

/// A joiner admitted by realm membership asks for an extension once its
/// grant ends within this long (macula-realm#46: the realm mints for 1 hour
/// and the adapter renews every 10 minutes).
const EXTEND_BEFORE_MS: u64 = 10 * 60 * 1_000;

/// How long a joiner waits between two extension requests.
const EXTEND_RETRY_MS: u64 = 60 * 1_000;

/// Milliseconds since the UNIX epoch, 0 on wasm. A clockless peer holds no
/// live grant (grants need a wall clock), so collaboration is only wired
/// where a real clock exists.
pub fn now_ms() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        0
    }
}

/// Where one piece of a session's state persists, as the app decides: the
/// installed grants (a restarted host relearns its holders) or the contacts
/// (they belong to the person, so one store serves every document).
pub trait TextStore: Send {
    /// The stored text, if there is any.
    fn read(&self) -> Option<String>;
    /// Replaces the stored text. A failed write never stops the session.
    fn write(&self, text: &str);
}

/// What a peer sent that the app applies to its document, in the order the
/// peers' messages arrived (per author, in sequence). Access has already been
/// checked; a stranger's message never becomes an event.
#[derive(Clone, Debug, PartialEq)]
pub enum Inbound {
    /// A text change as a CRDT update: the app applies it to
    /// [`CollabSession::texts_mut`] and brings its document along. `props`
    /// is the formatting the sender gave the inserted text, as the app's own
    /// bytes, when it knew it.
    Text { author: String, para: String, update: Vec<u8>, props: Option<Vec<u8>> },
    /// A command to replay with a remote origin, under the selection it ran
    /// with (`anchor`, app-encoded). An app refuses ids it would never send
    /// and counts it with [`CollabSession::note_refused`].
    Command { author: String, id: String, params: Vec<u8>, anchor: Option<String> },
    /// A peer asks for the document: the app answers with
    /// [`CollabSession::answer_snapshot`].
    SnapshotWanted,
    /// A peer's document: the app loads it when
    /// [`CollabSession::awaiting_snapshot`], then calls
    /// [`CollabSession::snapshot_loaded`] with `crdt`.
    Snapshot { data: Vec<u8>, crdt: Vec<u8> },
}

/// A host's mesh coordinates for invites: opaque to the seam, carried
/// verbatim in every invite it mints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareContext {
    pub realm: String,
    pub realm_key: String,
    pub seed: String,
    pub profile: String,
}

/// A join request waiting for the host's yes.
struct PendingJoin {
    name: String,
    role: Role,
    /// The membership's own end, when the admission was one: the grant
    /// never outlives it.
    ends_ms: Option<u64>,
}

/// One shared document session. See the module docs.
pub struct CollabSession {
    doc: String,
    name: String,
    author: String,
    transport: Box<dyn Transport>,
    texts: TextMerge,
    presence: Presence,
    order: OrderBuffer,
    /// Received-edit latency per author, milliseconds.
    latency: HashMap<String, Vec<u64>>,
    /// Remote commands that failed to apply (a divergence signal).
    remote_errors: u64,
    /// Messages dropped by the access check (stranger, expired, wrong role).
    unauthorized: u64,
    /// Who may act on this document, when access control is on.
    access: Option<Access>,
    seq: u64,
    /// This process's epoch: a restart keeps its author id but sends a new
    /// epoch, so peers never confuse its restarted sequence with the old.
    epoch: u64,
    last_cursor: Option<String>,
    /// This session asked for the document snapshot and is waiting for it.
    awaiting_snapshot: bool,
    snapshot_attempts: u32,
    last_snapshot_ms: u64,
    /// The host's signing side, when this session is the host.
    issuer: Option<Box<dyn GrantIssuer>>,
    /// A joiner's open token: presented until a grant arrives.
    token: Option<SignedGrant>,
    /// A joiner's realm membership UCAN, when it joins by membership.
    membership: Option<String>,
    /// The host's realm-member verifier: when set, the document is shared
    /// with that realm and a live membership admits.
    member_verifier: Option<Box<dyn MembershipVerifier>>,
    /// This joiner is waiting for its grant.
    awaiting_grant: bool,
    grant_attempts: u32,
    last_grant_ms: u64,
    /// The membership the last extension requests presented, how many were
    /// sent with it and when the last one went: a membership that stops
    /// renewing is presented at most [`MAX_ATTEMPTS`] times.
    extend_membership: Option<String>,
    extend_attempts: u32,
    last_extend_ms: u64,
    /// Join requests waiting for the host's yes, by node id.
    pending: BTreeMap<String, PendingJoin>,
    /// Whether the host admits a valid token without asking.
    auto_approve: bool,
    /// Whether this session holds the document: the host does from the
    /// start, a joiner only once it has loaded a snapshot. An approved
    /// joiner that has not caught up must never answer another joiner's
    /// snapshot request with its empty document.
    has_snapshot: bool,
    share: Option<ShareContext>,
    grants_store: Option<Box<dyn TextStore>>,
    contacts: Contacts,
    contacts_store: Option<Box<dyn TextStore>>,
}

impl CollabSession {
    fn new(doc: &str, name: &str, transport: Box<dyn Transport>) -> CollabSession {
        let author = transport.author();
        let texts = TextMerge::new(&author);
        CollabSession {
            doc: doc.to_string(),
            name: name.to_string(),
            author,
            transport,
            texts,
            presence: Presence::default(),
            order: OrderBuffer::default(),
            latency: HashMap::new(),
            remote_errors: 0,
            unauthorized: 0,
            access: None,
            seq: 0,
            epoch: now_ms().wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ u64::from(std::process::id()).wrapping_mul(0xBF58_476D_1CE4_E5B9),
            last_cursor: None,
            awaiting_snapshot: false,
            snapshot_attempts: 0,
            last_snapshot_ms: 0,
            issuer: None,
            token: None,
            membership: None,
            member_verifier: None,
            awaiting_grant: false,
            grant_attempts: 0,
            extend_membership: None,
            extend_attempts: 0,
            last_extend_ms: 0,
            last_grant_ms: 0,
            pending: BTreeMap::new(),
            auto_approve: false,
            has_snapshot: false,
            share: None,
            grants_store: None,
            contacts: Contacts::new(),
            contacts_store: None,
        }
    }

    /// Shares `doc` as its origin: the session holds the document from the
    /// start, and `body` seeds the shared text (joiners receive it in the
    /// snapshot).
    pub fn host(doc: &str, name: &str, transport: Box<dyn Transport>, body: &[BodyParagraph]) -> CollabSession {
        let mut session = CollabSession::new(doc, name, transport);
        session.has_snapshot = true;
        session.texts.seed_body(body);
        session
    }

    /// Joins an already-shared `doc` without admission (an open session):
    /// the first tick asks a peer for the document.
    pub fn join(doc: &str, name: &str, transport: Box<dyn Transport>) -> CollabSession {
        let mut session = CollabSession::new(doc, name, transport);
        session.awaiting_snapshot = true;
        session
    }

    /// Joins `doc` presenting an admission: the invite's open token, a realm
    /// membership UCAN, or both. The session asks the host until a grant
    /// names it, then asks for the document.
    pub fn join_requesting(
        doc: &str,
        name: &str,
        transport: Box<dyn Transport>,
        token: Option<SignedGrant>,
        membership: Option<String>,
    ) -> CollabSession {
        let mut session = CollabSession::new(doc, name, transport);
        session.token = token;
        session.membership = membership;
        session.awaiting_grant = true;
        session
    }

    /// The shared document's id.
    pub fn doc(&self) -> &str {
        &self.doc
    }

    /// This author's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// This author's id (the transport's node id).
    pub fn author(&self) -> &str {
        &self.author
    }

    /// The shared text.
    pub fn texts(&self) -> &TextMerge {
        &self.texts
    }

    /// The shared text, to apply a peer's update or capture a local edit.
    pub fn texts_mut(&mut self) -> &mut TextMerge {
        &mut self.texts
    }

    /// The peers present, with their app-encoded cursors.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.presence.peers()
    }

    /// Turns on access control: only the host and live grant holders act.
    /// Without it the session is open.
    pub fn set_access(&mut self, access: Access) {
        self.access = Some(access);
    }

    /// Installs the host's signing side: with it, this session answers join
    /// requests with grants.
    pub fn set_issuer(&mut self, issuer: Box<dyn GrantIssuer>) {
        self.issuer = Some(issuer);
    }

    /// Whether the host admits a valid token without asking (a UI leaves
    /// this off and approves from [`pending`](CollabSession::pending)).
    pub fn set_auto_approve(&mut self, on: bool) {
        self.auto_approve = on;
    }

    /// Remembers the mesh coordinates this host shares in, so an invite is
    /// one call.
    pub fn set_share_context(&mut self, share: ShareContext) {
        self.share = Some(share);
    }

    /// The host shares this document with a realm: members presenting a
    /// live membership of it are admitted with the verifier's role, and a
    /// grant issued on one is capped at the membership's own end.
    pub fn set_member_verifier(&mut self, verifier: Box<dyn MembershipVerifier>) {
        self.member_verifier = Some(verifier);
    }

    /// Whether this host shares with a realm.
    pub fn shares_with_realm(&self) -> bool {
        self.member_verifier.is_some()
    }

    /// Whether this session can mint invites: it is the host and knows its
    /// mesh coordinates.
    pub fn can_invite(&self) -> bool {
        self.issuer.is_some() && self.share.is_some()
    }

    /// The holders of this document, sorted.
    pub fn holders(&self) -> Vec<String> {
        self.access.as_ref().map(Access::holder_ids).unwrap_or_default()
    }

    /// Join requests awaiting the host's yes: (node id, display name).
    pub fn pending(&self) -> Vec<(String, String)> {
        self.pending.iter().map(|(node, p)| (node.clone(), p.name.clone())).collect()
    }

    /// Whether this joiner is still waiting for its grant.
    pub fn awaiting_grant(&self) -> bool {
        self.awaiting_grant
    }

    /// Whether this joiner is still waiting for the document.
    pub fn awaiting_snapshot(&self) -> bool {
        self.awaiting_snapshot
    }

    /// Persists the installed grants in `store`, and installs what it
    /// holds: a restarted host relearns its holders and a restarted holder
    /// its own grant. Malformed or unverifiable entries are skipped.
    pub fn set_grants_store(&mut self, store: Box<dyn TextStore>) {
        let now = now_ms();
        if let Some(text) = store.read()
            && let Ok(grants) = serde_json::from_str::<Vec<SignedGrant>>(&text)
            && let Some(access) = self.access.as_mut()
        {
            for signed in &grants {
                let _ = access.install(signed, now);
            }
        }
        self.grants_store = Some(store);
    }

    /// Persists this person's contacts in `store`, and loads what it holds.
    pub fn set_contacts_store(&mut self, store: Box<dyn TextStore>) {
        if let Some(text) = store.read() {
            self.contacts = Contacts::from_json(&text);
        }
        self.contacts_store = Some(store);
    }

    fn save_grants(&self) {
        let (Some(store), Some(access)) = (self.grants_store.as_ref(), self.access.as_ref()) else { return };
        if let Ok(json) = serde_json::to_string(&access.signed_grants()) {
            store.write(&json);
        }
    }

    fn save_contacts(&self) {
        if let Some(store) = self.contacts_store.as_ref() {
            store.write(&self.contacts.to_json());
        }
    }

    /// Remembers one sighting of a person: their node id, the name they gave
    /// (empty keeps what is known) and the realm, when known.
    pub fn note_contact(&mut self, node: &str, name: &str, realm: Option<&str>) {
        self.contacts.upsert(node, name, realm, now_ms());
        self.save_contacts();
    }

    /// The people this device has met, most recently seen first.
    pub fn contacts(&self) -> Vec<Contact> {
        self.contacts.list()
    }

    /// Forgets a person; true when one was known.
    pub fn forget_contact(&mut self, node: &str) -> bool {
        let forgotten = self.contacts.remove(node);
        if forgotten {
            self.save_contacts();
        }
        forgotten
    }

    /// Queues a message for the peers.
    fn send(&mut self, kind: Kind) {
        self.seq += 1;
        let msg = Message { doc: self.doc.clone(), author: self.author.clone(), epoch: self.epoch, seq: self.seq, sent_at_ms: now_ms(), kind };
        let _ = self.transport.send(msg);
    }

    /// Shares a local text edit (a CRDT update from [`texts_mut`](CollabSession::texts_mut)).
    pub fn send_text(&mut self, para: String, update: Vec<u8>, props: Option<Vec<u8>>) {
        self.send(Kind::TextEdit { para, update, props });
    }

    /// Shares a local command for the peers to replay.
    pub fn send_command(&mut self, id: String, params: Vec<u8>, anchor: Option<String>) {
        self.send(Kind::Command { id, params, anchor });
    }

    /// Shares this author's cursor (app-encoded) when it moved since the
    /// last share.
    pub fn share_cursor(&mut self, cursor: Option<String>) {
        if self.last_cursor == cursor {
            return;
        }
        self.last_cursor = cursor.clone();
        let name = self.name.clone();
        self.send(Kind::CursorMoved { position: cursor, name: Some(name) });
    }

    /// Undoes this author's most recent shared edit and shares the change.
    /// `None` when there is nothing of this author's to undo; the app then
    /// brings its document along with the shared text.
    pub fn undo_local(&mut self) -> Option<Vec<u8>> {
        let update = self.texts.undo_local()?;
        self.send(Kind::TextEdit { para: String::new(), update: update.clone(), props: None });
        Some(update)
    }

    /// Answers a [`Inbound::SnapshotWanted`] with the app's document. Only a
    /// session that holds the document answers.
    pub fn answer_snapshot(&mut self, data: Vec<u8>) {
        if !self.has_snapshot {
            return;
        }
        let crdt = self.texts.full_update();
        self.send(Kind::Snapshot { data, crdt });
    }

    /// The app loaded a peer's snapshot: the shared text takes the peer's
    /// history, so later merges align, and this session now holds the
    /// document.
    pub fn snapshot_loaded(&mut self, crdt: &[u8]) {
        let _ = self.texts.apply_doc_update(crdt);
        self.awaiting_snapshot = false;
        self.has_snapshot = true;
    }

    /// Counts a peer message the app refused (a command it would never
    /// send).
    pub fn note_refused(&mut self) {
        self.unauthorized += 1;
    }

    /// Counts a peer command that failed to apply (a divergence signal).
    pub fn note_remote_error(&mut self) {
        self.remote_errors += 1;
    }

    /// Takes the peers' messages, runs the protocol on them and returns what
    /// the app applies, in order. Then a waiting joiner asks again for its
    /// admission and its document. The app calls this once per frame while
    /// shared, applies the events, and shares its cursor.
    pub fn tick(&mut self) -> Vec<Inbound> {
        let mut events = Vec::new();
        for msg in self.poll() {
            if let Some(event) = self.receive(msg) {
                events.push(event);
            }
        }
        let now = now_ms();
        if self.awaiting_grant
            && self.grant_attempts < MAX_ATTEMPTS
            && (self.grant_attempts == 0 || now.saturating_sub(self.last_grant_ms) >= RETRY_MS)
            && (self.token.is_some() || self.membership.is_some())
        {
            self.grant_attempts += 1;
            self.last_grant_ms = now;
            let (token, membership, name) = (self.token.clone(), self.membership.clone(), self.name.clone());
            self.send(Kind::JoinRequest { token, name, membership });
        }
        self.ask_for_extension(now);
        // A publication can be lost; the request is cheap and idempotent.
        if self.awaiting_snapshot
            && self.snapshot_attempts < MAX_ATTEMPTS
            && (self.snapshot_attempts == 0 || now.saturating_sub(self.last_snapshot_ms) >= RETRY_MS)
        {
            self.snapshot_attempts += 1;
            self.last_snapshot_ms = now;
            self.send(Kind::SnapshotRequest {});
        }
        events
    }

    /// The messages for this document from other authors, in per-author
    /// sequence.
    fn poll(&mut self) -> Vec<Message> {
        let mut out = Vec::new();
        for msg in self.transport.poll() {
            if msg.doc == self.doc && msg.author != self.author {
                out.extend(self.order.push(msg));
            }
        }
        out
    }

    fn receive(&mut self, msg: Message) -> Option<Inbound> {
        // A join request is the door: the host judges it by its token, not
        // by a holder lookup (the joiner holds no grant yet).
        if let Kind::JoinRequest { token, name, membership } = &msg.kind {
            self.on_join_request(&msg.author, token.as_ref(), membership.as_deref(), name);
            return None;
        }
        // Access control on every message: the host and live grant holders
        // act; strangers, expired grants and role violations are dropped.
        if let Some(access) = self.access.as_ref()
            && !access.admits(&msg.author, &msg.kind, now_ms()).is_admitted()
        {
            self.unauthorized += 1;
            return None;
        }
        match msg.kind {
            Kind::TextEdit { para, update, props } => {
                self.record_latency(&msg.author, msg.sent_at_ms);
                Some(Inbound::Text { author: msg.author, para, update, props })
            }
            Kind::Command { id, params, anchor } => {
                self.record_latency(&msg.author, msg.sent_at_ms);
                Some(Inbound::Command { author: msg.author, id, params, anchor })
            }
            Kind::CursorMoved { position, name } => {
                let name = name.unwrap_or_else(|| msg.author.chars().take(6).collect());
                self.presence.set(&msg.author, &name, position);
                None
            }
            Kind::SnapshotRequest {} => self.has_snapshot.then_some(Inbound::SnapshotWanted),
            Kind::Snapshot { data, crdt } => self.awaiting_snapshot.then_some(Inbound::Snapshot { data, crdt }),
            Kind::GrantIssued { grant } => {
                // Every replica installs it (the verifier decides); a joiner
                // this grant names is admitted and may now ask for the doc.
                if let Some(access) = self.access.as_mut() {
                    let _ = access.install(&grant, now_ms());
                }
                if self.awaiting_grant && grant.grant.holder == self.author {
                    self.awaiting_grant = false;
                    self.awaiting_snapshot = true;
                    self.snapshot_attempts = 0;
                }
                self.save_grants();
                None
            }
            Kind::Revoked { revocation } => {
                if let Some(access) = self.access.as_mut() {
                    let _ = access.revoke(&revocation, now_ms());
                }
                self.save_grants();
                None
            }
            // Handled before the access check: it is the door itself.
            Kind::JoinRequest { .. } => None,
        }
    }

    /// A joiner admitted by membership asks the host to extend its grant
    /// before it ends, presenting its current membership. Only while its own
    /// table still holds a grant for it (a revocation removes it, so a
    /// revoked joiner never knocks), and never on the first-join state, so
    /// an extension cannot reload the document.
    fn ask_for_extension(&mut self, now: u64) {
        if self.awaiting_grant || self.issuer.is_some() {
            return;
        }
        let Some(membership) = self.transport.membership().or_else(|| self.membership.clone()) else { return };
        let Some(grant) = self.access.as_ref().and_then(|access| access.grant_for(&self.author)) else { return };
        if grant.expires_ms > now.saturating_add(EXTEND_BEFORE_MS) {
            return;
        }
        if self.extend_membership.as_deref() != Some(membership.as_str()) {
            self.extend_membership = Some(membership.clone());
            self.extend_attempts = 0;
        }
        if self.extend_attempts >= MAX_ATTEMPTS || (self.extend_attempts > 0 && now.saturating_sub(self.last_extend_ms) < EXTEND_RETRY_MS) {
            return;
        }
        self.extend_attempts += 1;
        self.last_extend_ms = now;
        self.membership = Some(membership.clone());
        let name = self.name.clone();
        self.send(Kind::JoinRequest { token: None, name, membership: Some(membership) });
    }

    /// The host judges a join request: a valid token, or a live membership
    /// of the shared realm, admits (at once when auto-approving, else queued
    /// for the host's yes); anything else is refused and counted.
    fn on_join_request(&mut self, author: &str, token: Option<&SignedGrant>, membership: Option<&str>, name: &str) {
        if self.issuer.is_none() {
            return; // not the host: only the host admits
        }
        let now = now_ms();
        let by_token = token
            .and_then(|token| self.access.as_ref().and_then(|access| access.check_token_for(token, author, now).ok()))
            .map(|checked| (checked.role, None));
        // The verifier holds the realm's key and the host's role mapping;
        // the audience check pins the caller, and the membership's own end
        // caps any grant issued on it.
        let admitted = by_token.or_else(|| {
            let (verifier, ucan) = (self.member_verifier.as_ref()?, membership?);
            let ends_ms = verifier.verify_member(ucan, author, now).ok()?;
            Some((verifier.role(), Some(ends_ms)))
        });
        // A stranger, or a membership that has already ended: nothing to
        // grant, so the door refuses and counts it.
        let Some((role, ends_ms)) = admitted.filter(|(_, ends)| !ends.is_some_and(|ends| ends <= now)) else {
            self.unauthorized += 1;
            return;
        };
        // A holder of a live grant presenting a renewed membership: the host
        // admitted this person once, so the grant is extended without asking
        // again, keeping its role, and only when it then ends later.
        let live = self.access.as_ref().and_then(|access| access.grant_for(author)).filter(|grant| grant.is_live(now)).cloned();
        if let (Some(current), Some(ends)) = (live, ends_ms) {
            let extended_end = now.saturating_add(GRANT_TTL_MS).min(ends);
            if extended_end > current.expires_ms {
                self.issue_grant(author, current.role, now, Some(ends));
            }
            return;
        }
        // The person at the door is someone we have met: remember them.
        self.note_contact(author, name, None);
        // A holder the host revoked comes back only with the host's yes.
        let revoked = self.access.as_ref().is_some_and(|access| access.was_revoked(author));
        if self.auto_approve && !revoked {
            self.issue_grant(author, role, now, ends_ms);
        } else {
            self.pending.insert(author.to_string(), PendingJoin { name: name.to_string(), role, ends_ms });
        }
    }

    /// The host approves a pending joiner: mints the grant from its
    /// admission's role (capped by the membership's end when it was one),
    /// broadcasts it and installs it.
    pub fn approve(&mut self, node: &str) -> Result<(), String> {
        let Some(p) = self.pending.get(node) else { return Err("no such pending joiner".into()) };
        let (role, ends_ms) = (p.role, p.ends_ms);
        if self.issuer.is_none() {
            return Err("this session is not the host".into());
        }
        self.issue_grant(node, role, now_ms(), ends_ms);
        Ok(())
    }

    /// The host revokes a holder: signs it, broadcasts it, applies it.
    pub fn revoke(&mut self, node: &str) -> Result<(), String> {
        let now = now_ms();
        let Some(issuer) = self.issuer.as_ref() else { return Err("this session is not the host".into()) };
        let signed = issuer.revoke(&self.doc, node, now)?;
        self.send(Kind::Revoked { revocation: signed.clone() });
        if let Some(access) = self.access.as_mut() {
            let _ = access.revoke(&signed, now);
        }
        self.pending.remove(node);
        Ok(())
    }

    /// Mints a grant for `holder` as the host, broadcasts it and installs
    /// it. `ends_ms` is the membership's own end when the admission was one:
    /// the grant never outlives it.
    fn issue_grant(&mut self, holder: &str, role: Role, now: u64, ends_ms: Option<u64>) {
        let ttl_ms = match ends_ms {
            Some(ends) => GRANT_TTL_MS.min(ends.saturating_sub(now)),
            None => GRANT_TTL_MS,
        };
        if ttl_ms == 0 {
            return; // nothing left of the membership: nothing to grant
        }
        let Some(issued) = self.issuer.as_ref().and_then(|issuer| issuer.issue(&self.doc, holder, role, ttl_ms, now).ok()) else { return };
        self.send(Kind::GrantIssued { grant: issued.clone() });
        if let Some(access) = self.access.as_mut() {
            let _ = access.install(&issued, now);
        }
        self.pending.remove(holder);
        self.save_grants();
    }

    /// Mints this host's invite line for the document. `share` is the mesh
    /// coordinates to carry (the remembered ones when `None`); `host_realm`
    /// is the host's own realm when it is signed in to one, shown beside its
    /// name on the joiner's side.
    pub fn mint_invite(&self, share: Option<&ShareContext>, host_realm: Option<&str>, role: Role, ttl_ms: u64) -> Result<String, String> {
        self.mint(share, host_realm, role, ttl_ms, false, None)
    }

    /// Mints a realm invite: no open token, and members of the shared realm
    /// are admitted with the verifier's role.
    pub fn mint_realm_invite(&self, share: Option<&ShareContext>, host_realm: Option<&str>, ttl_ms: u64) -> Result<String, String> {
        let Some(verifier) = self.member_verifier.as_ref() else { return Err("this document is not shared with a realm".into()) };
        self.mint(share, host_realm, verifier.role(), ttl_ms, true, None)
    }

    /// Mints an invite for one person: the token names their node id, so
    /// only that node is admitted at the door.
    pub fn mint_invite_for(
        &self,
        share: Option<&ShareContext>,
        host_realm: Option<&str>,
        holder: &str,
        invitee_name: &str,
        role: Role,
        ttl_ms: u64,
    ) -> Result<String, String> {
        let holder = holder.trim().to_ascii_lowercase();
        if holder.len() != 64 || !holder.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("an invitee node id is 64 hex characters".into());
        }
        self.mint(share, host_realm, role, ttl_ms, false, Some((&holder, invitee_name)))
    }

    fn mint(
        &self,
        share: Option<&ShareContext>,
        host_realm: Option<&str>,
        role: Role,
        ttl_ms: u64,
        realm_members: bool,
        holder: Option<(&str, &str)>,
    ) -> Result<String, String> {
        let Some(share) = share.or(self.share.as_ref()) else { return Err("this session does not know its mesh coordinates".into()) };
        let Some(issuer) = self.issuer.as_ref() else { return Err("this session is not the host".into()) };
        let now = now_ms();
        // A realm invite names the realm whose members it admits: the
        // verifier's, which may be another realm than the host's own.
        let member_realm = match (realm_members, self.member_verifier.as_ref()) {
            (true, Some(verifier)) => Some(verifier.realm().to_string()),
            (true, None) => return Err("this document is not shared with a realm".into()),
            (false, _) => None,
        };
        let token = match holder {
            Some((node, _)) => issuer.issue(&self.doc, node, role, ttl_ms, now)?,
            None => issuer.open_token(&self.doc, role, ttl_ms, now)?,
        };
        let mut invite = Invite {
            v: INVITE_VERSION,
            doc: self.doc.clone(),
            host: issuer.node_id(),
            host_key: hex(&issuer.carried_key()),
            host_name: self.name.clone(),
            realm: share.realm.clone(),
            realm_key: share.realm_key.clone(),
            profile: share.profile.clone(),
            seed: share.seed.clone(),
            issued_ms: now,
            expires_ms: now.saturating_add(ttl_ms),
            token: if realm_members { None } else { Some(token) },
            member_role: if realm_members { Some(role) } else { None },
            member_realm,
            host_realm: host_realm.map(str::to_string),
            invitee: holder.map(|(node, _)| node.to_string()),
            invitee_name: holder.map(|(_, name)| name.to_string()),
            signature: Vec::new(),
        };
        // Signed by the host identity: the joiner verifies who invited it,
        // and that no field was swapped en route.
        invite.signature = issuer.sign(&invite.signed_bytes()?)?;
        invite.encode()
    }

    fn record_latency(&mut self, author: &str, sent_at_ms: u64) {
        if sent_at_ms == 0 {
            return; // the sender had no clock
        }
        self.latency.entry(author.to_string()).or_default().push(now_ms().saturating_sub(sent_at_ms));
    }

    /// The session's status for agents and the share window: peers, join
    /// state, per-pair latency (p50/p95), refusals and the divergence count.
    pub fn stats(&self) -> Value {
        let peers: Vec<Value> =
            self.presence.peers().map(|p| json!({"name": p.name, "author": short(&p.author), "hasCursor": p.position.is_some()})).collect();
        let mut latency: Vec<Value> = self
            .latency
            .iter()
            .map(|(author, samples)| {
                let mut v = samples.clone();
                v.sort_unstable();
                json!({"author": short(author), "n": v.len(), "p50Ms": percentile(&v, 50), "p95Ms": percentile(&v, 95)})
            })
            .collect();
        latency.sort_by(|a, b| a["author"].as_str().cmp(&b["author"].as_str()));
        json!({
            "active": true,
            "doc": self.doc,
            "author": short(&self.author),
            "authorId": self.author,
            "joined": !self.awaiting_snapshot,
            "seq": self.seq,
            "peers": peers,
            "latency": latency,
            "remoteErrors": self.remote_errors,
            "unauthorized": self.unauthorized,
            "access": self.access.is_some(),
            "awaitingGrant": self.awaiting_grant,
            "realmShare": self.member_verifier.is_some(),
            "pending": self.pending.iter().map(|(node, p)| json!({"node": short(node), "name": p.name})).collect::<Vec<_>>(),
            "contacts": self.contacts.len(),
        })
    }
}

/// An author id shortened for people: its first eight characters.
pub fn short(author: &str) -> String {
    author.chars().take(8).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn percentile(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len().saturating_sub(1) * p) / 100;
    sorted.get(idx).copied().unwrap_or(0)
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
