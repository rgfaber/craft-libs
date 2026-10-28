//! The invite: one copyable line carrying everything a joiner needs to reach
//! the host's document — the document id, the host's id and carried key, the
//! realm, one seed station — and the host-signed open token the joiner
//! presents at the door. Coordinates are opaque strings; the transport
//! adapter is what knows how to use them.

use serde::{Deserialize, Serialize};

use crate::grant::{Role, SignedGrant};

/// The layout version. 2 added the host's signature over the envelope
/// (version 1 invites are refused outright); 3 made the open token optional
/// and added the realm-member role: a realm invite carries no token and is
/// admitted by a live membership instead; 4 names that membership's realm
/// (`member_realm`, which may differ from the transport's `realm`: a host in
/// realm H sharing with the members of realm E) and the host's own realm;
/// 5 names the sealed group the session's document travels under (`group`)
/// and the credential that pulls its key (`group_grant`), so a joiner can
/// pull the key before it knocks — a joiner with no key cannot publish a
/// sealed join request, and a clear knock would leak the document.
pub const INVITE_VERSION: u32 = 5;

/// The signature context for invites.
pub const INVITE_CONTEXT: &[u8] = b"craft-collab/invite/v1";

fn default_profile() -> String {
    "pq_hybrid".into()
}

/// The segments a topic prefix carries: `realm`, `org`, `app`, `domain`.
const PREFIX_SEGMENTS: usize = 4;

/// Whether `s` is a topic prefix this seam will carry: `realm/org/app/domain`,
/// exactly four segments, each non-empty and free of whitespace, under 256
/// characters. The transport owns what goes in each slot; this only keeps a
/// line of prose from arriving where a prefix belongs, and holds the count to
/// the four the threat model fixes so the topics the seam builds from it are
/// the five segments `macula_topic` requires.
fn is_topic_prefix(s: &str) -> bool {
    let segments: Vec<&str> = s.split('/').collect();
    s.len() <= 256
        && segments.len() == PREFIX_SEGMENTS
        && segments.iter().all(|seg| !seg.is_empty() && !seg.contains(char::is_whitespace) && seg.is_ascii())
}

/// A host's invitation to one document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Invite {
    pub v: u32,
    /// The document id.
    pub doc: String,
    /// The host's node id (hex).
    pub host: String,
    /// The host's carried public key (hex): what its grants verify under.
    pub host_key: String,
    /// The host's display name.
    pub host_name: String,
    /// The realm id (hex) the document is shared in.
    pub realm: String,
    /// The realm key (hex), when the transport needs one to be reached.
    #[serde(default)]
    pub realm_key: String,
    /// The signing profile (its name as the adapter knows it), so the joiner
    /// verifies the host's grants the way the host signs them.
    #[serde(default = "default_profile")]
    pub profile: String,
    /// One seed station, `host:port:node_hex`.
    pub seed: String,
    /// The sealed group this session's document travels under, as its whole
    /// topic prefix (`<realm>/<org>/<app>/<domain>`): the transport mints it
    /// when the host starts sharing, **never derived from the document**. The
    /// whole prefix travels rather than a bare id because its first segment is
    /// the realm's *name* while the envelope's `realm` is a hex id, and
    /// splitting a prefix across two fields is how they drift apart. Empty
    /// when the transport does not seal — a plain build, and
    /// `MemoryTransport`.
    #[serde(default)]
    pub group: String,
    /// What the joiner presents to pull that group's key. Opaque to the
    /// seam: the transport mints it with the open token, and on the mesh it
    /// is a UCAN for the distributor's `group_keys_v1`. Empty when the
    /// transport does not seal.
    #[serde(default)]
    pub group_grant: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
    /// The host-signed open token the joiner presents; a realm invite
    /// carries none and is admitted by membership instead.
    #[serde(default)]
    pub token: Option<SignedGrant>,
    /// Set on a realm invite: members of `realm` presenting a live
    /// membership UCAN are admitted with this role.
    #[serde(default)]
    pub member_role: Option<Role>,
    /// Set on a realm invite: the realm (by name) whose members are
    /// admitted. The host verifies their memberships against that realm's
    /// key from its own trust list; the joiner presents its membership of
    /// this realm.
    #[serde(default)]
    pub member_realm: Option<String>,
    /// The realm (by name) the host is attested in, when it has one: what
    /// the joiner shows beside the host's name.
    #[serde(default)]
    pub host_realm: Option<String>,
    /// An invite-by-person: the node this invite is for (hex). The token
    /// then carries that holder, and every other node is refused at the door.
    #[serde(default)]
    pub invitee: Option<String>,
    /// That person's display name, for the host's own copy.
    #[serde(default)]
    pub invitee_name: Option<String>,
    /// The host's signature over [`Invite::signed_bytes`]: every envelope
    /// field and the token, so a joiner can verify exactly who invited it
    /// and that nothing (seed, realm, expiry, token) was swapped on the way.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// What the invite signature covers: the envelope and the token, in one
/// canonical JSON body.
#[derive(Serialize)]
struct InviteBody<'a> {
    v: u32,
    doc: &'a str,
    host: &'a str,
    host_key: &'a str,
    host_name: &'a str,
    realm: &'a str,
    realm_key: &'a str,
    profile: &'a str,
    seed: &'a str,
    group: &'a str,
    group_grant: &'a str,
    issued_ms: u64,
    expires_ms: u64,
    token: Option<&'a SignedGrant>,
    member_role: Option<Role>,
    member_realm: Option<&'a str>,
    host_realm: Option<&'a str>,
    invitee: Option<&'a str>,
    invitee_name: Option<&'a str>,
}

impl Invite {
    /// The bytes the host's signature covers.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        let body = InviteBody {
            v: self.v,
            doc: &self.doc,
            host: &self.host,
            host_key: &self.host_key,
            host_name: &self.host_name,
            realm: &self.realm,
            realm_key: &self.realm_key,
            profile: &self.profile,
            seed: &self.seed,
            group: &self.group,
            group_grant: &self.group_grant,
            issued_ms: self.issued_ms,
            expires_ms: self.expires_ms,
            token: self.token.as_ref(),
            member_role: self.member_role,
            member_realm: self.member_realm.as_deref(),
            host_realm: self.host_realm.as_deref(),
            invitee: self.invitee.as_deref(),
            invitee_name: self.invitee_name.as_deref(),
        };
        let mut bytes = Vec::with_capacity(INVITE_CONTEXT.len() + 512);
        bytes.extend_from_slice(INVITE_CONTEXT);
        bytes.extend_from_slice(&serde_json::to_vec(&body).map_err(|e| e.to_string())?);
        Ok(bytes)
    }

    /// The copyable line.
    pub fn encode(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| e.to_string())
    }

    /// Parses an invite line and checks its layout version.
    pub fn decode(line: &str) -> Result<Invite, String> {
        let invite: Invite = serde_json::from_str(line).map_err(|e| format!("not an invite: {e}"))?;
        if invite.v != INVITE_VERSION {
            return Err(format!("unsupported invite version {}", invite.v));
        }
        // The group is a topic prefix (`<realm>/<org>/<app>/<domain>`). The
        // seam checks the shape and nothing else: the realm's name, the org
        // and the randomness of what the transport puts in those slots are the
        // transport's business, and a prefix derived from a document id would
        // put that id in the clear on every topic.
        if !invite.group.is_empty() && !is_topic_prefix(&invite.group) {
            return Err("an invite's group is a topic prefix".into());
        }
        Ok(invite)
    }

    /// Whether the invite is live at `now_ms`.
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.expires_ms > now_ms && self.issued_ms <= now_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::{GRANT_VERSION, Grant, Role};

    fn invite() -> Invite {
        Invite {
            v: INVITE_VERSION,
            doc: "doc-1".into(),
            host: "aa".repeat(32),
            host_key: "bb".repeat(32),
            host_name: "Host".into(),
            realm: "cc".repeat(32),
            realm_key: "ee".repeat(32),
            profile: "pq_hybrid".into(),
            seed: "station.example:4433:dd".repeat(32),
            group: "io.macula/~aa/craft/9f9f9f9f".into(),
            group_grant: "ucan-for-the-group".into(),
            issued_ms: 100,
            expires_ms: 200,
            token: Some(SignedGrant {
                grant: Grant {
                    v: GRANT_VERSION,
                    doc: "doc-1".into(),
                    host: "aa".repeat(32),
                    holder: String::new(),
                    role: Role::Editor,
                    issued_ms: 100,
                    expires_ms: 200,
                    nonce: "n".into(),
                },
                signature: vec![1, 2, 3],
            }),
            member_role: None,
            member_realm: None,
            host_realm: Some("io.macula".into()),
            invitee: None,
            invitee_name: None,
            signature: vec![9, 9, 9],
        }
    }

    #[test]
    fn an_invite_round_trips() {
        let line = invite().encode().expect("encode");
        let back = Invite::decode(&line).expect("decode");
        assert_eq!(back, invite());
        assert!(back.is_live(150));
        assert!(!back.is_live(250), "expiry is on the envelope too");
    }

    #[test]
    fn a_bad_line_or_version_is_refused() {
        assert!(Invite::decode("not json").is_err());
        let mut bad = invite();
        bad.v = 99;
        let line = serde_json::to_string(&bad).expect("json");
        assert!(Invite::decode(&line).is_err());
    }

    #[test]
    fn the_token_is_open() {
        assert!(invite().token.as_ref().expect("token").grant.is_open());
    }

    #[test]
    fn an_invite_by_person_names_its_invitee_in_the_signed_bytes() {
        let mut named = invite();
        named.invitee = Some("cc".repeat(32));
        named.invitee_name = Some("Juno".into());
        let line = named.encode().expect("encode");
        let back = Invite::decode(&line).expect("decode");
        assert_eq!(back.invitee.as_deref(), Some("cc".repeat(32).as_str()));
        assert_eq!(back.invitee_name.as_deref(), Some("Juno"));
        assert_ne!(named.signed_bytes().expect("bytes"), invite().signed_bytes().expect("bytes"), "the invitee is covered");
    }

    #[test]
    fn a_realm_invite_carries_no_token_and_names_the_member_role() {
        let mut realm_invite = invite();
        realm_invite.token = None;
        realm_invite.member_role = Some(Role::Viewer);
        realm_invite.invitee_name = None;
        let line = realm_invite.encode().expect("encode");
        let back = Invite::decode(&line).expect("decode");
        assert!(back.token.is_none(), "a realm invite needs no token");
        assert_eq!(back.member_role, Some(Role::Viewer));
        // The role is covered by the signature.
        assert_ne!(realm_invite.signed_bytes().expect("bytes"), invite().signed_bytes().expect("bytes"),);
    }

    #[test]
    fn a_cross_realm_invite_names_the_member_realm_and_the_host_realm_signed() {
        let mut cross = invite();
        cross.token = None;
        cross.member_role = Some(Role::Editor);
        cross.member_realm = Some("net.beam-campus".into());
        let line = cross.encode().expect("encode");
        let back = Invite::decode(&line).expect("decode");
        assert_eq!(back.member_realm.as_deref(), Some("net.beam-campus"), "the realm whose members are admitted");
        assert_eq!(back.host_realm.as_deref(), Some("io.macula"), "the realm the host is attested in");
        let base = cross.signed_bytes().expect("bytes");
        let mut swapped = cross.clone();
        swapped.member_realm = Some("io.macula".into());
        assert_ne!(base, swapped.signed_bytes().expect("bytes"), "the member realm is covered");
        let mut swapped = cross.clone();
        swapped.host_realm = Some("net.beam-campus".into());
        assert_ne!(base, swapped.signed_bytes().expect("bytes"), "the host realm is covered");
    }

    #[test]
    fn a_version_3_invite_is_refused() {
        let mut old = invite();
        old.v = 3;
        let line = serde_json::to_string(&old).expect("json");
        assert!(Invite::decode(&line).is_err(), "v3 names no member realm; a host must re-mint");
    }

    #[test]
    fn a_version_4_invite_is_refused() {
        let mut old = invite();
        old.v = 4;
        let line = serde_json::to_string(&old).expect("json");
        assert!(Invite::decode(&line).is_err(), "v4 names no sealed group; a host must re-mint");
    }

    /// The joiner pulls the group's key before it knocks, so the group's whole
    /// prefix and the credential that pulls its key travel in the signed
    /// envelope.
    #[test]
    fn the_group_and_its_grant_are_signed_and_prefix_checked() {
        let base = invite().signed_bytes().expect("bytes");
        let mut tampered = invite();
        tampered.group = "io.macula/~bb/craft/9f9f9f9f".into();
        assert_ne!(base, tampered.signed_bytes().expect("bytes"), "the group is covered");
        let mut tampered = invite();
        tampered.group_grant = "another-ucan".into();
        assert_ne!(base, tampered.signed_bytes().expect("bytes"), "the credential is covered");

        let back = Invite::decode(&invite().encode().expect("encode")).expect("decode");
        assert_eq!(back.group, "io.macula/~aa/craft/9f9f9f9f");
        assert_eq!(back.group_grant, "ucan-for-the-group");

        let mut prose = invite();
        prose.group = "the document id".into();
        let line = serde_json::to_string(&prose).expect("json");
        assert!(Invite::decode(&line).is_err(), "a group is a prefix, not prose");

        let mut two_segments = invite();
        two_segments.group = "io.macula/craft".into();
        let line = serde_json::to_string(&two_segments).expect("json");
        assert!(Invite::decode(&line).is_err(), "realm, org and app at least");

        // The threat model fixes the prefix at four segments, so the topic the
        // seam builds from it is the five `macula_topic` requires: three is one
        // short of the app, five leaves a slot nothing owns.
        let mut three_segments = invite();
        three_segments.group = "io.macula/~aa/craft".into();
        let line = serde_json::to_string(&three_segments).expect("json");
        assert!(Invite::decode(&line).is_err(), "three segments is one short");

        let mut five_segments = invite();
        five_segments.group = "io.macula/~aa/craft/9f9f9f9f/extra".into();
        let line = serde_json::to_string(&five_segments).expect("json");
        assert!(Invite::decode(&line).is_err(), "five segments is one too many");

        let mut four_segments = invite();
        four_segments.group = "io.macula/~aa/craft/9f9f9f9f".into();
        let back = Invite::decode(&four_segments.encode().expect("encode")).expect("decode");
        assert_eq!(back.group, "io.macula/~aa/craft/9f9f9f9f", "four is a prefix");

        let mut empty_segment = invite();
        empty_segment.group = "io.macula//craft/9f".into();
        let line = serde_json::to_string(&empty_segment).expect("json");
        assert!(Invite::decode(&line).is_err(), "no empty segment");

        // A transport that does not seal names no group and carries no credential.
        let mut plain = invite();
        plain.group = String::new();
        plain.group_grant = String::new();
        let back = Invite::decode(&plain.encode().expect("encode")).expect("decode");
        assert!(back.group.is_empty() && back.group_grant.is_empty());
    }

    #[test]
    fn the_signed_bytes_cover_the_envelope_and_the_token() {
        let base = invite().signed_bytes().expect("bytes");
        // Any field changing changes the signed bytes: the seed (where the
        // joiner connects), the expiry, and the token itself.
        let mut tampered = invite();
        tampered.seed.push('9');
        assert_ne!(base, tampered.signed_bytes().expect("bytes"), "the seed is covered");
        let mut tampered = invite();
        tampered.expires_ms += 1;
        assert_ne!(base, tampered.signed_bytes().expect("bytes"), "the expiry is covered");
        let mut tampered = invite();
        tampered.token.as_mut().expect("token").signature.push(4);
        assert_ne!(base, tampered.signed_bytes().expect("bytes"), "the token is covered");
        // The signature itself is not part of what is signed.
        let mut tampered = invite();
        tampered.signature = vec![7, 7, 7];
        assert_eq!(base, tampered.signed_bytes().expect("bytes"));
    }
}
