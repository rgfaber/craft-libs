//! The invite: one copyable line carrying everything a joiner needs to reach
//! the host's document — the document id, the host's id and carried key, the
//! realm, one seed station — and the host-signed open token the joiner
//! presents at the door. Coordinates are opaque strings; the transport
//! adapter is what knows how to use them.

use serde::{Deserialize, Serialize};

use crate::grant::SignedGrant;

/// The layout version. 2 added the host's signature over the envelope:
/// version 1 invites (unsigned) are refused outright.
pub const INVITE_VERSION: u32 = 2;

/// The signature context for invites.
pub const INVITE_CONTEXT: &[u8] = b"craft-collab/invite/v1";

fn default_profile() -> String {
    "pq_hybrid".into()
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
    pub issued_ms: u64,
    pub expires_ms: u64,
    /// The host-signed open token the joiner presents.
    pub token: SignedGrant,
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
    issued_ms: u64,
    expires_ms: u64,
    token: &'a SignedGrant,
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
            issued_ms: self.issued_ms,
            expires_ms: self.expires_ms,
            token: &self.token,
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
            issued_ms: 100,
            expires_ms: 200,
            token: SignedGrant {
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
            },
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
        assert!(invite().token.grant.is_open());
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
        tampered.token.signature.push(4);
        assert_ne!(base, tampered.signed_bytes().expect("bytes"), "the token is covered");
        // The signature itself is not part of what is signed.
        let mut tampered = invite();
        tampered.signature = vec![7, 7, 7];
        assert_eq!(base, tampered.signed_bytes().expect("bytes"));
    }
}
