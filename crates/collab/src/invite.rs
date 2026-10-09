//! The invite: one copyable line carrying everything a joiner needs to reach
//! the host's document — the document id, the host's id and carried key, the
//! realm, one seed station — and the host-signed open token the joiner
//! presents at the door. Coordinates are opaque strings; the transport
//! adapter is what knows how to use them.

use serde::{Deserialize, Serialize};

use crate::grant::SignedGrant;

/// The layout version.
pub const INVITE_VERSION: u32 = 1;

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
    /// One seed station, `host:port:node_hex`.
    pub seed: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
    /// The host-signed open token the joiner presents.
    pub token: SignedGrant,
}

impl Invite {
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
}
