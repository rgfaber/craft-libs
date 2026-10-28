//! The Share and Sign in windows for Craft apps, in egui.
//!
//! The Share window shows a document's shared session
//! ([`craft_collab::CollabSession`]): the host mints and copies invite lines,
//! approves the people waiting at the door, revokes holders and invites its
//! contacts; a joiner pastes an invite and waits for its grant. The Sign in
//! window is the realm surface: membership, display name, and the portal
//! link with its QR and confirmation poll.
//!
//! The windows hold only their own state ([`ShareState`], [`LoginState`]).
//! Everything else comes from the app through [`ShareHost`]: its shared
//! session, its realm status, and the hooks that need the network (joining,
//! signing in). A hook the app leaves out greys out its button.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use serde_json::Value;

pub mod login;
pub mod qr;
pub mod share;

pub use login::{LoginState, renewal_line};
pub use share::{ShareState, invite_preview};

/// Which of the app's network hooks this build has. A missing one greys
/// out its button and its command answers that the build lacks it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hooks {
    /// Join a document through a pasted invite line.
    pub join_invite: bool,
    /// Re-read the realm membership.
    pub realm_refresh: bool,
    /// Start a portal sign-in.
    pub sign_in: bool,
    /// Poll a started sign-in.
    pub sign_in_check: bool,
    /// Read the identity's display name.
    pub identity_name: bool,
    /// Save the identity's display name.
    pub set_identity_name: bool,
}

/// What the windows need from the app. The app owns the shared session,
/// the identity and the mesh; the windows only drive them.
pub trait ShareHost {
    /// The document's shared session, while it is shared.
    fn collab(&self) -> Option<&craft_collab::CollabSession>;
    /// The same, to approve, revoke, mint and forget.
    fn collab_mut(&mut self) -> Option<&mut craft_collab::CollabSession>;
    /// The realm membership status: `signedIn`, `realm`, `tier`, `handle`
    /// and `ucanExpiresMs` when signed in.
    fn realm_status(&self) -> Value;
    /// The name a joiner's form starts with (the app's user name).
    fn default_name(&self) -> String;
    /// Which network hooks this build has.
    fn hooks(&self) -> Hooks;
    /// Joins the shared document an invite line names, as `name`.
    fn join_invite(&mut self, invite: &str, name: &str) -> Result<(), String>;
    /// Re-reads the realm membership; the new status.
    fn realm_refresh(&mut self) -> Result<Value, String>;
    /// Starts a portal sign-in: `joinUrl` and `expiresAt`.
    fn sign_in(&mut self) -> Result<Value, String>;
    /// Polls the started sign-in: `status` is pending, confirmed, expired
    /// or none.
    fn sign_in_check(&mut self) -> Result<Value, String>;
    /// The identity's display name, as `name`.
    fn identity_name(&mut self) -> Result<Value, String>;
    /// Saves the identity's display name.
    fn set_identity_name(&mut self, name: &str) -> Result<Value, String>;

    /// The host's own realm when it is signed in to one: what an invite
    /// shows beside the host's name.
    fn host_realm(&self) -> Option<String> {
        let status = self.realm_status();
        (status["signedIn"] == true).then(|| status["realm"].as_str().map(str::to_string)).flatten()
    }

    /// Whether this build's shares are sealed. Every released Craft build seals
    /// (macula-craft-collab 0.8), so the default is `true`: an app that does not
    /// seal says so, rather than an app that does seal having to remember to.
    /// A sealed share offers named invites only — never a line anyone could copy
    /// — because the invite must carry the credential that pulls the share's key.
    fn sealed(&self) -> bool {
        true
    }
}

/// How long an invite minted from the Share window lasts.
pub const INVITE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;

/// A node id shortened for people.
fn short(node: &str) -> String {
    craft_collab::short(node)
}
