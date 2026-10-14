//! A collaboration seam for document apps, built for the Craft apps.
//!
//! One mechanism, adopted by every app: a command or a cursor travels as a
//! [`Message`] between peers, a [`Transport`] carries it (the mesh
//! implementation lives in `macula-craft-collab`), paragraph text converges
//! through [`TextMerge`], and [`Presence`] carries remote cursors. The app
//! side of the seam is [`CollabHost`] (origin-aware dispatch) and
//! [`DocAdapter`] (stable paragraph ids <-> text, snapshots), implemented
//! once per app; wordcraft is first. [`CollabSession`] runs the protocol of
//! one shared document (join, grants, invites, contacts, snapshots) and hands
//! the app what to apply.

pub mod contacts;
pub mod grant;
pub mod host;
pub mod ids;
pub mod invite;
pub mod mem;
pub mod message;
pub mod order;
pub mod presence;
pub mod session;
pub mod text;
pub mod transport;

pub use contacts::{Contact, Contacts};
pub use grant::{
    Access, Admission, GRANT_VERSION, Grant, GrantIssuer, GrantVerifier, MembershipVerifier, Revocation, Role, SignedGrant, SignedRevocation,
    mint_nonce,
};
pub use host::{CollabHost, DocAdapter, Origin};
pub use ids::{author_id, author_tag};
pub use invite::{INVITE_VERSION, Invite};
pub use mem::MemoryTransport;
pub use message::{Kind, Message};
pub use order::OrderBuffer;
pub use presence::{Peer, Presence, color_for};
pub use session::{CollabSession, Inbound, ShareContext, TextStore, now_ms, short};
pub use text::{BodyParagraph, TextMerge};
pub use transport::Transport;
