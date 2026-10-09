//! The shared collaboration seam for the Craft apps (spike).
//!
//! One mechanism, adopted by every app: a command or a cursor travels as a
//! [`Message`] between peers, a [`Transport`] carries it (the mesh
//! implementation lives in `macula-craft-collab`), paragraph text converges
//! through [`TextMerge`], and [`Presence`] carries remote cursors. The app
//! side of the seam is [`CollabHost`] (origin-aware dispatch) and
//! [`DocAdapter`] (stable paragraph ids <-> text, snapshots), implemented
//! once per app; wordcraft is first.

pub mod grant;
pub mod host;
pub mod mem;
pub mod message;
pub mod order;
pub mod presence;
pub mod text;
pub mod transport;

pub use grant::{Access, Admission, GRANT_VERSION, Grant, GrantVerifier, Role, SignedGrant};
pub use host::{CollabHost, DocAdapter, Origin};
pub use mem::MemoryTransport;
pub use message::{Kind, Message};
pub use order::OrderBuffer;
pub use presence::{Peer, Presence, color_for};
pub use text::TextMerge;
pub use transport::Transport;
