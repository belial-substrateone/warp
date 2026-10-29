//! Pure-logic building blocks for AnonWarp remote access.
//!
//! This crate deliberately has no WarpUI, axum or filesystem-layout knowledge.
//! It contains everything that can be tested without a phone or a socket:
//! the `anonwarp-remote` v1 wire types, the pairing state machine, the
//! device-token registry, QR payload encoding, the private-address filter,
//! self-signed TLS identity generation and Host/Origin validation. The server
//! and the app glue code are layered on top of these types.
//!
//! See `REMOTE_CONTROL.md` sections 6 and 7 for the security design and the
//! protocol specification these modules implement.
pub mod cert;
pub mod clock;
pub mod host;
pub mod netfilter;
pub mod origin;
pub mod pairing;
pub mod protocol;
pub mod qr;
pub mod ratelimit;
#[cfg(feature = "server")]
pub mod server;
pub mod tokens;

#[cfg(any(test, feature = "test-util"))]
pub use clock::ManualClock;
pub use clock::{Clock, SystemClock};
#[cfg(any(test, feature = "test-util"))]
pub use host::MockTerminalHost;
pub use host::{HostError, PaneId, PaneStream, TerminalHost};
