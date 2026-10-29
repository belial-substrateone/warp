//! Phone remote control ("remote access") for AnonWarp.
//!
//! The pure logic (pairing, device tokens, QR payload, cert generation, protocol types) lives in
//! `crates/remote_access`. This module is the app side:
//!
//! - [`service`]: the `RemoteAccessService` singleton model, the single API the UI talks to.
//! - [`terminal_host`]: the app's `TerminalHost` implementation (PTY mirror + input injection).
//!
//! See `REMOTE_CONTROL.md` at the AnonWarp repo root for the design.
pub mod api;
pub mod service;
pub mod terminal_host;
pub mod ui;

pub use api::{ActiveSession, PairingQr, RemoteAccessEvent};
pub use service::{HostFactory, RemoteAccessService};
pub use terminal_host::{AppTerminalHost, PaneBackend, PaneRuntime, PaneSource};
