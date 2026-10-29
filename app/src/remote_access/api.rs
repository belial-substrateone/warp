//! Plain data types exchanged between [`super::RemoteAccessService`] and its UIs (GUI settings
//! page, TUI view). Keep these free of WarpUI types so both front-ends can use them.
use std::net::IpAddr;

use ::remote_access::pairing::PairingId;

/// What the PC shows for a freshly armed pairing: render `url` as a QR code.
#[derive(Clone, Debug)]
pub struct PairingQr {
    /// The `https://host:port/pair#v=1&s=...&fp=...` URL to encode in the QR code.
    pub url: String,
    /// The `anonwarp://pair?...` form for the native Android client (all hosts).
    pub app_url: String,
    /// Unix seconds when the one-time secret expires.
    pub expires_at: i64,
    /// Certificate fingerprint formatted `AB:CD:..` for manual comparison.
    pub fingerprint_display: String,
    /// `ip:port` strings the server is listening on.
    pub hosts: Vec<String>,
}

/// A phone currently connected over the remote-access WebSocket.
#[derive(Clone, Debug)]
pub struct ActiveSession {
    pub device_id: String,
    pub label: String,
    pub ip: Option<IpAddr>,
    /// Unix seconds when the session started.
    pub since: i64,
}

/// Events emitted by the service so views can refresh.
#[derive(Clone, Debug)]
pub enum RemoteAccessEvent {
    /// Enabled/disabled, listening addresses, or armed state changed.
    StateChanged,
    /// A phone submitted a valid pairing secret and waits for approval on the PC.
    ApprovalRequested(PairingId),
    /// Paired devices were added, revoked or renamed.
    DevicesChanged,
    /// A phone connected or disconnected.
    SessionsChanged,
}
