//! Offline stand-ins for every Warp server client trait.
//!
//! Selected at startup by [`warp_core::channel::stub_server_enabled`]. Nothing here touches the
//! network. Each method returns the most benign valid value (empty list, `None`, default struct)
//! or a clear "unsupported offline" error for operations that cannot meaningfully succeed.
//! Every call is logged at debug level under the `anonwarp::stub` target so a run shows exactly
//! which server features the app asked for; later work replaces individual methods with real
//! local implementations.

pub mod ai;
pub mod auth;
pub mod misc;
pub mod objects;
pub mod team;
pub mod workspace;

/// Error returned by stubbed operations that have no sensible offline result.
#[derive(Debug, thiserror::Error)]
#[error("{0} is not available in AnonWarp's offline mode")]
pub struct StubUnsupported(pub &'static str);

/// Logs a stubbed call. Use as the first statement of every stub method.
macro_rules! stub_call {
    ($name:expr) => {
        log::debug!(target: "anonwarp::stub", "stub call: {}", $name)
    };
}
pub(crate) use stub_call;

/// `Err(anyhow::Error)` carrying [`StubUnsupported`] for the named operation.
macro_rules! unsupported {
    ($name:expr) => {
        Err(::anyhow::Error::new($crate::server::stub::StubUnsupported($name)))
    };
}
pub(crate) use unsupported;
