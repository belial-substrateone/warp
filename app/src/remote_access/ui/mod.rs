//! GUI pieces for phone remote access: the pairing/approval overlay and pure view-model helpers.
//! The Settings page lives in `settings_view/remote_access_page.rs`.
pub mod overlay;
pub mod view_model;

pub use overlay::{RemoteAccessOverlay, RemoteAccessOverlayEvent, init};
