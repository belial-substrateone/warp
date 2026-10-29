//! `RemoteAccessService` dispatch: the real implementation is native-only (tokio runtime, TLS
//! server); wasm builds get an inert stand-in with the same public API.
#[cfg(not(target_family = "wasm"))]
pub use super::service_native::*;

#[cfg(target_family = "wasm")]
pub use self::wasm_stub::*;

#[cfg(target_family = "wasm")]
mod wasm_stub {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use ::remote_access::TerminalHost;
    use ::remote_access::pairing::{PairingId, PendingApproval};
    use ::remote_access::tokens::DeviceRecord;
    use warpui::{Entity, ModelContext, SingletonEntity};

    use super::super::api::{ActiveSession, PairingQr, RemoteAccessEvent};

    /// Remote access is a native-desktop feature; this stand-in is never enabled.
    pub fn default_port() -> u16 {
        9477
    }

    pub struct RemoteAccessService {
        port: u16,
    }

    pub type HostFactory =
        Box<dyn Fn(&mut ModelContext<RemoteAccessService>) -> Arc<dyn TerminalHost>>;

    impl RemoteAccessService {
        pub fn new(_ctx: &mut ModelContext<Self>) -> Self {
            Self {
                port: default_port(),
            }
        }

        pub fn set_host_factory(&mut self, _factory: HostFactory) {}

        pub fn is_enabled(&self) -> bool {
            false
        }

        pub fn last_error(&self) -> Option<&str> {
            None
        }

        pub fn port(&self) -> u16 {
            self.port
        }

        pub fn set_port(&mut self, port: u16) {
            self.port = port;
        }

        pub fn set_enabled(&mut self, _enabled: bool, _ctx: &mut ModelContext<Self>) {}

        pub fn listen_addrs(&self) -> Vec<SocketAddr> {
            Vec::new()
        }

        pub fn arm_pairing(&mut self, _ctx: &mut ModelContext<Self>) -> anyhow::Result<PairingQr> {
            Err(anyhow::anyhow!(
                "remote access is not supported on this platform"
            ))
        }

        pub fn disarm_pairing(&mut self, _ctx: &mut ModelContext<Self>) {}

        pub fn pending_approvals(&self) -> Vec<PendingApproval> {
            Vec::new()
        }

        pub fn resolve_approval(
            &mut self,
            _id: &PairingId,
            _approve: bool,
            _ctx: &mut ModelContext<Self>,
        ) {
        }

        pub fn devices(&self) -> Vec<DeviceRecord> {
            Vec::new()
        }

        pub fn revoke_device(&mut self, _device_id: &str, _ctx: &mut ModelContext<Self>) {}

        pub fn active_sessions(&self) -> Vec<ActiveSession> {
            Vec::new()
        }

        pub fn kill_all_sessions(&mut self, _ctx: &mut ModelContext<Self>) {}

        pub fn rotate_certificate(&mut self, _ctx: &mut ModelContext<Self>) {}

        pub fn fingerprint_display(&self) -> Option<String> {
            None
        }
    }

    impl Entity for RemoteAccessService {
        type Event = RemoteAccessEvent;
    }

    impl SingletonEntity for RemoteAccessService {}
}
