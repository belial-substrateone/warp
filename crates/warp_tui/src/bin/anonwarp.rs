//! AnonWarp `warp-tui` binary: the OSS channel with every Warp-hosted service stubbed out
//! (mirrors `app/src/bin/anonwarp.rs`). Server URLs point at localhost, telemetry, crash
//! reporting and autoupdate are off, the offline server stubs are selected, and the HTTP egress
//! guard blocks Warp-operated hosts.

use anyhow::Result;
use warp_core::AppId;
use warp_core::channel::{Channel, ChannelConfig, ChannelState, OzConfig, WarpServerConfig};

const LOCAL_SERVER: &str = "http://127.0.0.1:8080";
const LOCAL_WS: &str = "ws://127.0.0.1:8080/graphql/v2";

fn main() -> Result<()> {
    http_client::egress::set_block_warp_hosts(true);
    // Catch-all: nothing may reach the stub server address until a local backend is wired in.
    http_client::egress::set_blocked_authorities(&["127.0.0.1:8080"]);
    warp_core::channel::set_stub_server(true);

    let mut state = ChannelState::new(
        Channel::Oss,
        ChannelConfig {
            app_id: AppId::new("dev", "anonwarp", "AnonWarpTui"),
            logfile_name: "anonwarp-tui.log".into(),
            server_config: WarpServerConfig {
                server_root_url: LOCAL_SERVER.into(),
                rtc_server_url: LOCAL_WS.into(),
                session_sharing_server_url: None,
                firebase_auth_api_key: "".into(),
                iap_config: None,
            },
            oz_config: OzConfig {
                oz_root_url: LOCAL_SERVER.into(),
                workload_audience_url: None,
            },
            telemetry_config: None,
            crash_reporting_config: None,
            autoupdate_config: None,
            mcp_static_config: None,
        },
    );
    if cfg!(debug_assertions) {
        state = state.with_additional_features(warp_core::features::DEBUG_FLAGS);
    }
    // Phone remote access (`/remote-access`); the service itself stays off until enabled.
    state = state.with_additional_features(&[warp_core::features::FeatureFlag::RemoteAccess]);
    ChannelState::set(state);

    warp_tui::run()
}
