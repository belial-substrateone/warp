// On Windows, we don't want to display a console window when the application is running in release
// builds. See https://doc.rust-lang.org/reference/runtime.html#the-windows_subsystem-attribute.
#![cfg_attr(feature = "release_bundle", windows_subsystem = "windows")]

use anyhow::Result;
use warp_core::AppId;
use warp_core::channel::{Channel, ChannelConfig, ChannelState, OzConfig, WarpServerConfig};
use warp_core::features::FeatureFlag;

/// Local address standing in for the Warp server. Nothing listens here by default, so every
/// server call is refused immediately; a local backend can bind it later.
const LOCAL_SERVER: &str = "http://127.0.0.1:8080";
const LOCAL_WS: &str = "ws://127.0.0.1:8080/graphql/v2";

// AnonWarp: Warp with every Warp-hosted service stubbed out. Telemetry, crash reporting,
// autoupdate and static MCP OAuth config are off, server URLs point at localhost, and the
// HTTP egress guard blocks Warp-operated hosts as a backstop.
fn main() -> Result<()> {
    http_client::egress::set_block_warp_hosts(true);
    // Catch-all: nothing may reach the stub server address until a local backend is wired in.
    http_client::egress::set_blocked_authorities(&["127.0.0.1:8080"]);
    warp_core::channel::set_stub_server(true);

    let state = ChannelState::new(
        Channel::Oss,
        ChannelConfig {
            app_id: AppId::new("dev", "anonwarp", "AnonWarp"),
            logfile_name: "anonwarp.log".into(),
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
    )
    // Go straight to the terminal instead of the login screen.
    .with_additional_features(&[FeatureFlag::SkipFirebaseAnonymousUser]);
    ChannelState::set(state);

    warp::run()
}

// If we're not using an external plist, embed the following as the Info.plist.
#[cfg(all(not(feature = "extern_plist"), target_os = "macos"))]
embed_plist::embed_info_plist_bytes!(r#"
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>English</string>
    <key>CFBundleDisplayName</key>
    <string>AnonWarp</string>
    <key>CFBundleExecutable</key>
    <string>anonwarp</string>
    <key>CFBundleIdentifier</key>
    <string>dev.anonwarp.AnonWarp</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>AnonWarp</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.developer-tools</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>UIDesignRequiresCompatibility</key>
    <true/>
    <key>CFBundleURLTypes</key>
    <array><dict><key>CFBundleURLName</key><string>Custom App</string><key>CFBundleURLSchemes</key><array><string>anonwarp</string></array></dict></array>
    <key>NSHumanReadableCopyright</key>
    <string>© 2026, Denver Technologies, Inc</string>
    </dict>
    </plist>
"#.as_bytes());
