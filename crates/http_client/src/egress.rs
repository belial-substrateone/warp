//! Egress guard for outbound HTTP. When enabled, requests to Warp-operated and
//! Warp-telemetry hosts are refused before they reach the network.
//!
//! The channel binary opts in once at startup via [`set_block_warp_hosts`]. This is a
//! defense-in-depth backstop under the stubbed `ServerApi`: anything that still tries to
//! reach a blocked host fails fast and is logged instead of leaving the machine.

use std::sync::atomic::{AtomicBool, Ordering};

static BLOCK_WARP_HOSTS: AtomicBool = AtomicBool::new(false);

/// Host suffixes that identify Warp-operated services and the third-party services the
/// client uses on Warp's behalf (auth, telemetry, crash reporting).
const BLOCKED_HOST_SUFFIXES: &[&str] = &[
    "warp.dev",
    "warpdotdev.com",
    "rudderstack.com",
    "sentry.io",
    "identitytoolkit.googleapis.com",
    "securetoken.googleapis.com",
    "sts.googleapis.com",
    "iamcredentials.googleapis.com",
    "firebaseio.com",
    "firebaseapp.com",
];

pub fn set_block_warp_hosts(block: bool) {
    BLOCK_WARP_HOSTS.store(block, Ordering::Relaxed);
}

/// Returns true if the guard is on and `url` targets a blocked host.
pub fn is_blocked(url: &reqwest::Url) -> bool {
    if !BLOCK_WARP_HOSTS.load(Ordering::Relaxed) {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    BLOCKED_HOST_SUFFIXES
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

/// Builds a `reqwest::Error` for a blocked request. `reqwest::Error` has no public
/// constructor, so this produces a builder-kind error by building a request from an
/// invalid URL.
pub fn blocked_error(client: &reqwest::Client, url: &reqwest::Url) -> reqwest::Error {
    log::warn!("egress guard: blocked request to {url}");
    client
        .get("http://")
        .build()
        .expect_err("an empty-host URL must fail to build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_exact_and_subdomains_only() {
        set_block_warp_hosts(true);
        let blocked = |s: &str| is_blocked(&reqwest::Url::parse(s).unwrap());
        assert!(blocked("https://app.warp.dev/graphql/v2"));
        assert!(blocked("https://warp.dev/"));
        assert!(blocked("https://o123.ingest.sentry.io/x"));
        assert!(!blocked("https://notwarp.dev/"));
        assert!(!blocked("https://api.github.com/"));
        set_block_warp_hosts(false);
        assert!(!blocked("https://app.warp.dev/"));
    }
}
