//! Pure helpers (no WarpUI types) that turn service data into display strings and rows.
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use ::remote_access::tokens::DeviceRecord;

use crate::remote_access::api::ActiveSession;

/// How long an unanswered approval prompt stays alive on the service side
/// (`PairingConfig::default().approval_timeout_secs`). Used only for the countdown display; the
/// service stays the authority and the prompt also closes when it drops the request.
pub const APPROVAL_TIMEOUT_SECS: i64 = 120;

/// Approve stays disabled for this long after the prompt appears so a click that was already in
/// flight (for example on a Disconnect button) cannot approve a phone.
pub const APPROVE_ARM_DELAY_MS: u128 = 1500;

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `M:SS`, clamped at `0:00`.
pub fn format_countdown(remaining_secs: i64) -> String {
    let secs = remaining_secs.max(0);
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// Seconds left until `expires_at` (may be negative).
pub fn seconds_remaining(expires_at: i64, now: i64) -> i64 {
    expires_at - now
}

/// Human "last seen" text relative to `now`.
pub fn format_last_seen(last_seen: i64, now: i64) -> String {
    if last_seen <= 0 {
        return "never".to_owned();
    }
    let delta = (now - last_seen).max(0);
    match delta {
        0..=59 => "just now".to_owned(),
        60..=3599 => format!("{} min ago", delta / 60),
        3600..=86399 => format!("{} h ago", delta / 3600),
        _ => format!("{} d ago", delta / 86400),
    }
}

/// Splits `AB:CD:..` into lines of `per_line` bytes so a SHA-256 fingerprint (32 bytes) fits a
/// dialog. Input that is not colon separated is returned as a single line.
pub fn fingerprint_lines(fingerprint: &str, per_line: usize) -> Vec<String> {
    let groups: Vec<&str> = fingerprint.split(':').collect();
    if groups.len() <= 1 || per_line == 0 {
        return vec![fingerprint.to_owned()];
    }
    groups.chunks(per_line).map(|c| c.join(":")).collect()
}

/// One row of the paired-devices list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRow {
    pub id: String,
    pub label: String,
    pub platform: String,
    pub last_seen: String,
    pub last_ip: String,
}

pub fn device_rows(devices: &[DeviceRecord], now: i64) -> Vec<DeviceRow> {
    devices
        .iter()
        .filter(|d| !d.revoked)
        .map(|d| DeviceRow {
            id: d.id.0.clone(),
            label: if d.label.trim().is_empty() {
                "Unnamed device".to_owned()
            } else {
                d.label.clone()
            },
            platform: if d.platform.is_empty() {
                "unknown".to_owned()
            } else {
                d.platform.clone()
            },
            last_seen: format_last_seen(d.last_seen, now),
            last_ip: format_ip(d.last_ip),
        })
        .collect()
}

pub fn format_ip(ip: Option<IpAddr>) -> String {
    ip.map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown IP".to_owned())
}

/// One row of the active-sessions list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub label: String,
    pub ip: String,
    pub duration: String,
}

pub fn session_rows(sessions: &[ActiveSession], now: i64) -> Vec<SessionRow> {
    sessions
        .iter()
        .map(|s| SessionRow {
            label: s.label.clone(),
            ip: format_ip(s.ip),
            duration: format_duration(now - s.since),
        })
        .collect()
}

pub fn format_duration(secs: i64) -> String {
    let secs = secs.max(0);
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{} min", secs / 60),
        _ => format!("{} h {} min", secs / 3600, (secs % 3600) / 60),
    }
}

/// Text for the always-visible workspace banner. `None` when no phone is connected.
pub fn session_banner_text(sessions: &[ActiveSession]) -> Option<String> {
    match sessions {
        [] => None,
        [one] => Some(format!(
            "Remote: {} ({}) can view and control your terminals.",
            one.label,
            format_ip(one.ip)
        )),
        many => Some(format!(
            "Remote: {} phones can view and control your terminals.",
            many.len()
        )),
    }
}

#[cfg(test)]
#[path = "view_model_tests.rs"]
mod tests;
