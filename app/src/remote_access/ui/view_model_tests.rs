use ::remote_access::tokens::{DeviceId, DeviceRecord};

use super::*;

fn session(label: &str, ip: Option<&str>) -> ActiveSession {
    ActiveSession {
        device_id: "d".into(),
        label: label.into(),
        ip: ip.map(|i| i.parse().unwrap()),
        since: 100,
    }
}

fn device(id: &str, label: &str, last_seen: i64, revoked: bool) -> DeviceRecord {
    DeviceRecord {
        id: DeviceId(id.into()),
        label: label.into(),
        token_sha256: [0; 32],
        created: 0,
        last_seen,
        last_ip: Some("192.168.1.9".parse().unwrap()),
        platform: "android".into(),
        revoked,
    }
}

#[test]
fn countdown_formats_and_clamps() {
    assert_eq!(format_countdown(120), "2:00");
    assert_eq!(format_countdown(65), "1:05");
    assert_eq!(format_countdown(9), "0:09");
    assert_eq!(format_countdown(-5), "0:00");
}

#[test]
fn seconds_remaining_can_go_negative() {
    assert_eq!(seconds_remaining(150, 100), 50);
    assert_eq!(seconds_remaining(100, 150), -50);
}

#[test]
fn last_seen_buckets() {
    assert_eq!(format_last_seen(0, 1000), "never");
    assert_eq!(format_last_seen(990, 1000), "just now");
    assert_eq!(format_last_seen(1000 - 300, 1000), "5 min ago");
    assert_eq!(format_last_seen(100_000 - 7200, 100_000), "2 h ago");
    assert_eq!(format_last_seen(1_000_000 - 3 * 86400, 1_000_000), "3 d ago");
}

#[test]
fn fingerprint_splits_into_lines() {
    let fp = (0..32).map(|i| format!("{i:02X}")).collect::<Vec<_>>().join(":");
    let lines = fingerprint_lines(&fp, 16);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("00:01"));
    assert!(lines[1].starts_with("10:11"));
    assert_eq!(fingerprint_lines("abcd", 16), vec!["abcd".to_owned()]);
}

#[test]
fn device_rows_skip_revoked_and_fill_blanks() {
    let rows = device_rows(
        &[device("a", "Pixel 8", 990, false), device("b", "Old", 5, true), device("c", " ", 0, false)],
        1000,
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].label, "Pixel 8");
    assert_eq!(rows[0].last_seen, "just now");
    assert_eq!(rows[0].last_ip, "192.168.1.9");
    assert_eq!(rows[1].label, "Unnamed device");
    assert_eq!(rows[1].last_seen, "never");
}

#[test]
fn session_rows_and_banner() {
    assert_eq!(session_banner_text(&[]), None);
    let one = session_banner_text(&[session("Pixel 8", Some("10.0.0.2"))]).unwrap();
    assert!(one.contains("Pixel 8") && one.contains("10.0.0.2"));
    let two = session_banner_text(&[session("a", None), session("b", None)]).unwrap();
    assert!(two.contains("2 phones"));
    let rows = session_rows(&[session("a", None)], 190);
    assert_eq!(rows[0].ip, "unknown IP");
    assert_eq!(rows[0].duration, "1 min");
}
