use super::*;

#[test]
fn qr_half_blocks_match_module_grid() {
    let data = "HELLO";
    let code = QrCode::new(data.as_bytes()).unwrap();
    let width = code.width();
    let colors = code.to_colors();
    let lines = qr_half_block_lines(data).unwrap();

    let total = width + 2 * QUIET_ZONE;
    assert_eq!(lines.len(), total.div_ceil(2));
    for line in &lines {
        assert_eq!(line.chars().count(), total);
    }
    // Quiet zone: first row(s) and edge columns are blank.
    assert!(lines[0].chars().all(|c| c == ' '));
    for line in &lines {
        assert!(line.chars().take(QUIET_ZONE).all(|c| c == ' '));
    }
    // Every module round-trips through its half-block glyph.
    let dark = |x: usize, y: usize| colors[y * width + x] == QrColor::Dark;
    for y in 0..width {
        let row = QUIET_ZONE + y;
        let chars: Vec<char> = lines[row / 2].chars().collect();
        for x in 0..width {
            let glyph = chars[QUIET_ZONE + x];
            let is_top = row % 2 == 0;
            let expected = if is_top {
                matches!(glyph, '▀' | '█')
            } else {
                matches!(glyph, '▄' | '█')
            };
            assert_eq!(expected, dark(x, y), "module ({x},{y}) glyph {glyph:?}");
        }
    }
    // Finder pattern: top-left module is dark, so the first data row starts with a block glyph.
    assert_eq!(lines[1].chars().nth(QUIET_ZONE), Some('█'));
}

#[test]
fn qr_uses_only_half_block_glyphs() {
    let lines = qr_half_block_lines("https://192.168.1.2:8443/pair#v=1").unwrap();
    assert!(
        lines
            .iter()
            .all(|l| l.chars().all(|c| matches!(c, ' ' | '▀' | '▄' | '█')))
    );
}

#[test]
fn countdown_formatting() {
    assert_eq!(pairing_expiry_text(272), "Expires in 4:32");
    assert_eq!(pairing_expiry_text(65), "Expires in 1:05");
    assert_eq!(pairing_expiry_text(5), "Expires in 0:05");
    assert!(pairing_expiry_text(0).starts_with("Code expired"));
    assert!(pairing_expiry_text(-3).starts_with("Code expired"));
}

#[test]
fn approval_prompt_text() {
    assert_eq!(
        approval_prompt_lines("Pixel 8", "android", Some("192.168.1.20"), Some("AB:CD")),
        vec![
            "A phone wants to pair",
            "Name:        Pixel 8",
            "Platform:    android",
            "IP address:  192.168.1.20",
            "Fingerprint: AB:CD",
            "Only approve if this is your phone and the fingerprint matches.",
        ]
    );
    let unknown = approval_prompt_lines("x", "ios", None, None);
    assert!(unknown.contains(&"IP address:  unknown".to_owned()));
    assert!(!unknown.iter().any(|l| l.starts_with("Fingerprint")));
}

#[test]
fn device_row_text_marks_selection() {
    let device = remote_access::tokens::DeviceRecord {
        id: remote_access::tokens::DeviceId("d1".into()),
        label: "Pixel 8".into(),
        token_sha256: [0; 32],
        created: 0,
        last_seen: 1000,
        last_ip: Some("192.168.1.20".parse().unwrap()),
        platform: "android".into(),
        revoked: false,
    };
    assert_eq!(
        device_row_text(&device, 1000 + 125, true),
        "> Pixel 8 (android) 192.168.1.20 seen 2m ago"
    );
    assert_eq!(
        device_row_text(&device, 1000, false),
        "  Pixel 8 (android) 192.168.1.20 seen just now"
    );
}

#[test]
fn status_indicator_and_url_chunks() {
    assert_eq!(status_indicator_text(0), None);
    assert_eq!(status_indicator_text(1).unwrap(), "📱 phone connected");
    assert_eq!(status_indicator_text(3).unwrap(), "📱 3 phones connected");
    assert_eq!(wrap_chunks("abcdef", 4), vec!["abcd", "ef"]);
}
