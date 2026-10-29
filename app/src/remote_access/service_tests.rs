use ::remote_access::netfilter::{NetPolicy, is_allowed_addr};
use ::remote_access::qr::QrPayload;

use super::*;

#[test]
fn identity_round_trips_with_owner_only_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join(IDENTITY_FILE);
    assert!(Identity::load(&path).unwrap().is_none());
    let identity = Identity::generate(None).unwrap();
    identity.save(&path).unwrap();
    let loaded = Identity::load(&path).unwrap().unwrap();
    assert_eq!(loaded.instance_id, identity.instance_id);
    assert_eq!(loaded.cert.fingerprint(), identity.cert.fingerprint());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let rotated = Identity::generate(Some(identity.instance_id.clone())).unwrap();
    assert_eq!(rotated.instance_id, identity.instance_id);
    assert_ne!(rotated.cert.fingerprint(), identity.cert.fingerprint());
}

#[test]
fn corrupt_identity_is_an_error_not_silently_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(IDENTITY_FILE);
    std::fs::write(&path, b"{not json").unwrap();
    assert!(Identity::load(&path).is_err());
}

#[test]
fn default_port_is_in_the_documented_range() {
    if std::env::var(PORT_ENV).is_err() {
        assert!((PORT_BASE..=PORT_BASE + 5).contains(&default_port()));
    }
}

#[test]
fn enable_pair_rotate_disable_cycle() {
    warpui::App::test((), |mut app| async move {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().to_path_buf();
        let service = app.add_singleton_model(move |ctx| {
            let mut s = RemoteAccessService::with_state_dir(state, ctx);
            s.set_port(0);
            s
        });
        let on = |app: &mut warpui::App, enabled| {
            service.update(app, |s, ctx| s.set_enabled(enabled, ctx));
        };

        assert!(service.read(&app, |s, _| !s.is_enabled()));
        assert!(service.read(&app, |s, _| s.listen_addrs().is_empty()));
        assert!(service.read(&app, |s, _| s.fingerprint_display().is_none()));
        assert!(
            service
                .update(&mut app, |s, ctx| s.arm_pairing(ctx))
                .is_err()
        );

        on(&mut app, true);
        let (enabled, error) = service.read(&app, |s, _| {
            (s.is_enabled(), s.last_error().map(str::to_owned))
        });
        if !enabled {
            // A machine without any private LAN/Tailscale address cannot listen at all.
            assert!(
                error.unwrap().contains("no private"),
                "unexpected start failure"
            );
            return;
        }

        let policy = NetPolicy::default();
        let addrs = service.read(&app, |s, _| s.listen_addrs());
        assert!(!addrs.is_empty());
        for a in &addrs {
            assert!(!a.ip().is_unspecified() && !a.ip().is_loopback(), "{a}");
            assert!(
                is_allowed_addr(a.ip(), &policy),
                "{a} is not a private address"
            );
        }

        let fp_before = service.read(&app, |s, _| s.fingerprint_display()).unwrap();
        let qr = service
            .update(&mut app, |s, ctx| s.arm_pairing(ctx))
            .expect("arming");
        let payload = QrPayload::parse(&qr.url).expect("the QR URL parses");
        assert_eq!(qr.fingerprint_display, fp_before);
        assert_eq!(payload.hosts.len(), addrs.len());
        assert!(QrPayload::parse(&qr.app_url).is_ok());
        for h in &payload.hosts {
            assert!(addrs.contains(h));
        }
        assert!(
            dir.path().join(IDENTITY_FILE).exists(),
            "the certificate is persisted on first enable"
        );

        service.update(&mut app, |s, ctx| s.kill_all_sessions(ctx));
        assert!(service.read(&app, |s, _| s.active_sessions().is_empty()));
        assert!(service.read(&app, |s, _| s.pending_approvals().is_empty()));

        service.update(&mut app, |s, ctx| s.rotate_certificate(ctx));
        let fp_after = service.read(&app, |s, _| s.fingerprint_display()).unwrap();
        assert_ne!(fp_before, fp_after, "rotation changes the fingerprint");
        assert!(
            service.read(&app, |s, _| s.is_enabled()),
            "server restarted"
        );
        assert!(service.read(&app, |s, _| s.devices().is_empty()));

        on(&mut app, false);
        assert!(service.read(&app, |s, _| !s.is_enabled()));
        assert!(service.read(&app, |s, _| s.listen_addrs().is_empty()));
        // The certificate survives disabling so the fingerprint stays stable.
        assert_eq!(
            service.read(&app, |s, _| s.fingerprint_display()).unwrap(),
            fp_after
        );
    });
}
