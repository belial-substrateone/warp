//! Private-address policy: which local addresses we may bind and which peers
//! we accept (REMOTE_CONTROL.md 6.1).
//!
//! Accepted: RFC1918, Tailscale CGNAT `100.64.0.0/10`, IPv6 ULA `fc00::/7`
//! (including Tailscale's `fd7a:115c:a1e0::/48`). Link-local, public,
//! unspecified and multicast addresses are always rejected. Loopback is only
//! accepted when the policy explicitly allows it (tests / dev host).
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What a bound address is, for display and subnet policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrKind {
    /// RFC1918 or IPv6 ULA (non-Tailscale).
    Lan,
    /// `100.64.0.0/10` or `fd7a:115c:a1e0::/48`.
    Tailscale,
    /// Only produced when `NetPolicy::allow_loopback` is set.
    Loopback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetPolicy {
    pub allow_lan: bool,
    pub allow_tailscale: bool,
    /// IPv6 unique-local addresses (`fc00::/7`, non-Tailscale).
    pub allow_ula: bool,
    /// Tests and the dev host only.
    pub allow_loopback: bool,
    /// If non-empty, only interfaces whose name starts with one of these
    /// prefixes are enumerated (e.g. `["utun", "tailscale"]`).
    pub iface_prefixes: Vec<String>,
}

impl Default for NetPolicy {
    fn default() -> Self {
        Self {
            allow_lan: true,
            allow_tailscale: true,
            allow_ula: true,
            allow_loopback: false,
            iface_prefixes: Vec::new(),
        }
    }
}

impl NetPolicy {
    /// Default policy plus loopback, for tests and the dev host.
    pub fn with_loopback() -> Self {
        Self {
            allow_loopback: true,
            ..Self::default()
        }
    }
}

/// A local address the server may listen on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAddr {
    pub ip: IpAddr,
    pub iface: String,
    pub kind: AddrKind,
    /// Prefix length of the interface's subnet.
    pub prefix_len: u8,
}

/// Unwraps `::ffff:a.b.c.d` to the embedded IPv4 address.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn is_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xc0) == 0x40
}

fn is_tailscale_v6(v6: Ipv6Addr) -> bool {
    v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0]
}

fn is_ula(v6: Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

fn is_rfc1918(v4: Ipv4Addr) -> bool {
    v4.is_private()
}

/// Classifies `ip` under `policy`; `None` means not acceptable.
pub fn classify(ip: IpAddr, policy: &NetPolicy) -> Option<AddrKind> {
    match unmap(ip) {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                policy.allow_loopback.then_some(AddrKind::Loopback)
            } else if is_rfc1918(v4) {
                policy.allow_lan.then_some(AddrKind::Lan)
            } else if is_cgnat(v4) {
                policy.allow_tailscale.then_some(AddrKind::Tailscale)
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                policy.allow_loopback.then_some(AddrKind::Loopback)
            } else if is_tailscale_v6(v6) {
                policy.allow_tailscale.then_some(AddrKind::Tailscale)
            } else if is_ula(v6) {
                policy.allow_ula.then_some(AddrKind::Lan)
            } else {
                None
            }
        }
    }
}

/// True if `ip` (after unmapping `::ffff:`) is in an accepted range.
pub fn is_allowed_addr(ip: IpAddr, policy: &NetPolicy) -> bool {
    classify(ip, policy).is_some()
}

fn masked_eq(a: IpAddr, b: IpAddr, prefix: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let prefix = u32::from(prefix.min(32));
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let prefix = u32::from(prefix.min(128));
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

/// Whether `peer` is on the same network as the local address it connected to.
///
/// Tailscale addresses accept any peer inside the Tailscale range (the tailnet
/// is one flat overlay); LAN addresses require the interface's own subnet.
pub fn same_subnet(local: &BoundAddr, peer: IpAddr) -> bool {
    let peer = unmap(peer);
    match local.kind {
        AddrKind::Tailscale => match (local.ip, peer) {
            (IpAddr::V4(_), IpAddr::V4(p)) => is_cgnat(p),
            (IpAddr::V6(_), IpAddr::V6(p)) => is_tailscale_v6(p),
            _ => false,
        },
        AddrKind::Loopback => peer.is_loopback(),
        AddrKind::Lan => masked_eq(local.ip, peer, local.prefix_len),
    }
}

/// Peer admission check done at TCP accept time, before TLS.
pub fn peer_allowed(local: &BoundAddr, peer: IpAddr, policy: &NetPolicy) -> bool {
    is_allowed_addr(peer, policy) && same_subnet(local, peer)
}

/// Builds candidates from raw `(iface, ip, prefix_len)` triples. Pure, so the
/// policy is testable without touching real interfaces.
pub fn candidates_from<I>(ifaces: I, policy: &NetPolicy) -> Vec<BoundAddr>
where
    I: IntoIterator<Item = (String, IpAddr, u8)>,
{
    let mut out: Vec<BoundAddr> = Vec::new();
    for (iface, ip, prefix_len) in ifaces {
        if !policy.iface_prefixes.is_empty()
            && !policy
                .iface_prefixes
                .iter()
                .any(|p| iface.starts_with(p.as_str()))
        {
            continue;
        }
        // Link-local scoped IPv6 and v4-mapped addresses are never bind targets.
        if matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()) {
            continue;
        }
        let Some(kind) = classify(ip, policy) else {
            continue;
        };
        if out.iter().any(|b| b.ip == ip) {
            continue;
        }
        out.push(BoundAddr {
            ip,
            iface,
            kind,
            prefix_len,
        });
    }
    out
}

/// Enumerates local interface addresses acceptable under `policy`.
/// Enumeration failure yields an empty list (nothing is bound).
#[cfg(not(target_family = "wasm"))]
pub fn candidate_bind_addrs(policy: &NetPolicy) -> Vec<BoundAddr> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    candidates_from(
        ifaces.into_iter().map(|i| {
            let (ip, prefix) = match i.addr {
                if_addrs::IfAddr::V4(a) => (IpAddr::V4(a.ip), a.prefixlen),
                if_addrs::IfAddr::V6(a) => (IpAddr::V6(a.ip), a.prefixlen),
            };
            (i.name, ip, prefix)
        }),
        policy,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allowed_table() {
        let p = NetPolicy::default();
        let yes = [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.20",
            "100.64.0.1",
            "100.127.255.254",
            "fd7a:115c:a1e0::1",
            "fd7a:115c:a1e0:ab12::7",
            "fd00::1",
            "fc00::1",
            "fdff::1",
            "::ffff:192.168.1.5",
            "::ffff:100.100.100.100",
        ];
        for a in yes {
            assert!(is_allowed_addr(ip(a), &p), "{a} should be allowed");
        }
        let no = [
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "11.0.0.1",
            "192.169.0.1",
            "8.8.8.8",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "169.254.1.1",
            "127.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fec0::1",
            "fbff::1",
            "ff02::1",
            "2001:db8::1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "::ffff:127.0.0.1",
            "::ffff:169.254.0.1",
        ];
        for a in no {
            assert!(!is_allowed_addr(ip(a), &p), "{a} should be rejected");
        }
    }

    #[test]
    fn loopback_only_when_explicit() {
        assert!(!is_allowed_addr(ip("127.0.0.1"), &NetPolicy::default()));
        assert!(is_allowed_addr(
            ip("127.0.0.1"),
            &NetPolicy::with_loopback()
        ));
        assert!(is_allowed_addr(ip("::1"), &NetPolicy::with_loopback()));
        assert!(is_allowed_addr(
            ip("::ffff:127.0.0.1"),
            &NetPolicy::with_loopback()
        ));
        // Link-local stays rejected even with loopback allowed.
        assert!(!is_allowed_addr(ip("fe80::1"), &NetPolicy::with_loopback()));
    }

    #[test]
    fn class_toggles() {
        let p = NetPolicy {
            allow_tailscale: false,
            ..NetPolicy::default()
        };
        assert!(!is_allowed_addr(ip("100.64.0.1"), &p));
        assert!(!is_allowed_addr(ip("fd7a:115c:a1e0::1"), &p));
        assert!(is_allowed_addr(ip("fd00::1"), &p));
        let p = NetPolicy {
            allow_ula: false,
            ..NetPolicy::default()
        };
        assert!(!is_allowed_addr(ip("fd00::1"), &p));
        assert!(is_allowed_addr(ip("fd7a:115c:a1e0::1"), &p));
        let p = NetPolicy {
            allow_lan: false,
            ..NetPolicy::default()
        };
        assert!(!is_allowed_addr(ip("192.168.1.1"), &p));
    }

    #[test]
    fn classification_kinds() {
        let p = NetPolicy::with_loopback();
        assert_eq!(classify(ip("192.168.0.2"), &p), Some(AddrKind::Lan));
        assert_eq!(classify(ip("fd00::2"), &p), Some(AddrKind::Lan));
        assert_eq!(
            classify(ip("100.101.102.103"), &p),
            Some(AddrKind::Tailscale)
        );
        assert_eq!(
            classify(ip("fd7a:115c:a1e0::5"), &p),
            Some(AddrKind::Tailscale)
        );
        assert_eq!(classify(ip("::1"), &p), Some(AddrKind::Loopback));
    }

    fn bound(s: &str, kind: AddrKind, prefix: u8) -> BoundAddr {
        BoundAddr {
            ip: ip(s),
            iface: "en0".into(),
            kind,
            prefix_len: prefix,
        }
    }

    #[test]
    fn subnet_lan_v4() {
        let l = bound("192.168.1.10", AddrKind::Lan, 24);
        assert!(same_subnet(&l, ip("192.168.1.200")));
        assert!(same_subnet(&l, ip("::ffff:192.168.1.200")));
        assert!(!same_subnet(&l, ip("192.168.2.200")));
        assert!(!same_subnet(&l, ip("10.0.0.1")));
        assert!(!same_subnet(&l, ip("fd00::1")));
        let wide = bound("10.1.2.3", AddrKind::Lan, 8);
        assert!(same_subnet(&wide, ip("10.200.0.1")));
        assert!(!same_subnet(&wide, ip("11.0.0.1")));
    }

    #[test]
    fn subnet_lan_v6() {
        let l = bound("fd12:3456:789a:1::5", AddrKind::Lan, 64);
        assert!(same_subnet(&l, ip("fd12:3456:789a:1::99")));
        assert!(!same_subnet(&l, ip("fd12:3456:789a:2::99")));
        assert!(!same_subnet(&l, ip("192.168.1.1")));
    }

    #[test]
    fn subnet_tailscale_is_whole_range() {
        let l = bound("100.90.1.1", AddrKind::Tailscale, 32);
        assert!(same_subnet(&l, ip("100.64.0.9")));
        assert!(same_subnet(&l, ip("100.127.0.9")));
        assert!(!same_subnet(&l, ip("100.128.0.9")));
        assert!(!same_subnet(&l, ip("192.168.1.1")));
        assert!(!same_subnet(&l, ip("fd7a:115c:a1e0::1")));
        let l6 = bound("fd7a:115c:a1e0::1234", AddrKind::Tailscale, 128);
        assert!(same_subnet(&l6, ip("fd7a:115c:a1e0:ab12::1")));
        assert!(!same_subnet(&l6, ip("fd00::1")));
    }

    #[test]
    fn peer_allowed_combines_both() {
        let policy = NetPolicy::default();
        let l = bound("192.168.1.10", AddrKind::Lan, 24);
        assert!(peer_allowed(&l, ip("192.168.1.77"), &policy));
        assert!(!peer_allowed(&l, ip("192.168.9.77"), &policy));
        assert!(!peer_allowed(&l, ip("8.8.8.8"), &policy));
    }

    #[test]
    fn candidates_filtering() {
        let input = vec![
            ("lo0".to_string(), ip("127.0.0.1"), 8),
            ("en0".to_string(), ip("192.168.1.10"), 24),
            ("en0".to_string(), ip("fe80::1"), 64),
            ("en0".to_string(), ip("169.254.3.3"), 16),
            ("en0".to_string(), ip("203.0.113.9"), 24),
            ("utun4".to_string(), ip("100.80.1.2"), 32),
            ("utun4".to_string(), ip("fd7a:115c:a1e0::2"), 128),
            ("en0".to_string(), ip("192.168.1.10"), 24), // duplicate
        ];
        let got = candidates_from(input.clone(), &NetPolicy::default());
        let ips: Vec<_> = got.iter().map(|b| b.ip).collect();
        assert_eq!(
            ips,
            vec![
                ip("192.168.1.10"),
                ip("100.80.1.2"),
                ip("fd7a:115c:a1e0::2")
            ]
        );
        assert_eq!(got[1].kind, AddrKind::Tailscale);

        let got = candidates_from(input.clone(), &NetPolicy::with_loopback());
        assert!(got.iter().any(|b| b.kind == AddrKind::Loopback));

        let only_ts = NetPolicy {
            iface_prefixes: vec!["utun".into(), "tailscale".into()],
            ..NetPolicy::default()
        };
        let got = candidates_from(input, &only_ts);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|b| b.iface == "utun4"));
    }

    #[test]
    fn real_enumeration_respects_policy() {
        // Whatever this machine has, every result must satisfy the policy and
        // loopback must never appear under the default policy.
        let policy = NetPolicy::default();
        for b in candidate_bind_addrs(&policy) {
            assert!(is_allowed_addr(b.ip, &policy));
            assert_ne!(b.kind, AddrKind::Loopback);
        }
        assert!(
            candidate_bind_addrs(&NetPolicy::with_loopback())
                .iter()
                .any(|b| b.kind == AddrKind::Loopback)
        );
    }
}
