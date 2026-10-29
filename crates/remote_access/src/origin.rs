//! `Host` / `Origin` / content-type validation (anti DNS-rebinding and CSRF,
//! REMOTE_CONTROL.md 6.1). Pure functions over header values so the server can
//! call them for both the WebSocket upgrade and every POST.
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderCheckError {
    #[error("missing Host header")]
    MissingHost,
    #[error("Host header is not one of the bound addresses")]
    BadHost,
    #[error("Origin header is not allowed")]
    BadOrigin,
    #[error("Content-Type must be application/json")]
    BadContentType,
}

fn parse_authority(s: &str) -> Option<SocketAddr> {
    // `SocketAddr` parsing requires brackets for IPv6 and a numeric port, and
    // rejects hostnames, userinfo, paths and whitespace.
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    s.parse::<SocketAddr>().ok()
}

/// `Host` must be exactly one of the bound `ip:port` literals.
pub fn validate_host(
    host: Option<&str>,
    bound: &[SocketAddr],
) -> Result<SocketAddr, HeaderCheckError> {
    let host = host.ok_or(HeaderCheckError::MissingHost)?;
    let addr = parse_authority(host).ok_or(HeaderCheckError::BadHost)?;
    if bound.contains(&addr) {
        Ok(addr)
    } else {
        Err(HeaderCheckError::BadHost)
    }
}

/// `Origin` must be absent (native clients) or exactly `https://<bound ip:port>`.
/// The literal `null` origin and any other scheme or host are rejected.
pub fn validate_origin(origin: Option<&str>, bound: &[SocketAddr]) -> Result<(), HeaderCheckError> {
    let Some(origin) = origin else {
        return Ok(());
    };
    let rest = origin
        .strip_prefix("https://")
        .ok_or(HeaderCheckError::BadOrigin)?;
    let addr = parse_authority(rest).ok_or(HeaderCheckError::BadOrigin)?;
    if bound.contains(&addr) {
        Ok(())
    } else {
        Err(HeaderCheckError::BadOrigin)
    }
}

/// POST bodies must be `application/json` (forces a CORS preflight from
/// browsers, which the Origin policy then refuses).
pub fn require_json_content_type(content_type: Option<&str>) -> Result<(), HeaderCheckError> {
    let ct = content_type.ok_or(HeaderCheckError::BadContentType)?;
    let essence = ct.split(';').next().unwrap_or("").trim();
    if essence.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(HeaderCheckError::BadContentType)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound() -> Vec<SocketAddr> {
        vec![
            "192.168.1.10:9477".parse().unwrap(),
            "[fd7a:115c:a1e0::2]:9477".parse().unwrap(),
        ]
    }

    #[test]
    fn host_table() {
        let b = bound();
        assert!(validate_host(Some("192.168.1.10:9477"), &b).is_ok());
        assert!(validate_host(Some("[fd7a:115c:a1e0::2]:9477"), &b).is_ok());
        assert_eq!(validate_host(None, &b), Err(HeaderCheckError::MissingHost));
        for bad in [
            "",
            "192.168.1.10",
            "192.168.1.10:9478",
            "192.168.1.11:9477",
            "evil.example.com:9477",
            "evil.example.com",
            "localhost:9477",
            "192.168.1.10:9477 ",
            " 192.168.1.10:9477",
            "192.168.1.10:9477@evil.com",
            "evil.com@192.168.1.10:9477",
            "192.168.1.10:9477/path",
            "fd7a:115c:a1e0::2:9477",
            "[fd7a:115c:a1e0::3]:9477",
            "192.168.1.10:09477x",
        ] {
            assert_eq!(
                validate_host(Some(bad), &b),
                Err(HeaderCheckError::BadHost),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn origin_table() {
        let b = bound();
        assert!(validate_origin(None, &b).is_ok());
        assert!(validate_origin(Some("https://192.168.1.10:9477"), &b).is_ok());
        assert!(validate_origin(Some("https://[fd7a:115c:a1e0::2]:9477"), &b).is_ok());
        for bad in [
            "null",
            "",
            "http://192.168.1.10:9477",
            "https://192.168.1.10",
            "https://192.168.1.10:9477/",
            "https://192.168.1.10:9478",
            "https://evil.com",
            "https://evil.com:9477",
            "https://192.168.1.10:9477.evil.com",
            "https://localhost:9477",
            "file://",
            "HTTPS://192.168.1.10:9477",
        ] {
            assert_eq!(
                validate_origin(Some(bad), &b),
                Err(HeaderCheckError::BadOrigin),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn content_type() {
        assert!(require_json_content_type(Some("application/json")).is_ok());
        assert!(require_json_content_type(Some("Application/JSON; charset=utf-8")).is_ok());
        for bad in [
            None,
            Some("text/plain"),
            Some("application/x-www-form-urlencoded"),
            Some("multipart/form-data"),
            Some("application/jsonx"),
            Some(""),
        ] {
            assert!(require_json_content_type(bad).is_err(), "{bad:?}");
        }
    }
}
