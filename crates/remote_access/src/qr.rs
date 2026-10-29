//! Pairing QR payload (REMOTE_CONTROL.md section 7).
//!
//! ```text
//! https://<host0>:<port>/pair#v=1&s=<secret>&fp=<sha256 b64url>&h=<host1,host2>&id=<instance>&exp=<unix>&n=<pc name>
//! anonwarp://pair?v=1&s=...&fp=...&h=<host0,host1,...>&id=...&exp=...&n=...
//! ```
//! Everything lives in the fragment (https form) so the secret is never sent in
//! a request line. Parsing is strict: exact scheme/path, no duplicate keys,
//! IP-literal hosts only, a 32-byte base64url secret and fingerprint.
use std::fmt;
use std::net::SocketAddr;

use base64::Engine as _;

pub const QR_VERSION: u32 = 1;
/// Upper bound on a payload we are willing to parse.
pub const MAX_PAYLOAD_LEN: usize = 2048;
pub const MAX_HOSTS: usize = 16;
const MAX_NAME_LEN: usize = 64;
const MAX_ID_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq)]
pub struct QrPayload {
    /// Preferred address first; all must be IP literals.
    pub hosts: Vec<SocketAddr>,
    /// base64url (no padding) of the 32-byte pairing secret.
    pub secret: String,
    /// SHA-256 of the leaf certificate DER.
    pub fp: [u8; 32],
    pub instance_id: String,
    pub expires_unix: i64,
    pub pc_name: String,
}

impl fmt::Debug for QrPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QrPayload")
            .field("hosts", &self.hosts)
            .field("secret", &"<redacted>")
            .field("fp", &hex::encode(self.fp))
            .field("instance_id", &self.instance_id)
            .field("expires_unix", &self.expires_unix)
            .field("pc_name", &self.pc_name)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QrError {
    #[error("payload too long")]
    TooLong,
    #[error("unsupported scheme or path")]
    BadScheme,
    #[error("malformed host or port")]
    BadHost,
    #[error("missing or malformed parameters")]
    Malformed,
    #[error("duplicate parameter `{0}`")]
    Duplicate(String),
    #[error("missing parameter `{0}`")]
    Missing(&'static str),
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("invalid secret")]
    BadSecret,
    #[error("invalid fingerprint")]
    BadFingerprint,
    #[error("invalid percent-encoding")]
    BadEncoding,
    #[error("a field is too long or contains control characters")]
    BadField,
    #[error("cannot encode: {0}")]
    Encode(&'static str),
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn pct_decode(s: &str) -> Result<String, QrError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = s.get(i + 1..i + 3).ok_or(QrError::BadEncoding)?;
                if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(QrError::BadEncoding);
                }
                out.push(u8::from_str_radix(hex, 16).map_err(|_| QrError::BadEncoding)?);
                i += 3;
            }
            b'+' | b'#' | b'&' | b'=' | b' ' => return Err(QrError::BadEncoding),
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| QrError::BadEncoding)
}

fn valid_field(s: &str, max: usize) -> bool {
    s.chars().count() <= max && !s.chars().any(char::is_control)
}

fn parse_hosts(list: &str) -> Result<Vec<SocketAddr>, QrError> {
    list.split(',')
        .map(|h| {
            let a: SocketAddr = h.parse().map_err(|_| QrError::BadHost)?;
            if a.port() == 0 {
                return Err(QrError::BadHost);
            }
            Ok(a)
        })
        .collect()
}

impl QrPayload {
    fn validate(&self) -> Result<(), QrError> {
        if self.hosts.is_empty() {
            return Err(QrError::Encode("no hosts"));
        }
        if self.hosts.len() > MAX_HOSTS || self.hosts.iter().any(|h| h.port() == 0) {
            return Err(QrError::Encode("bad hosts"));
        }
        if !valid_secret(&self.secret) {
            return Err(QrError::BadSecret);
        }
        if !valid_field(&self.pc_name, MAX_NAME_LEN) || !valid_field(&self.instance_id, MAX_ID_LEN)
        {
            return Err(QrError::BadField);
        }
        Ok(())
    }

    fn params(&self, other_hosts: &[SocketAddr]) -> String {
        let mut p = format!(
            "v={QR_VERSION}&s={}&fp={}",
            self.secret,
            b64().encode(self.fp)
        );
        if !other_hosts.is_empty() {
            let h: Vec<String> = other_hosts.iter().map(|a| a.to_string()).collect();
            p.push_str("&h=");
            p.push_str(&h.join(","));
        }
        p.push_str(&format!(
            "&id={}&exp={}&n={}",
            pct_encode(&self.instance_id),
            self.expires_unix,
            pct_encode(&self.pc_name)
        ));
        p
    }

    /// Canonical `https://` URL (what the QR code encodes).
    ///
    /// Panics-free: invalid payloads (no hosts, bad secret) return an empty
    /// string; use [`QrPayload::try_to_url`] to see why.
    pub fn to_url(&self) -> String {
        self.try_to_url().unwrap_or_default()
    }

    pub fn try_to_url(&self) -> Result<String, QrError> {
        self.validate()?;
        Ok(format!(
            "https://{}/pair#{}",
            self.hosts[0],
            self.params(&self.hosts[1..])
        ))
    }

    /// `anonwarp://pair?...` form for the Android intent filter.
    pub fn try_to_app_url(&self) -> Result<String, QrError> {
        self.validate()?;
        Ok(format!("anonwarp://pair?{}", self.params(&self.hosts)))
    }

    /// Parses either URL form.
    pub fn parse(s: &str) -> Result<Self, QrError> {
        if s.len() > MAX_PAYLOAD_LEN {
            return Err(QrError::TooLong);
        }
        if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(QrError::Malformed);
        }
        if let Some(rest) = s.strip_prefix("https://") {
            let (authority_path, fragment) = rest.split_once('#').ok_or(QrError::Malformed)?;
            let authority = authority_path
                .strip_suffix("/pair")
                .ok_or(QrError::BadScheme)?;
            let host0: SocketAddr = authority.parse().map_err(|_| QrError::BadHost)?;
            if host0.port() == 0 {
                return Err(QrError::BadHost);
            }
            Self::from_params(fragment, Some(host0))
        } else if let Some(query) = s.strip_prefix("anonwarp://pair?") {
            if query.contains('#') {
                return Err(QrError::Malformed);
            }
            Self::from_params(query, None)
        } else {
            Err(QrError::BadScheme)
        }
    }

    fn from_params(params: &str, host0: Option<SocketAddr>) -> Result<Self, QrError> {
        let mut v = None;
        let mut s = None;
        let mut fp = None;
        let mut h = None;
        let mut id = None;
        let mut exp = None;
        let mut n = None;
        for pair in params.split('&') {
            let (k, val) = pair.split_once('=').ok_or(QrError::Malformed)?;
            let slot = match k {
                "v" => &mut v,
                "s" => &mut s,
                "fp" => &mut fp,
                "h" => &mut h,
                "id" => &mut id,
                "exp" => &mut exp,
                "n" => &mut n,
                // Unknown keys are ignored for forward compatibility.
                _ => {
                    if k.is_empty() {
                        return Err(QrError::Malformed);
                    }
                    continue;
                }
            };
            if slot.replace(val).is_some() {
                return Err(QrError::Duplicate(k.to_string()));
            }
        }

        if v.ok_or(QrError::Missing("v"))? != "1" {
            return Err(QrError::UnsupportedVersion);
        }
        let secret = s.ok_or(QrError::Missing("s"))?;
        if !valid_secret(secret) {
            return Err(QrError::BadSecret);
        }
        let fp_str = fp.ok_or(QrError::Missing("fp"))?;
        let fp = parse_fp(fp_str)?;

        let mut hosts = Vec::new();
        hosts.extend(host0);
        if let Some(h) = h {
            hosts.extend(parse_hosts(h)?);
        }
        if hosts.is_empty() {
            return Err(QrError::Missing("h"));
        }
        if hosts.len() > MAX_HOSTS {
            return Err(QrError::BadHost);
        }
        for (i, a) in hosts.iter().enumerate() {
            if hosts[..i].contains(a) {
                return Err(QrError::BadHost);
            }
        }

        let expires_unix = match exp {
            None => 0,
            Some(e) => {
                if e.is_empty() || !e.bytes().all(|b| b.is_ascii_digit()) || e.len() > 12 {
                    return Err(QrError::Malformed);
                }
                e.parse::<i64>().map_err(|_| QrError::Malformed)?
            }
        };
        let instance_id = id.map(pct_decode).transpose()?.unwrap_or_default();
        let pc_name = n.map(pct_decode).transpose()?.unwrap_or_default();
        if !valid_field(&pc_name, MAX_NAME_LEN) || !valid_field(&instance_id, MAX_ID_LEN) {
            return Err(QrError::BadField);
        }
        Ok(Self {
            hosts,
            secret: secret.to_string(),
            fp,
            instance_id,
            expires_unix,
            pc_name,
        })
    }
}

fn valid_secret(s: &str) -> bool {
    s.len() == 43 && matches!(b64().decode(s), Ok(b) if b.len() == 32) && {
        // Reject non-canonical encodings (trailing bits set).
        b64().encode(b64().decode(s).unwrap_or_default()) == s
    }
}

/// Accepts base64url (43 chars) or lowercase/uppercase hex (64 chars).
fn parse_fp(s: &str) -> Result<[u8; 32], QrError> {
    let bytes = if s.len() == 64 {
        hex::decode(s).map_err(|_| QrError::BadFingerprint)?
    } else if s.len() == 43 {
        let b = b64().decode(s).map_err(|_| QrError::BadFingerprint)?;
        if b64().encode(&b) != s {
            return Err(QrError::BadFingerprint);
        }
        b
    } else {
        return Err(QrError::BadFingerprint);
    };
    bytes.try_into().map_err(|_| QrError::BadFingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    fn sample() -> QrPayload {
        QrPayload {
            hosts: vec![
                "192.168.1.10:9477".parse().unwrap(),
                "100.80.1.2:9477".parse().unwrap(),
                "[fd7a:115c:a1e0::2]:9477".parse().unwrap(),
            ],
            secret: SECRET.to_string(),
            fp: core::array::from_fn(|i| i as u8),
            instance_id: "inst-1".into(),
            expires_unix: 1_800_000_120,
            pc_name: "Belial's PC #1 & co".into(),
        }
    }

    const GOLDEN_FP_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    #[test]
    fn golden_url() {
        let url = sample().to_url();
        assert_eq!(
            url,
            format!(
                "https://192.168.1.10:9477/pair#v=1&s={SECRET}&fp={GOLDEN_FP_B64}&h=100.80.1.2:9477,[fd7a:115c:a1e0::2]:9477&id=inst-1&exp=1800000120&n=Belial%27s%20PC%20%231%20%26%20co"
            )
        );
        assert!(url.len() < 300);
    }

    #[test]
    fn round_trip_https_and_app() {
        let p = sample();
        assert_eq!(QrPayload::parse(&p.to_url()).unwrap(), p);
        let app = p.try_to_app_url().unwrap();
        assert!(app.starts_with("anonwarp://pair?v=1&s="));
        assert_eq!(QrPayload::parse(&app).unwrap(), p);
    }

    #[test]
    fn round_trip_single_host_and_unicode_name() {
        let mut p = sample();
        p.hosts.truncate(1);
        p.pc_name = "Büro-PC 🖥".into();
        let url = p.to_url();
        assert!(!url.contains("&h="));
        assert_eq!(QrPayload::parse(&url).unwrap(), p);
    }

    #[test]
    fn optional_fields_default() {
        let url = format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={GOLDEN_FP_B64}");
        let p = QrPayload::parse(&url).unwrap();
        assert_eq!(p.hosts.len(), 1);
        assert_eq!(p.instance_id, "");
        assert_eq!(p.expires_unix, 0);
        assert_eq!(p.pc_name, "");
    }

    #[test]
    fn hex_fingerprint_accepted() {
        let p = sample();
        let url = format!(
            "https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={}",
            hex::encode(p.fp)
        );
        assert_eq!(QrPayload::parse(&url).unwrap().fp, p.fp);
    }

    #[test]
    fn unknown_keys_ignored() {
        let url = format!("https://10.0.0.5:9477/pair#v=1&x=1&s={SECRET}&fp={GOLDEN_FP_B64}&zz=%");
        assert!(QrPayload::parse(&url).is_ok());
    }

    #[test]
    fn malformed_inputs() {
        let good = sample().to_url();
        let fp = GOLDEN_FP_B64;
        let cases: Vec<(String, QrError)> = vec![
            ("".into(), QrError::BadScheme),
            ("http://10.0.0.5:9477/pair#v=1".into(), QrError::BadScheme),
            ("HTTPS://10.0.0.5:9477/pair#v=1".into(), QrError::BadScheme),
            ("ftp://x".into(), QrError::BadScheme),
            ("https://10.0.0.5:9477/pair".into(), QrError::Malformed),
            (
                format!("https://10.0.0.5:9477/other#v=1&s={SECRET}&fp={fp}"),
                QrError::BadScheme,
            ),
            (
                format!("https://10.0.0.5:9477/pair?x=1#v=1&s={SECRET}&fp={fp}"),
                QrError::BadScheme,
            ),
            (
                format!("https://10.0.0.5/pair#v=1&s={SECRET}&fp={fp}"),
                QrError::BadHost,
            ),
            (
                format!("https://10.0.0.5:0/pair#v=1&s={SECRET}&fp={fp}"),
                QrError::BadHost,
            ),
            (
                format!("https://example.com:9477/pair#v=1&s={SECRET}&fp={fp}"),
                QrError::BadHost,
            ),
            (
                format!("https://user@10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}"),
                QrError::BadHost,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=2&s={SECRET}&fp={fp}"),
                QrError::UnsupportedVersion,
            ),
            (
                format!("https://10.0.0.5:9477/pair#s={SECRET}&fp={fp}"),
                QrError::Missing("v"),
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&fp={fp}"),
                QrError::Missing("s"),
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}"),
                QrError::Missing("fp"),
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s=short&fp={fp}"),
                QrError::BadSecret,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}x&fp={fp}"),
                QrError::BadSecret,
            ),
            (
                format!(
                    "https://10.0.0.5:9477/pair#v=1&s={}%&fp={fp}",
                    &SECRET[..42]
                ),
                QrError::BadSecret,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp=abcd"),
                QrError::BadFingerprint,
            ),
            (
                format!(
                    "https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={}",
                    "g".repeat(64)
                ),
                QrError::BadFingerprint,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&s={SECRET}"),
                QrError::Duplicate("s".into()),
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&h=evil.com:1"),
                QrError::BadHost,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&h=10.0.0.5:9477"),
                QrError::BadHost,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&h="),
                QrError::BadHost,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&exp=-5"),
                QrError::Malformed,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&exp="),
                QrError::Malformed,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&n=%ZZ"),
                QrError::BadEncoding,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&n=%C3%28"),
                QrError::BadEncoding,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&n=a%00b"),
                QrError::BadField,
            ),
            (
                format!(
                    "https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&n={}",
                    "a".repeat(65)
                ),
                QrError::BadField,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&junk"),
                QrError::Malformed,
            ),
            (
                format!("https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}\n"),
                QrError::Malformed,
            ),
            (format!("{good} "), QrError::Malformed),
            (
                format!(
                    "https://10.0.0.5:9477/pair#v=1&s={SECRET}&fp={fp}&n={}",
                    "a".repeat(3000)
                ),
                QrError::TooLong,
            ),
            (
                format!("anonwarp://pair?v=1&s={SECRET}&fp={fp}"),
                QrError::Missing("h"),
            ),
            (
                format!("anonwarp://other?v=1&s={SECRET}&fp={fp}&h=10.0.0.5:1"),
                QrError::BadScheme,
            ),
            (
                format!("anonwarp://pair?v=1&s={SECRET}&fp={fp}&h=10.0.0.5:1#x"),
                QrError::Malformed,
            ),
        ];
        for (input, want) in cases {
            let got = QrPayload::parse(&input);
            assert_eq!(got, Err(want.clone()), "input: {input}");
        }
    }

    #[test]
    fn non_canonical_secret_rejected() {
        let mut s = SECRET.to_string();
        s.pop();
        s.push('9'); // sets low bits that must be zero for 32 bytes
        let url = format!("https://10.0.0.5:9477/pair#v=1&s={s}&fp={GOLDEN_FP_B64}");
        assert_eq!(QrPayload::parse(&url), Err(QrError::BadSecret));
    }

    #[test]
    fn encode_rejects_invalid_payloads() {
        let mut p = sample();
        p.hosts.clear();
        assert!(p.try_to_url().is_err());
        assert_eq!(p.to_url(), "");
        let mut p = sample();
        p.secret = "nope".into();
        assert_eq!(p.try_to_url(), Err(QrError::BadSecret));
        let mut p = sample();
        p.pc_name = "a\nb".into();
        assert_eq!(p.try_to_url(), Err(QrError::BadField));
    }

    #[test]
    fn debug_redacts_secret() {
        assert!(!format!("{:?}", sample()).contains(SECRET));
    }

    #[test]
    fn pct_round_trip() {
        for s in ["", "plain", "a b&c=d#e+f%", "ünï", "tab\t"] {
            assert_eq!(pct_decode(&pct_encode(s)).unwrap(), s);
        }
        assert!(pct_decode("a+b").is_err());
    }
}
