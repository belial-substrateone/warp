//! Self-signed TLS identity for the remote-access listener.
//!
//! One persistent ECDSA P-256 certificate is generated on first enable and
//! rotated on demand (rotation revokes every device, see tokens.rs). Clients
//! pin the SHA-256 of the leaf certificate DER, which is carried in the QR
//! payload, so hostname validation is irrelevant and the SAN list only exists
//! to keep browsers' "view certificate" output honest.
use std::net::IpAddr;
use std::sync::Arc;

use base64::Engine as _;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring as ring_provider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("certificate generation failed: {0}")]
    Generate(String),
    #[error("invalid certificate material: {0}")]
    Invalid(String),
    #[error("tls configuration failed: {0}")]
    Tls(String),
}

/// Certificate and private key. The key is zeroized on drop.
#[derive(Clone)]
pub struct CertBundle {
    pub cert_der: Vec<u8>,
    pub key_der_pkcs8: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for CertBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertBundle")
            .field("fingerprint", &fingerprint_hex(&self.cert_der))
            .field("key_der_pkcs8", &"<redacted>")
            .finish()
    }
}

impl CertBundle {
    /// Rebuilds a bundle from persisted DER (e.g. read back from secure storage).
    pub fn from_der(cert_der: Vec<u8>, key_der_pkcs8: Vec<u8>) -> Result<Self, CertError> {
        let bundle = Self {
            cert_der,
            key_der_pkcs8: Zeroizing::new(key_der_pkcs8),
        };
        // Reject garbage early: the pair must be usable by rustls.
        rustls_server_config(&bundle)?;
        Ok(bundle)
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint_sha256(&self.cert_der)
    }
}

/// Generates a self-signed ECDSA P-256 certificate whose SAN lists `ips`.
pub fn generate_self_signed(
    ips: &[IpAddr],
    name: &str,
    valid_days: u32,
) -> Result<CertBundle, CertError> {
    let gen_err = |e: rcgen::Error| CertError::Generate(e.to_string());
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(gen_err)?;
    params.subject_alt_names = ips.iter().copied().map(SanType::IpAddress).collect();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // Backdate a day so a phone with a slightly slow clock still accepts it.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(i64::from(valid_days.max(1)));

    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(gen_err)?;
    let cert = params.self_signed(&key).map_err(gen_err)?;
    Ok(CertBundle {
        cert_der: cert.der().to_vec(),
        key_der_pkcs8: Zeroizing::new(key.serialize_der()),
    })
}

/// SHA-256 of the leaf certificate DER.
pub fn fingerprint_sha256(cert_der: &[u8]) -> [u8; 32] {
    Sha256::digest(cert_der).into()
}

pub fn fingerprint_hex(cert_der: &[u8]) -> String {
    hex::encode(fingerprint_sha256(cert_der))
}

/// Unpadded base64url form used in QR payloads.
pub fn fingerprint_b64url(fp: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fp)
}

/// `AB:CD:..` form for showing the fingerprint to a human.
pub fn fingerprint_display(fp: &[u8; 32]) -> String {
    fp.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn provider() -> Arc<CryptoProvider> {
    // Explicit provider: never depend on a process-default install.
    Arc::new(ring_provider::default_provider())
}

/// TLS 1.3-only server configuration with the `ring` provider.
///
/// ALPN is pinned to `http/1.1` so browsers never negotiate HTTP/2 (WebSocket
/// upgrades are plain HTTP/1.1). Clone the config if a caller needs different ALPN.
pub fn rustls_server_config(b: &CertBundle) -> Result<Arc<rustls::ServerConfig>, CertError> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(b.key_der_pkcs8.to_vec()));
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| CertError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(b.cert_der.clone())], key)
        .map_err(|e| CertError::Invalid(e.to_string()))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Verifier that accepts exactly one leaf certificate, identified by its
/// SHA-256 fingerprint, and ignores chain and hostname (this is how the native
/// Android client and Rust test clients behave).
#[derive(Debug)]
struct PinnedVerifier {
    fp: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = fingerprint_sha256(end_entity.as_ref());
        if bool::from(got.ct_eq(&self.fp)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// TLS 1.3 client configuration that pins `fp` (for Rust test clients and the
/// dev host's self-check; mirrors what the Android client does).
pub fn pinned_client_config(fp: [u8; 32]) -> Result<Arc<rustls::ClientConfig>, CertError> {
    let provider = provider();
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| CertError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { fp, provider }))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ips() -> Vec<IpAddr> {
        vec![
            "192.168.1.10".parse().unwrap(),
            "fd7a:115c:a1e0::2".parse().unwrap(),
        ]
    }

    #[test]
    fn fingerprint_matches_cert_and_is_stable() {
        let b = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        let fp = b.fingerprint();
        assert_eq!(fp, fingerprint_sha256(&b.cert_der));
        // Independent computation.
        let mut h = Sha256::new();
        h.update(&b.cert_der);
        assert_eq!(<[u8; 32]>::from(h.finalize()), fp);
        assert_eq!(fingerprint_hex(&b.cert_der), hex::encode(fp));
        assert_eq!(fingerprint_b64url(&fp).len(), 43);
        assert_eq!(fingerprint_display(&fp).len(), 32 * 3 - 1);
        // Reloading persisted DER keeps the same fingerprint.
        let again = CertBundle::from_der(b.cert_der.clone(), b.key_der_pkcs8.to_vec()).unwrap();
        assert_eq!(again.fingerprint(), fp);
    }

    #[test]
    fn distinct_generations_differ() {
        let a = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        let b = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn san_contains_ips() {
        let b = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        let (_, cert) = x509_ips(&b.cert_der);
        assert!(cert.contains(&[192, 168, 1, 10].to_vec()));
        let v6: IpAddr = "fd7a:115c:a1e0::2".parse().unwrap();
        let IpAddr::V6(v6) = v6 else { unreachable!() };
        assert!(cert.contains(&v6.octets().to_vec()));
    }

    /// Minimal DER walk: returns the iPAddress GeneralName payloads of the SAN
    /// extension (avoids a parser dependency).
    fn x509_ips(der: &[u8]) -> ((), Vec<Vec<u8>>) {
        // SAN extension OID 2.5.29.17 = 55 1D 11.
        let oid = [0x55, 0x1d, 0x11];
        let pos = der.windows(3).position(|w| w == oid).expect("san oid");
        // After OID: OCTET STRING { SEQUENCE { [7] ip ... } }.
        let mut i = pos + 3;
        assert_eq!(der[i], 0x04);
        i += 2; // tag + 1-byte length (short form for our sizes)
        assert_eq!(der[i], 0x30);
        let seq_len = der[i + 1] as usize;
        i += 2;
        let end = i + seq_len;
        let mut out = vec![];
        while i < end {
            let tag = der[i];
            let len = der[i + 1] as usize;
            if tag == 0x87 {
                out.push(der[i + 2..i + 2 + len].to_vec());
            }
            i += 2 + len;
        }
        ((), out)
    }

    /// Drives an in-memory TLS handshake and one application-data round trip.
    fn handshake(
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    ) -> Result<(), String> {
        let name = ServerName::IpAddress("192.168.1.10".parse::<IpAddr>().unwrap().into());
        let mut c = rustls::ClientConnection::new(client, name).map_err(|e| e.to_string())?;
        let mut s = rustls::ServerConnection::new(server).map_err(|e| e.to_string())?;
        for _ in 0..20 {
            for (from, to) in [(0, 1), (1, 0)] {
                let mut buf = Vec::new();
                if from == 0 {
                    while c.wants_write() {
                        c.write_tls(&mut buf).unwrap();
                    }
                } else {
                    while s.wants_write() {
                        s.write_tls(&mut buf).unwrap();
                    }
                }
                if buf.is_empty() {
                    continue;
                }
                let mut cur = Cursor::new(buf);
                let r = if to == 1 {
                    s.read_tls(&mut cur).and_then(|_| {
                        s.process_new_packets()
                            .map(|_| ())
                            .map_err(|e| std::io::Error::other(e.to_string()))
                    })
                } else {
                    c.read_tls(&mut cur).and_then(|_| {
                        c.process_new_packets()
                            .map(|_| ())
                            .map_err(|e| std::io::Error::other(e.to_string()))
                    })
                };
                r.map_err(|e| e.to_string())?;
            }
            if !c.is_handshaking() && !s.is_handshaking() {
                assert_eq!(c.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
                return Ok(());
            }
        }
        Err("handshake did not complete".into())
    }

    #[test]
    fn handshake_with_matching_pin_succeeds() {
        let b = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        let server = rustls_server_config(&b).unwrap();
        let client = pinned_client_config(b.fingerprint()).unwrap();
        handshake(client, server).unwrap();
    }

    #[test]
    fn handshake_with_wrong_pin_fails() {
        let b = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        let other = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        let server = rustls_server_config(&b).unwrap();
        let client = pinned_client_config(other.fingerprint()).unwrap();
        assert!(handshake(client, server).is_err());
        let mut bad = b.fingerprint();
        bad[0] ^= 1;
        let client = pinned_client_config(bad).unwrap();
        assert!(handshake(client, rustls_server_config(&b).unwrap()).is_err());
    }

    #[test]
    fn tls12_only_client_is_rejected() {
        let b = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        let server = rustls_server_config(&b).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                fp: b.fingerprint(),
                provider: provider(),
            }))
            .with_no_client_auth();
        assert!(handshake(Arc::new(client), server).is_err());
    }

    #[test]
    fn from_der_rejects_mismatched_material() {
        let a = generate_self_signed(&ips(), "a", 30).unwrap();
        let b = generate_self_signed(&ips(), "b", 30).unwrap();
        assert!(CertBundle::from_der(a.cert_der.clone(), b.key_der_pkcs8.to_vec()).is_err());
        assert!(CertBundle::from_der(vec![1, 2, 3], vec![4, 5]).is_err());
    }

    #[test]
    fn debug_hides_key() {
        let b = generate_self_signed(&ips(), "anonwarp", 30).unwrap();
        let s = format!("{b:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains(&hex::encode(&b.key_der_pkcs8[..16])));
    }
}
