//! Device-token registry (REMOTE_CONTROL.md 6.1 "Device token").
//!
//! Tokens are 256 bits from `OsRng`. Only `SHA-256(token)` is ever stored; the
//! plaintext exists once, in the [`IssuedDevice`] handed to the pairing flow.
//! Expiry is sliding: a device that has not been seen for `ttl_secs` (default
//! 90 days) stops authenticating, and the window is only extended by
//! connections from the same network range as the last one.
use std::fmt;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::netfilter::{self, NetPolicy};

pub const DEFAULT_TTL_SECS: i64 = 90 * 24 * 60 * 60;
/// `last_seen` writes to the store are throttled to this interval.
const PERSIST_TOUCH_INTERVAL_SECS: i64 = 3600;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub String);

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.0)
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        b.try_into()
            .map_err(|_| serde::de::Error::custom("token hash must be 32 bytes"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub label: String,
    #[serde(with = "hex32")]
    pub token_sha256: [u8; 32],
    pub created: i64,
    pub last_seen: i64,
    pub last_ip: Option<IpAddr>,
    pub platform: String,
    pub revoked: bool,
}

/// A freshly issued credential. The token is shown to the device exactly once.
pub struct IssuedDevice {
    pub id: DeviceId,
    /// base64url, 43 characters.
    pub token: Zeroizing<String>,
    pub record: DeviceRecord,
}

impl fmt::Debug for IssuedDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedDevice")
            .field("id", &self.id)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("token store I/O error: {0}")]
    Io(String),
    #[error("token store is corrupt: {0}")]
    Corrupt(String),
}

/// Persistence for device records. Implementations must be atomic: a failed
/// `save` leaves the previous contents intact.
pub trait TokenStore: Send + Sync {
    fn load(&self) -> Result<Vec<DeviceRecord>, StoreError>;
    fn save(&self, records: &[DeviceRecord]) -> Result<(), StoreError>;
}

/// Alias matching the name used in REMOTE_CONTROL.md.
pub use TokenStore as TokenStorage;

#[derive(Default)]
pub struct MemoryTokenStore(Mutex<Vec<DeviceRecord>>);

impl MemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_records(records: Vec<DeviceRecord>) -> Self {
        Self(Mutex::new(records))
    }
}

impl TokenStore for MemoryTokenStore {
    fn load(&self) -> Result<Vec<DeviceRecord>, StoreError> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    fn save(&self, records: &[DeviceRecord]) -> Result<(), StoreError> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = records.to_vec();
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct FileFormat {
    version: u32,
    devices: Vec<DeviceRecord>,
}

/// JSON file store: write to a sibling temp file with mode 0600, fsync, rename.
pub struct JsonFileTokenStore {
    path: PathBuf,
}

impl JsonFileTokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn io_err(e: std::io::Error) -> StoreError {
    StoreError::Io(e.to_string())
}

impl TokenStore for JsonFileTokenStore {
    fn load(&self) -> Result<Vec<DeviceRecord>, StoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_err(e)),
        };
        // A corrupt file is an error, never silently treated as "no devices":
        // that would look like a successful revoke-all to the operator.
        let f: FileFormat =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        if f.version != 1 {
            return Err(StoreError::Corrupt(format!(
                "unsupported version {}",
                f.version
            )));
        }
        Ok(f.devices)
    }

    fn save(&self, records: &[DeviceRecord]) -> Result<(), StoreError> {
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir).map_err(io_err)?;
        let json = serde_json::to_vec_pretty(&FileFormat {
            version: 1,
            devices: records.to_vec(),
        })
        .map_err(|e| StoreError::Io(e.to_string()))?;

        let mut name = self
            .path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| "devices.json".into());
        let mut suffix = [0u8; 6];
        rand::rngs::OsRng.fill_bytes(&mut suffix);
        name.push(format!(".{}.tmp", hex::encode(suffix)));
        let tmp = dir.join(name);

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let result = (|| {
            let mut f = opts.open(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &self.path)
        })();
        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(io_err(e));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub ttl_secs: i64,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("unknown token")]
    Unknown,
    #[error("device revoked")]
    Revoked,
    #[error("token expired")]
    Expired,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn range_key(ip: IpAddr) -> (u8, [u8; 6]) {
    // Coarse "same network" bucket: Tailscale as a whole, v4 LAN by /16, v6 ULA by /48.
    let ip = netfilter::unmap(ip);
    let kind = netfilter::classify(ip, &NetPolicy::with_loopback());
    let mut k = [0u8; 6];
    match (kind, ip) {
        (Some(netfilter::AddrKind::Tailscale), _) => (1, k),
        (_, IpAddr::V4(v4)) => {
            k[..2].copy_from_slice(&v4.octets()[..2]);
            (2, k)
        }
        (_, IpAddr::V6(v6)) => {
            k.copy_from_slice(&v6.octets()[..6]);
            (3, k)
        }
    }
}

pub fn same_range(a: IpAddr, b: IpAddr) -> bool {
    range_key(a) == range_key(b)
}

pub struct DeviceRegistry {
    store: Arc<dyn TokenStore>,
    clock: Arc<dyn Clock>,
    cfg: RegistryConfig,
    records: Vec<DeviceRecord>,
    /// `last_seen` as last written to the store, per device, for throttling.
    persisted_seen: Vec<(DeviceId, i64)>,
}

impl DeviceRegistry {
    pub fn new(
        store: Arc<dyn TokenStore>,
        clock: Arc<dyn Clock>,
        cfg: RegistryConfig,
    ) -> Result<Self, StoreError> {
        let records = store.load()?;
        let persisted_seen = records
            .iter()
            .map(|r| (r.id.clone(), r.last_seen))
            .collect();
        Ok(Self {
            store,
            clock,
            cfg,
            records,
            persisted_seen,
        })
    }

    /// Generates a token and registers its hash. Persists before returning; on
    /// failure nothing is registered.
    pub fn issue(
        &mut self,
        label: &str,
        platform: &str,
        ip: Option<IpAddr>,
    ) -> Result<IssuedDevice, StoreError> {
        let mut raw = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *raw);
        let token = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*raw));
        let mut id_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let now = self.clock.now_unix();
        let record = DeviceRecord {
            id: DeviceId(hex::encode(id_bytes)),
            label: label.to_string(),
            token_sha256: hash_token(&token),
            created: now,
            last_seen: now,
            last_ip: ip,
            platform: platform.to_string(),
            revoked: false,
        };
        self.records.push(record.clone());
        if let Err(e) = self.persist() {
            self.records.pop();
            return Err(e);
        }
        self.persisted_seen.push((record.id.clone(), now));
        Ok(IssuedDevice {
            id: record.id.clone(),
            token,
            record,
        })
    }

    /// Validates a presented token and slides its expiry.
    ///
    /// All hashes are compared in constant time and the whole list is always
    /// walked, so timing does not reveal which record matched.
    pub fn authenticate(&mut self, token: &str, ip: Option<IpAddr>) -> Result<DeviceId, AuthError> {
        let presented = hash_token(token);
        let mut found = None;
        for (i, r) in self.records.iter().enumerate() {
            if bool::from(r.token_sha256.ct_eq(&presented)) {
                found = Some(i);
            }
        }
        let i = found.ok_or(AuthError::Unknown)?;
        let now = self.clock.now_unix();
        let r = &mut self.records[i];
        if r.revoked {
            return Err(AuthError::Revoked);
        }
        if now.saturating_sub(r.last_seen) > self.cfg.ttl_secs {
            return Err(AuthError::Expired);
        }
        // Never slide the expiry over a different network range than last time.
        let slide = match (r.last_ip, ip) {
            (Some(prev), Some(cur)) => same_range(prev, cur),
            (None, _) => true,
            (Some(_), None) => true,
        };
        let id = r.id.clone();
        if slide {
            r.last_seen = now;
            if ip.is_some() {
                r.last_ip = ip;
            }
            let due = self
                .persisted_seen
                .iter()
                .find(|(d, _)| *d == id)
                .map(|(_, t)| now - *t >= PERSIST_TOUCH_INTERVAL_SECS)
                .unwrap_or(true);
            if due {
                // Best effort: a failed touch write must not break a login.
                if self.persist().is_ok() {
                    self.mark_persisted(&id, now);
                }
            }
        }
        Ok(id)
    }

    fn mark_persisted(&mut self, id: &DeviceId, now: i64) {
        match self.persisted_seen.iter_mut().find(|(d, _)| d == id) {
            Some(e) => e.1 = now,
            None => self.persisted_seen.push((id.clone(), now)),
        }
    }

    /// Active (non-revoked) devices.
    pub fn list(&self) -> Vec<DeviceRecord> {
        self.records
            .iter()
            .filter(|r| !r.revoked)
            .cloned()
            .collect()
    }

    /// Everything including revoked entries (audit view).
    pub fn list_all(&self) -> Vec<DeviceRecord> {
        self.records.clone()
    }

    pub fn get(&self, id: &DeviceId) -> Option<DeviceRecord> {
        self.records.iter().find(|r| &r.id == id).cloned()
    }

    /// Revokes one device. Returns false if it does not exist or was revoked.
    /// The in-memory revocation is kept even if persisting fails (fail closed).
    pub fn revoke(&mut self, id: &DeviceId) -> Result<bool, StoreError> {
        let Some(r) = self.records.iter_mut().find(|r| &r.id == id && !r.revoked) else {
            return Ok(false);
        };
        r.revoked = true;
        self.persist()?;
        Ok(true)
    }

    /// Revokes every device (certificate rotation, "revoke all"). Returns how
    /// many were active.
    pub fn revoke_all(&mut self) -> Result<usize, StoreError> {
        let mut n = 0;
        for r in self.records.iter_mut().filter(|r| !r.revoked) {
            r.revoked = true;
            n += 1;
        }
        self.persist()?;
        Ok(n)
    }

    /// Drops revoked records from memory and the store.
    pub fn purge_revoked(&mut self) -> Result<(), StoreError> {
        self.records.retain(|r| !r.revoked);
        self.persist()
    }

    pub fn is_active(&self, id: &DeviceId) -> bool {
        self.records.iter().any(|r| &r.id == id && !r.revoked)
    }

    fn persist(&self) -> Result<(), StoreError> {
        self.store.save(&self.records)
    }
}

/// Registry shared between the pairing manager and the server.
pub type SharedRegistry = Arc<Mutex<DeviceRegistry>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    fn registry() -> (DeviceRegistry, Arc<ManualClock>, Arc<MemoryTokenStore>) {
        let clock = Arc::new(ManualClock::new(1_000_000));
        let store = Arc::new(MemoryTokenStore::new());
        let reg =
            DeviceRegistry::new(store.clone(), clock.clone(), RegistryConfig::default()).unwrap();
        (reg, clock, store)
    }

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn issue_authenticate_and_hash_only() {
        let (mut reg, _c, store) = registry();
        let d = reg.issue("Pixel", "android", ip("192.168.1.5")).unwrap();
        assert_eq!(d.token.len(), 43);
        assert_eq!(
            reg.authenticate(&d.token, ip("192.168.1.5")),
            Ok(d.id.clone())
        );
        assert_eq!(reg.authenticate("wrong", None), Err(AuthError::Unknown));
        assert_eq!(reg.authenticate("", None), Err(AuthError::Unknown));
        // Stored record has only the hash.
        let rec = &store.load().unwrap()[0];
        assert_eq!(rec.token_sha256, hash_token(&d.token));
        assert!(!format!("{d:?}").contains(&*d.token));
    }

    #[test]
    fn tokens_are_unique_and_random() {
        let (mut reg, _c, _s) = registry();
        let a = reg.issue("a", "web", None).unwrap();
        let b = reg.issue("b", "web", None).unwrap();
        assert_ne!(*a.token, *b.token);
        assert_ne!(a.id, b.id);
        assert_eq!(reg.authenticate(&a.token, None), Ok(a.id));
        assert_eq!(reg.authenticate(&b.token, None), Ok(b.id));
    }

    #[test]
    fn revoke_one_and_all() {
        let (mut reg, _c, _s) = registry();
        let a = reg.issue("a", "web", None).unwrap();
        let b = reg.issue("b", "android", None).unwrap();
        assert_eq!(reg.list().len(), 2);
        assert!(reg.revoke(&a.id).unwrap());
        assert!(!reg.revoke(&a.id).unwrap());
        assert!(!reg.revoke(&DeviceId("nope".into())).unwrap());
        assert_eq!(reg.authenticate(&a.token, None), Err(AuthError::Revoked));
        assert!(reg.authenticate(&b.token, None).is_ok());
        assert_eq!(reg.list().len(), 1);
        assert_eq!(reg.list_all().len(), 2);
        assert!(!reg.is_active(&a.id));
        assert_eq!(reg.revoke_all().unwrap(), 1);
        assert_eq!(reg.authenticate(&b.token, None), Err(AuthError::Revoked));
        assert!(reg.list().is_empty());
        reg.purge_revoked().unwrap();
        assert!(reg.list_all().is_empty());
        assert_eq!(reg.authenticate(&b.token, None), Err(AuthError::Unknown));
    }

    #[test]
    fn sliding_expiry() {
        let (mut reg, clock, _s) = registry();
        let d = reg.issue("a", "web", ip("192.168.1.5")).unwrap();
        let day = 86_400;
        clock.advance(89 * day);
        assert!(reg.authenticate(&d.token, ip("192.168.1.9")).is_ok()); // slides
        clock.advance(89 * day);
        assert!(reg.authenticate(&d.token, ip("192.168.1.9")).is_ok());
        clock.advance(91 * day);
        assert_eq!(
            reg.authenticate(&d.token, ip("192.168.1.9")),
            Err(AuthError::Expired)
        );
        // Expired stays expired (last_seen not refreshed by a failed attempt).
        assert_eq!(
            reg.authenticate(&d.token, ip("192.168.1.9")),
            Err(AuthError::Expired)
        );
    }

    #[test]
    fn expiry_not_slid_from_other_range() {
        let (mut reg, clock, _s) = registry();
        let d = reg.issue("a", "web", ip("192.168.1.5")).unwrap();
        let day = 86_400;
        clock.advance(60 * day);
        // Authenticates, but from a different range: no slide, ip not updated.
        assert!(reg.authenticate(&d.token, ip("10.1.1.1")).is_ok());
        let rec = reg.get(&d.id).unwrap();
        assert_eq!(rec.last_seen, 1_000_000);
        assert_eq!(rec.last_ip, ip("192.168.1.5"));
        clock.advance(31 * day);
        assert_eq!(
            reg.authenticate(&d.token, ip("10.1.1.1")),
            Err(AuthError::Expired)
        );
    }

    #[test]
    fn range_buckets() {
        let a = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(same_range(a("192.168.1.1"), a("192.168.200.3")));
        assert!(!same_range(a("192.168.1.1"), a("192.169.1.1")));
        assert!(same_range(a("100.64.0.1"), a("100.120.5.5")));
        assert!(same_range(a("fd7a:115c:a1e0::1"), a("fd7a:115c:a1e0:9::1")));
        assert!(!same_range(a("100.64.0.1"), a("192.168.1.1")));
        assert!(same_range(a("::ffff:192.168.1.1"), a("192.168.1.2")));
        assert!(same_range(a("fd12:3456:789a::1"), a("fd12:3456:789a:5::1")));
        assert!(!same_range(a("fd12:3456:789a::1"), a("fd12:3456:789b::1")));
    }

    #[test]
    fn registry_reloads_from_store() {
        let (mut reg, clock, store) = registry();
        let d = reg.issue("a", "web", None).unwrap();
        let mut again = DeviceRegistry::new(store, clock, RegistryConfig::default()).unwrap();
        assert_eq!(again.authenticate(&d.token, None), Ok(d.id));
    }

    struct FailingStore;
    impl TokenStore for FailingStore {
        fn load(&self) -> Result<Vec<DeviceRecord>, StoreError> {
            Ok(vec![])
        }
        fn save(&self, _: &[DeviceRecord]) -> Result<(), StoreError> {
            Err(StoreError::Io("disk full".into()))
        }
    }

    #[test]
    fn issue_rolls_back_on_save_failure_and_revoke_fails_closed() {
        let clock = Arc::new(ManualClock::new(0));
        let mut reg =
            DeviceRegistry::new(Arc::new(FailingStore), clock, RegistryConfig::default()).unwrap();
        assert!(reg.issue("a", "web", None).is_err());
        assert!(reg.list_all().is_empty());

        let store = Arc::new(MemoryTokenStore::new());
        let clock = Arc::new(ManualClock::new(0));
        let mut ok = DeviceRegistry::new(store, clock.clone(), RegistryConfig::default()).unwrap();
        let d = ok.issue("a", "web", None).unwrap();
        let mut broken =
            DeviceRegistry::new(Arc::new(FailingStore), clock, RegistryConfig::default()).unwrap();
        broken.records = ok.records.clone();
        assert!(broken.revoke(&d.id).is_err());
        // Still revoked in memory.
        assert_eq!(broken.authenticate(&d.token, None), Err(AuthError::Revoked));
    }

    #[test]
    fn file_store_round_trip_hashes_only_and_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("devices.json");
        let clock = Arc::new(ManualClock::new(5));
        let store = Arc::new(JsonFileTokenStore::new(&path));
        let mut reg =
            DeviceRegistry::new(store.clone(), clock.clone(), RegistryConfig::default()).unwrap();
        let d = reg.issue("Pixel 8", "android", ip("10.0.0.2")).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&*d.token), "plaintext token on disk");
        assert!(text.contains(&hex::encode(hash_token(&d.token))));
        assert!(text.contains("Pixel 8"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let mut again = DeviceRegistry::new(store, clock, RegistryConfig::default()).unwrap();
        assert_eq!(again.list().len(), 1);
        assert_eq!(
            again.authenticate(&d.token, ip("10.0.0.2")),
            Ok(d.id.clone())
        );
        assert!(again.revoke(&d.id).unwrap());

        // No stray temp files left behind.
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["devices.json".to_string()]);

        let reloaded = JsonFileTokenStore::new(&path).load().unwrap();
        assert!(reloaded[0].revoked);
    }

    #[test]
    fn file_store_missing_and_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let store = JsonFileTokenStore::new(&path);
        assert!(store.load().unwrap().is_empty());
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(store.load(), Err(StoreError::Corrupt(_))));
        std::fs::write(&path, br#"{"version":2,"devices":[]}"#).unwrap();
        assert!(matches!(store.load(), Err(StoreError::Corrupt(_))));
        std::fs::write(
            &path,
            br#"{"version":1,"devices":[{"id":"x","label":"l","token_sha256":"abcd","created":0,"last_seen":0,"last_ip":null,"platform":"web","revoked":false}]}"#,
        )
        .unwrap();
        assert!(matches!(store.load(), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn file_store_overwrite_is_atomic_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("devices.json");
        let store = JsonFileTokenStore::new(&path);
        store.save(&[]).unwrap();
        let rec = DeviceRecord {
            id: DeviceId("a".into()),
            label: "l".into(),
            token_sha256: [9; 32],
            created: 1,
            last_seen: 2,
            last_ip: Some("fd00::1".parse().unwrap()),
            platform: "ios".into(),
            revoked: false,
        };
        store.save(std::slice::from_ref(&rec)).unwrap();
        assert_eq!(store.load().unwrap(), vec![rec]);
    }

    #[test]
    fn touch_persistence_is_throttled() {
        struct Counting(Mutex<usize>, MemoryTokenStore);
        impl TokenStore for Counting {
            fn load(&self) -> Result<Vec<DeviceRecord>, StoreError> {
                self.1.load()
            }
            fn save(&self, r: &[DeviceRecord]) -> Result<(), StoreError> {
                *self.0.lock().unwrap() += 1;
                self.1.save(r)
            }
        }
        let store = Arc::new(Counting(Mutex::new(0), MemoryTokenStore::new()));
        let clock = Arc::new(ManualClock::new(0));
        let mut reg =
            DeviceRegistry::new(store.clone(), clock.clone(), RegistryConfig::default()).unwrap();
        let d = reg.issue("a", "web", None).unwrap();
        assert_eq!(*store.0.lock().unwrap(), 1);
        for _ in 0..5 {
            clock.advance(10);
            reg.authenticate(&d.token, None).unwrap();
        }
        assert_eq!(*store.0.lock().unwrap(), 1);
        clock.advance(3600);
        reg.authenticate(&d.token, None).unwrap();
        assert_eq!(*store.0.lock().unwrap(), 2);
    }
}
