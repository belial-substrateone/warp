//! Pairing state machine (REMOTE_CONTROL.md 6.1):
//! `Idle -> Armed{secret, expires} -> AwaitingApproval -> Paired | Failed`.
//!
//! * The secret is 32 bytes from `OsRng` (base64url), valid for `arm_ttl_secs`
//!   (120 s), single use, and only one is live at a time.
//! * It is compared in constant time and consumed on the first correct
//!   submission, even if the PC user then denies.
//! * `max_wrong_secrets` (3) wrong guesses invalidate the armed secret.
//! * Failures feed a global escalating lockout (30 s, 1 m, 5 m, 30 m) and a
//!   global rate limit (5 submissions per minute). Counters are global, not
//!   per-IP, because LAN source addresses are spoofable.
//! * The device token is issued only on approval and handed out exactly once,
//!   via [`PairingManager::poll`].
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use base64::Engine as _;
use rand::RngCore as _;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::ratelimit::{Lockout, SlidingWindow};
use crate::tokens::{DeviceRecord, IssuedDevice, SharedRegistry};

pub const ARM_TTL_SECS: i64 = 120;
pub const PLATFORMS: [&str; 3] = ["android", "web", "ios"];
const MAX_DEVICE_NAME: usize = 64;

#[derive(Debug, Clone)]
pub struct PairingConfig {
    pub arm_ttl_secs: i64,
    pub max_wrong_secrets: u32,
    pub require_approval: bool,
    /// How long an unanswered approval prompt, or an approved-but-uncollected
    /// token, stays alive.
    pub approval_timeout_secs: i64,
    pub max_submits_per_minute: usize,
    pub lockout_schedule: Vec<u64>,
}

impl Default for PairingConfig {
    fn default() -> Self {
        Self {
            arm_ttl_secs: ARM_TTL_SECS,
            max_wrong_secrets: 3,
            require_approval: true,
            approval_timeout_secs: 120,
            max_submits_per_minute: 5,
            lockout_schedule: Lockout::DEFAULT_SCHEDULE.to_vec(),
        }
    }
}

/// What `arm()` returns for the PC UI to turn into a QR code.
pub struct ArmedPairing {
    /// base64url, 43 characters.
    pub secret: Zeroizing<String>,
    pub expires_at: i64,
}

impl fmt::Debug for ArmedPairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArmedPairing")
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequest {
    pub device_name: String,
    pub platform: String,
    pub ip: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PairingId(pub String);

impl fmt::Display for PairingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairError {
    #[error("pairing is not armed")]
    NotArmed,
    #[error("pairing secret expired")]
    Expired,
    #[error("wrong pairing secret")]
    BadSecret,
    #[error("locked out, retry in {retry_after}s")]
    Locked { retry_after: u64 },
    #[error("too many requests, retry in {retry_after}s")]
    RateLimited { retry_after: u64 },
    #[error("invalid pairing request: {0}")]
    InvalidRequest(&'static str),
    #[error("internal error: {0}")]
    Internal(String),
}

impl PairError {
    /// Seconds to report in a `429` body, if this is a throttling error.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Locked { retry_after } | Self::RateLimited { retry_after } => Some(*retry_after),
            _ => None,
        }
    }
}

pub enum PairPoll {
    Pending,
    Approved(IssuedDevice),
    Denied,
    /// Also returned for unknown ids and for tokens already collected.
    Expired,
}

impl fmt::Debug for PairPoll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("Pending"),
            Self::Approved(d) => write!(f, "Approved({d:?})"),
            Self::Denied => f.write_str("Denied"),
            Self::Expired => f.write_str("Expired"),
        }
    }
}

/// Coarse state for UIs and `/v1/info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    Idle,
    Armed { expires_at: i64 },
    AwaitingApproval { count: usize },
}

/// A request waiting for the PC user's approve/deny decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    pub id: PairingId,
    pub device_name: String,
    pub platform: String,
    pub ip: Option<IpAddr>,
    pub requested_at: i64,
}

enum Status {
    Awaiting,
    Approved(IssuedDevice),
    Denied,
}

struct Pending {
    req: PairRequest,
    created: i64,
    /// When the current status was entered (drives expiry of every status).
    since: i64,
    status: Status,
}

enum Armed {
    Idle,
    /// The last secret timed out; reported once as `Expired` to a late phone.
    Expired,
    Live {
        secret: Zeroizing<String>,
        expires_at: i64,
        wrong: u32,
    },
}

pub struct PairingManager {
    cfg: PairingConfig,
    clock: Arc<dyn Clock>,
    registry: SharedRegistry,
    armed: Armed,
    pending: HashMap<PairingId, Pending>,
    lockout: Lockout,
    window: SlidingWindow,
}

fn random_b64url() -> Zeroizing<String> {
    let mut b = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *b);
    Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*b))
}

fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_DEVICE_NAME)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "Unnamed device".to_string()
    } else {
        cleaned.to_string()
    }
}

impl PairingManager {
    /// `registry` is where approved devices are issued.
    pub fn new(cfg: PairingConfig, clock: Arc<dyn Clock>, registry: SharedRegistry) -> Self {
        let lockout = Lockout::new(cfg.lockout_schedule.clone(), cfg.max_wrong_secrets.max(1));
        let window = SlidingWindow::new(cfg.max_submits_per_minute, 60);
        Self {
            cfg,
            clock,
            registry,
            armed: Armed::Idle,
            pending: HashMap::new(),
            lockout,
            window,
        }
    }

    /// Generates a new secret, replacing any live one.
    pub fn arm(&mut self) -> ArmedPairing {
        self.gc();
        let secret = random_b64url();
        let expires_at = self.clock.now_unix() + self.cfg.arm_ttl_secs;
        self.armed = Armed::Live {
            secret: secret.clone(),
            expires_at,
            wrong: 0,
        };
        ArmedPairing { secret, expires_at }
    }

    /// Cancels the live secret (QR hidden, window blurred, feature disabled).
    pub fn disarm(&mut self) {
        self.armed = Armed::Idle;
    }

    pub fn state(&mut self) -> PairingState {
        self.gc();
        let awaiting = self
            .pending
            .values()
            .filter(|p| matches!(p.status, Status::Awaiting))
            .count();
        match &self.armed {
            Armed::Live { expires_at, .. } => PairingState::Armed {
                expires_at: *expires_at,
            },
            Armed::Idle | Armed::Expired if awaiting > 0 => {
                PairingState::AwaitingApproval { count: awaiting }
            }
            Armed::Idle | Armed::Expired => PairingState::Idle,
        }
    }

    pub fn is_armed(&mut self) -> bool {
        matches!(self.state(), PairingState::Armed { .. })
    }

    /// Unix time until which submissions are refused, if locked out.
    pub fn locked_until(&self) -> Option<i64> {
        self.lockout.locked_until(self.clock.now_unix())
    }

    /// PC-side explicit unlock (the user is physically present).
    pub fn reset_lockout(&mut self) {
        self.lockout.reset();
    }

    pub fn pending_approvals(&mut self) -> Vec<PendingApproval> {
        self.gc();
        let mut v: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| matches!(p.status, Status::Awaiting))
            .map(|(id, p)| PendingApproval {
                id: id.clone(),
                device_name: p.req.device_name.clone(),
                platform: p.req.platform.clone(),
                ip: p.req.ip,
                requested_at: p.created,
            })
            .collect();
        v.sort_by_key(|p| p.requested_at);
        v
    }

    /// Handles `POST /v1/pair`. On success the armed secret has been consumed.
    pub fn submit(&mut self, secret: &str, req: PairRequest) -> Result<PairingId, PairError> {
        let now = self.clock.now_unix();
        self.gc();

        if let Some(retry_after) = self.lockout.retry_after(now) {
            return Err(PairError::Locked { retry_after });
        }
        if let Err(retry_after) = self.window.check(now) {
            return Err(PairError::RateLimited { retry_after });
        }
        if !PLATFORMS.contains(&req.platform.as_str()) {
            return Err(PairError::InvalidRequest("unknown platform"));
        }

        let Armed::Live {
            secret: armed,
            wrong,
            ..
        } = &mut self.armed
        else {
            return Err(if matches!(self.armed, Armed::Expired) {
                PairError::Expired
            } else {
                PairError::NotArmed
            });
        };

        let matches = bool::from(secret.as_bytes().ct_eq(armed.as_bytes()));
        if !matches {
            *wrong += 1;
            if *wrong >= self.cfg.max_wrong_secrets {
                self.armed = Armed::Idle;
            }
            self.lockout.record_failure(now);
            return Err(PairError::BadSecret);
        }

        // Correct: consume immediately (single use, even if approval is denied).
        self.armed = Armed::Idle;
        self.lockout.reset();

        let req = PairRequest {
            device_name: sanitize_name(&req.device_name),
            ..req
        };
        let id = PairingId({
            let mut b = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut b);
            hex::encode(b)
        });
        let status = if self.cfg.require_approval {
            Status::Awaiting
        } else {
            Status::Approved(self.issue(&req)?)
        };
        self.pending.insert(
            id.clone(),
            Pending {
                req,
                created: now,
                since: now,
                status,
            },
        );
        Ok(id)
    }

    fn issue(&self, req: &PairRequest) -> Result<IssuedDevice, PairError> {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .issue(&req.device_name, &req.platform, req.ip)
            .map_err(|e| PairError::Internal(e.to_string()))
    }

    /// PC user's decision. Returns the registered device on approval (the token
    /// itself is only available through [`poll`](Self::poll)).
    pub fn resolve(&mut self, id: &PairingId, approve: bool) -> Option<DeviceRecord> {
        self.gc();
        let now = self.clock.now_unix();
        let req = {
            let p = self.pending.get(id)?;
            if !matches!(p.status, Status::Awaiting) {
                return None;
            }
            p.req.clone()
        };
        let issued = if approve { self.issue(&req).ok() } else { None };
        let p = self.pending.get_mut(id)?;
        p.since = now;
        match issued {
            Some(d) => {
                let record = d.record.clone();
                p.status = Status::Approved(d);
                Some(record)
            }
            None => {
                p.status = Status::Denied;
                None
            }
        }
    }

    /// Phone-side poll. `Approved` is returned once; afterwards the id is gone.
    pub fn poll(&mut self, id: &PairingId) -> PairPoll {
        self.gc();
        let Some(p) = self.pending.get(id) else {
            return PairPoll::Expired;
        };
        match p.status {
            Status::Awaiting => PairPoll::Pending,
            Status::Denied | Status::Approved(_) => {
                let p = self.pending.remove(id).map(|p| p.status);
                match p {
                    Some(Status::Approved(d)) => PairPoll::Approved(d),
                    _ => PairPoll::Denied,
                }
            }
        }
    }

    /// Expires secrets, unanswered prompts and uncollected tokens.
    fn gc(&mut self) {
        let now = self.clock.now_unix();
        if let Armed::Live { expires_at, .. } = &self.armed
            && now >= *expires_at
        {
            self.armed = Armed::Expired;
        }
        let timeout = self.cfg.approval_timeout_secs;
        let expired: Vec<PairingId> = self
            .pending
            .iter()
            .filter(|(_, p)| now - p.since >= timeout)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(Pending {
                status: Status::Approved(d),
                ..
            }) = self.pending.remove(&id)
            {
                // The phone never collected its token; it can never use it.
                let _ = self
                    .registry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .revoke(&d.id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::tokens::{DeviceRegistry, MemoryTokenStore, RegistryConfig};
    use std::sync::Mutex;

    struct Fixture {
        mgr: PairingManager,
        clock: Arc<ManualClock>,
        registry: SharedRegistry,
    }

    fn fixture(cfg: PairingConfig) -> Fixture {
        let clock = Arc::new(ManualClock::new(1_000_000));
        let registry: SharedRegistry = Arc::new(Mutex::new(
            DeviceRegistry::new(
                Arc::new(MemoryTokenStore::new()),
                clock.clone(),
                RegistryConfig::default(),
            )
            .unwrap(),
        ));
        let mgr = PairingManager::new(cfg, clock.clone(), registry.clone());
        Fixture {
            mgr,
            clock,
            registry,
        }
    }

    fn req() -> PairRequest {
        PairRequest {
            device_name: "Pixel 8".into(),
            platform: "android".into(),
            ip: Some("192.168.1.9".parse().unwrap()),
        }
    }

    #[test]
    fn happy_path_with_approval_and_token_once() {
        let mut f = fixture(PairingConfig::default());
        assert_eq!(f.mgr.state(), PairingState::Idle);
        let armed = f.mgr.arm();
        assert_eq!(armed.secret.len(), 43);
        assert_eq!(armed.expires_at, 1_000_120);
        assert!(f.mgr.is_armed());

        let id = f.mgr.submit(&armed.secret, req()).unwrap();
        assert_eq!(f.mgr.state(), PairingState::AwaitingApproval { count: 1 });
        assert!(matches!(f.mgr.poll(&id), PairPoll::Pending));
        let pending = f.mgr.pending_approvals();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].device_name, "Pixel 8");
        assert_eq!(pending[0].ip, req().ip);

        let rec = f.mgr.resolve(&id, true).unwrap();
        assert_eq!(rec.label, "Pixel 8");
        assert_eq!(f.registry.lock().unwrap().list().len(), 1);

        let PairPoll::Approved(dev) = f.mgr.poll(&id) else {
            panic!("expected approved")
        };
        assert_eq!(dev.id, rec.id);
        assert_eq!(dev.token.len(), 43);
        assert!(
            f.registry
                .lock()
                .unwrap()
                .authenticate(&dev.token, None)
                .is_ok()
        );
        // Token is returned once.
        assert!(matches!(f.mgr.poll(&id), PairPoll::Expired));
        assert_eq!(f.mgr.state(), PairingState::Idle);
    }

    #[test]
    fn secret_expires_with_fake_clock() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        f.clock.advance(119);
        assert!(f.mgr.is_armed());
        f.clock.advance(1);
        assert!(!f.mgr.is_armed());
        assert_eq!(f.mgr.submit(&armed.secret, req()), Err(PairError::Expired));
        assert_eq!(f.mgr.submit("x", req()), Err(PairError::Expired));
        f.mgr.disarm();
        assert_eq!(f.mgr.submit(&armed.secret, req()), Err(PairError::NotArmed));
        // Fresh arm works again.
        let armed = f.mgr.arm();
        assert!(f.mgr.submit(&armed.secret, req()).is_ok());
    }

    #[test]
    fn secret_is_single_use() {
        let mut f = fixture(PairingConfig {
            require_approval: false,
            ..PairingConfig::default()
        });
        let armed = f.mgr.arm();
        let id = f.mgr.submit(&armed.secret, req()).unwrap();
        assert_eq!(f.mgr.submit(&armed.secret, req()), Err(PairError::NotArmed));
        assert!(matches!(f.mgr.poll(&id), PairPoll::Approved(_)));
    }

    #[test]
    fn secret_consumed_even_when_denied() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        let id = f.mgr.submit(&armed.secret, req()).unwrap();
        assert!(f.mgr.resolve(&id, false).is_none());
        assert!(matches!(f.mgr.poll(&id), PairPoll::Denied));
        assert!(matches!(f.mgr.poll(&id), PairPoll::Expired));
        assert!(f.registry.lock().unwrap().list().is_empty());
        assert_eq!(f.mgr.submit(&armed.secret, req()), Err(PairError::NotArmed));
    }

    #[test]
    fn re_arm_replaces_previous_secret() {
        let mut f = fixture(PairingConfig::default());
        let first = f.mgr.arm();
        let second = f.mgr.arm();
        assert_ne!(*first.secret, *second.secret);
        assert_eq!(
            f.mgr.submit(&first.secret, req()),
            Err(PairError::BadSecret)
        );
        assert!(f.mgr.submit(&second.secret, req()).is_ok());
    }

    #[test]
    fn three_wrong_secrets_invalidate_armed_secret() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        for _ in 0..3 {
            assert_eq!(f.mgr.submit("nope", req()), Err(PairError::BadSecret));
        }
        // Locked now (3 failures = first lockout step), and the secret is gone.
        assert_eq!(
            f.mgr.submit(&armed.secret, req()),
            Err(PairError::Locked { retry_after: 30 })
        );
        f.clock.advance(30);
        assert_eq!(f.mgr.submit(&armed.secret, req()), Err(PairError::NotArmed));
        assert!(!f.mgr.is_armed());
    }

    #[test]
    fn two_wrong_then_right_still_works_and_resets() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        assert_eq!(f.mgr.submit("a", req()), Err(PairError::BadSecret));
        assert_eq!(f.mgr.submit("b", req()), Err(PairError::BadSecret));
        assert!(f.mgr.submit(&armed.secret, req()).is_ok());
        assert!(f.mgr.locked_until().is_none());
    }

    #[test]
    fn lockout_schedule_escalates() {
        let mut f = fixture(PairingConfig {
            max_submits_per_minute: 1000,
            ..PairingConfig::default()
        });
        let mut waits = vec![];
        for _ in 0..5 {
            f.mgr.arm();
            for _ in 0..3 {
                let _ = f.mgr.submit("bad", req());
            }
            let Err(PairError::Locked { retry_after }) = f.mgr.submit("bad", req()) else {
                panic!("expected lockout")
            };
            waits.push(retry_after);
            assert!(f.mgr.locked_until().is_some());
            f.clock.advance(retry_after as i64);
        }
        assert_eq!(waits, vec![30, 60, 300, 1800, 1800]);
    }

    #[test]
    fn correct_secret_rejected_while_locked_and_not_consumed() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        for _ in 0..3 {
            let _ = f.mgr.submit("bad", req());
        }
        // Re-arm during lockout (PC user), then the correct secret is still refused.
        let again = f.mgr.arm();
        assert!(matches!(
            f.mgr.submit(&again.secret, req()),
            Err(PairError::Locked { .. })
        ));
        let _ = armed;
        f.clock.advance(31);
        assert!(
            f.mgr.submit(&again.secret, req()).is_ok(),
            "secret survived the lockout"
        );
    }

    #[test]
    fn reset_lockout_unlocks() {
        let mut f = fixture(PairingConfig::default());
        f.mgr.arm();
        for _ in 0..3 {
            let _ = f.mgr.submit("bad", req());
        }
        assert!(f.mgr.locked_until().is_some());
        f.mgr.reset_lockout();
        let armed = f.mgr.arm();
        assert!(f.mgr.submit(&armed.secret, req()).is_ok());
    }

    #[test]
    fn rate_limit_five_per_minute() {
        let mut f = fixture(PairingConfig {
            lockout_schedule: vec![1],
            max_wrong_secrets: 1000,
            ..PairingConfig::default()
        });
        f.mgr.arm();
        for _ in 0..5 {
            assert_eq!(f.mgr.submit("bad", req()), Err(PairError::BadSecret));
        }
        let e = f.mgr.submit("bad", req()).unwrap_err();
        assert!(matches!(e, PairError::RateLimited { .. }));
        assert_eq!(e.retry_after(), Some(60));
        f.clock.advance(60);
        assert_eq!(f.mgr.submit("bad", req()), Err(PairError::BadSecret));
    }

    #[test]
    fn not_armed_does_not_feed_lockout() {
        let mut f = fixture(PairingConfig {
            max_submits_per_minute: 1000,
            ..PairingConfig::default()
        });
        for _ in 0..20 {
            assert_eq!(f.mgr.submit("x", req()), Err(PairError::NotArmed));
        }
        assert!(f.mgr.locked_until().is_none());
    }

    #[test]
    fn tamper_cases() {
        let mut f = fixture(PairingConfig {
            max_wrong_secrets: 100,
            max_submits_per_minute: 1000,
            ..PairingConfig::default()
        });
        let armed = f.mgr.arm();
        let s = armed.secret.to_string();
        let mut flipped = s.clone().into_bytes();
        flipped[10] = if flipped[10] == b'A' { b'B' } else { b'A' };
        let truncated = s[..42].to_string();
        let extended = format!("{s}A");
        let upper = s.to_uppercase();
        for bad in [
            String::from_utf8(flipped).unwrap(),
            truncated,
            extended,
            upper,
            String::new(),
            format!(" {s}"),
            format!("{s}\n"),
        ] {
            assert_eq!(
                f.mgr.submit(&bad, req()),
                Err(PairError::BadSecret),
                "{bad:?}"
            );
        }
        assert!(f.mgr.submit(&s, req()).is_ok());
    }

    #[test]
    fn invalid_requests_do_not_consume_secret() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        let mut bad = req();
        bad.platform = "toaster".into();
        assert!(matches!(
            f.mgr.submit(&armed.secret, bad),
            Err(PairError::InvalidRequest(_))
        ));
        assert!(f.mgr.submit(&armed.secret, req()).is_ok());
    }

    #[test]
    fn device_name_sanitized() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        let mut r = req();
        r.device_name = format!("a\u{7}b\n{}", "z".repeat(200));
        let id = f.mgr.submit(&armed.secret, r).unwrap();
        let p = f.mgr.pending_approvals().remove(0);
        assert_eq!(p.id, id);
        assert!(p.device_name.chars().count() <= 64);
        assert!(!p.device_name.chars().any(char::is_control));
        assert!(p.device_name.starts_with("a b "));

        let armed = f.mgr.arm();
        let mut r = req();
        r.device_name = " \n ".into();
        f.mgr.submit(&armed.secret, r).unwrap();
        assert!(
            f.mgr
                .pending_approvals()
                .iter()
                .any(|p| p.device_name == "Unnamed device")
        );
    }

    #[test]
    fn unanswered_prompt_expires_and_cannot_be_approved() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        let id = f.mgr.submit(&armed.secret, req()).unwrap();
        f.clock.advance(120);
        assert!(matches!(f.mgr.poll(&id), PairPoll::Expired));
        assert!(f.mgr.resolve(&id, true).is_none());
        assert!(f.registry.lock().unwrap().list().is_empty());
    }

    #[test]
    fn uncollected_token_is_revoked_after_timeout() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        let id = f.mgr.submit(&armed.secret, req()).unwrap();
        f.mgr.resolve(&id, true).unwrap();
        assert_eq!(f.registry.lock().unwrap().list().len(), 1);
        f.clock.advance(121);
        assert!(matches!(f.mgr.poll(&id), PairPoll::Expired));
        assert!(f.registry.lock().unwrap().list().is_empty());
    }

    #[test]
    fn resolve_twice_and_unknown_id() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        let id = f.mgr.submit(&armed.secret, req()).unwrap();
        assert!(f.mgr.resolve(&id, true).is_some());
        assert!(f.mgr.resolve(&id, true).is_none());
        assert!(f.mgr.resolve(&PairingId("zzz".into()), true).is_none());
        assert!(matches!(
            f.mgr.poll(&PairingId("zzz".into())),
            PairPoll::Expired
        ));
    }

    #[test]
    fn disarm_cancels() {
        let mut f = fixture(PairingConfig::default());
        let armed = f.mgr.arm();
        f.mgr.disarm();
        assert_eq!(f.mgr.submit(&armed.secret, req()), Err(PairError::NotArmed));
    }

    #[test]
    fn without_approval_issues_immediately() {
        let mut f = fixture(PairingConfig {
            require_approval: false,
            ..PairingConfig::default()
        });
        let armed = f.mgr.arm();
        let id = f.mgr.submit(&armed.secret, req()).unwrap();
        assert!(f.mgr.pending_approvals().is_empty());
        assert!(matches!(f.mgr.poll(&id), PairPoll::Approved(_)));
    }

    #[test]
    fn secrets_are_unique_and_redacted() {
        let mut f = fixture(PairingConfig::default());
        let a = f.mgr.arm();
        let b = f.mgr.arm();
        assert_ne!(*a.secret, *b.secret);
        assert!(!format!("{a:?}").contains(&*a.secret));
    }
}
