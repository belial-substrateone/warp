//! The remote-access server: a TLS-only HTTP/1.1 + WebSocket listener bound to private LAN and
//! Tailscale addresses, serving the embedded PWA, the pairing endpoints and the `anonwarp.v1`
//! terminal socket on top of any [`TerminalHost`].
//!
//! Security properties enforced here (REMOTE_CONTROL.md 6.1): only addresses from
//! [`candidate_bind_addrs`] are bound (never a wildcard), each accepted peer is filtered with
//! [`peer_allowed`] before any bytes are read, TLS 1.3 is mandatory, and `Host`/`Origin` are
//! validated on every request including the WebSocket upgrade.
mod assets;
mod conn;
mod http;
mod ws;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::{Notify, Semaphore, broadcast, watch};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::cert::{CertBundle, CertError, rustls_server_config};
use crate::clock::{Clock, SystemClock};
use crate::host::TerminalHost;
use crate::netfilter::{BoundAddr, NetPolicy, candidate_bind_addrs};
use crate::pairing::{ArmedPairing, PairingId, PairingManager, PendingApproval};
use crate::protocol::{
    INPUT_BURST_BYTES, INPUT_RATE_BYTES_PER_SEC, MAX_AUTHENTICATED_SOCKETS,
    MAX_UNAUTHENTICATED_SOCKETS, SERVER_PING_INTERVAL_SECS, SILENCE_TIMEOUT_SECS,
};
use crate::ratelimit::Lockout;
use crate::tokens::{DeviceId, DeviceRecord, SharedRegistry};

pub type SharedPairing = Arc<Mutex<PairingManager>>;

const LOG: &str = "anonwarp::remote_access";

/// Largest number of simultaneously open TLS connections (all kinds).
pub const MAX_CONNECTIONS: usize = 64;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Port to bind on every accepted address. `0` picks a free port per address (tests).
    pub port: u16,
    pub policy: NetPolicy,
    /// Policy applied to accepted peers; defaults to `policy`. Differs only in tests that prove
    /// the accept-time filter drops peers the listener would otherwise bind for.
    pub peer_policy: Option<NetPolicy>,
    pub instance_id: String,
    pub pc_name: String,
    /// Reported in `welcome.server`.
    pub server_name: String,
    /// Honor `resize` requests from clients.
    pub phone_resize: bool,
    pub max_authenticated_sockets: usize,
    pub max_unauthenticated_sockets: usize,
    pub max_connections: usize,
    pub hello_deadline: Duration,
    pub ping_interval: Duration,
    pub silence_timeout: Duration,
    pub input_rate_bytes_per_sec: u64,
    pub input_burst_bytes: u64,
    /// How often interface addresses are re-scanned; `None` disables rescanning.
    pub rescan_interval: Option<Duration>,
}

impl ServerConfig {
    pub fn new(instance_id: impl Into<String>, pc_name: impl Into<String>) -> Self {
        Self {
            port: crate::protocol::DEFAULT_PORT_BASE,
            policy: NetPolicy::default(),
            peer_policy: None,
            instance_id: instance_id.into(),
            pc_name: pc_name.into(),
            server_name: format!("anonwarp {}", env!("CARGO_PKG_VERSION")),
            phone_resize: false,
            max_authenticated_sockets: MAX_AUTHENTICATED_SOCKETS,
            max_unauthenticated_sockets: MAX_UNAUTHENTICATED_SOCKETS,
            max_connections: MAX_CONNECTIONS,
            hello_deadline: Duration::from_secs(crate::protocol::HELLO_DEADLINE_SECS),
            ping_interval: Duration::from_secs(SERVER_PING_INTERVAL_SECS),
            silence_timeout: Duration::from_secs(SILENCE_TIMEOUT_SECS),
            input_rate_bytes_per_sec: INPUT_RATE_BYTES_PER_SEC,
            input_burst_bytes: INPUT_BURST_BYTES,
            rescan_interval: Some(Duration::from_secs(10)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("certificate error: {0}")]
    Cert(#[from] CertError),
    #[error("no private LAN or Tailscale address is available to listen on")]
    NoAddresses,
    #[error("cannot listen on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    pub device_id: DeviceId,
    pub label: String,
    pub ip: Option<IpAddr>,
    /// Unix seconds.
    pub since: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    SessionConnected(SessionInfo),
    SessionDisconnected {
        session: SessionInfo,
        reason: String,
    },
    /// A phone submitted the right secret and waits for a decision from
    /// [`ServerHandle::resolve_approval`].
    ApprovalRequested(PendingApproval),
    /// Devices were added or revoked.
    DevicesChanged,
    /// Pairing submissions are refused until this unix time.
    LockedOut {
        until: i64,
    },
    /// The set of listening addresses changed after an interface rescan.
    AddrsChanged(Vec<SocketAddr>),
}

struct ListenerEntry {
    bound: BoundAddr,
    local: SocketAddr,
    task: JoinHandle<()>,
}

pub(crate) struct SessionEntry {
    pub info: SessionInfo,
    pub kill: watch::Sender<Option<String>>,
}

pub(crate) struct Inner {
    pub cfg: ServerConfig,
    pub host: Arc<dyn TerminalHost>,
    pub registry: SharedRegistry,
    pub pairing: SharedPairing,
    pub clock: Arc<dyn Clock>,
    pub acceptor: TlsAcceptor,
    pub fingerprint: [u8; 32],
    pub events: broadcast::Sender<ServerEvent>,
    pub pair_notify: Notify,
    pub auth_lockout: Mutex<Lockout>,
    pub conn_sem: Arc<Semaphore>,
    pub unauth: AtomicUsize,
    next_session: AtomicU64,
    sessions: Mutex<HashMap<SessionId, SessionEntry>>,
    listeners: Mutex<Vec<ListenerEntry>>,
    background: Mutex<Vec<JoinHandle<()>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Inner {
    pub fn now(&self) -> i64 {
        self.clock.now_unix()
    }

    pub fn emit(&self, event: ServerEvent) {
        let _ = self.events.send(event);
    }

    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        lock(&self.listeners).iter().map(|l| l.local).collect()
    }

    pub fn lock_pairing(&self) -> MutexGuard<'_, PairingManager> {
        lock(&self.pairing)
    }

    pub fn lock_registry(&self) -> MutexGuard<'_, crate::tokens::DeviceRegistry> {
        lock(&self.registry)
    }

    pub fn auth_locked_for(&self) -> Option<u64> {
        lock(&self.auth_lockout).retry_after(self.now())
    }

    pub fn record_auth_failure(&self) {
        lock(&self.auth_lockout).record_failure(self.now());
    }

    pub fn session_count(&self) -> usize {
        lock(&self.sessions).len()
    }

    /// Registers an authenticated session; returns its guard and the kill-signal receiver.
    pub fn register_session(
        self: &Arc<Self>,
        device_id: DeviceId,
        label: String,
        ip: Option<IpAddr>,
    ) -> Option<(ws::SessionGuard, watch::Receiver<Option<String>>)> {
        let mut sessions = lock(&self.sessions);
        if sessions.len() >= self.cfg.max_authenticated_sockets {
            return None;
        }
        let id = SessionId(self.next_session.fetch_add(1, Ordering::Relaxed));
        let info = SessionInfo {
            id,
            device_id,
            label,
            ip,
            since: self.now(),
        };
        let (kill, rx) = watch::channel(None);
        sessions.insert(
            id,
            SessionEntry {
                info: info.clone(),
                kill,
            },
        );
        drop(sessions);
        self.emit(ServerEvent::SessionConnected(info.clone()));
        Some((ws::SessionGuard::new(self.clone(), info), rx))
    }

    pub fn session_devices(&self) -> Vec<DeviceId> {
        lock(&self.sessions)
            .values()
            .map(|e| e.info.device_id.clone())
            .collect()
    }

    pub fn remove_session(&self, id: SessionId) -> bool {
        lock(&self.sessions).remove(&id).is_some()
    }

    fn kill_where(&self, reason: &str, pred: impl Fn(&SessionInfo) -> bool) -> usize {
        let sessions = lock(&self.sessions);
        let mut n = 0;
        for e in sessions.values().filter(|e| pred(&e.info)) {
            e.kill.send_replace(Some(reason.to_string()));
            n += 1;
        }
        n
    }

    /// Binds listeners for newly appeared candidate addresses and closes those whose address
    /// vanished. In `strict` mode a port conflict is an error and an empty result is too.
    fn reconcile(self: &Arc<Self>, strict: bool) -> Result<bool, ServerError> {
        let wanted = candidate_bind_addrs(&self.cfg.policy);
        let mut changed = false;
        let mut listeners = lock(&self.listeners);
        listeners.retain(|l| {
            let keep = wanted.iter().any(|w| w.ip == l.bound.ip);
            if !keep {
                l.task.abort();
                changed = true;
                log::info!(target: LOG, "stopped listening on {}", l.local);
            }
            keep
        });
        for w in wanted {
            if listeners.iter().any(|l| l.bound.ip == w.ip) {
                continue;
            }
            let addr = SocketAddr::new(w.ip, self.cfg.port);
            let bound = std::net::TcpListener::bind(addr)
                .and_then(|l| l.set_nonblocking(true).map(|()| l))
                .and_then(tokio::net::TcpListener::from_std);
            let listener = match bound {
                Ok(l) => l,
                Err(source) if strict && source.kind() == std::io::ErrorKind::AddrInUse => {
                    for l in listeners.drain(..) {
                        l.task.abort();
                    }
                    return Err(ServerError::Bind { addr, source });
                }
                Err(err) => {
                    log::warn!(target: LOG, "cannot listen on {addr}: {err}");
                    continue;
                }
            };
            let local = listener.local_addr().unwrap_or(addr);
            log::info!(target: LOG, "listening on https://{local} ({:?} on {})", w.kind, w.iface);
            let task = tokio::spawn(conn::accept_loop(
                self.clone(),
                listener,
                w.clone(),
                local,
                http::router(self.clone()),
            ));
            listeners.push(ListenerEntry {
                bound: w,
                local,
                task,
            });
            changed = true;
        }
        if strict && listeners.is_empty() {
            return Err(ServerError::NoAddresses);
        }
        Ok(changed)
    }
}

/// Entry point; see [`Server::start`].
pub struct Server;

impl Server {
    /// Binds the listeners and starts serving. Must be called inside a tokio runtime.
    ///
    /// `registry` and `pairing` are shared with the caller (the pairing manager must have been
    /// built on the same registry so approved devices authenticate).
    pub async fn start(
        config: ServerConfig,
        host: Arc<dyn TerminalHost>,
        registry: SharedRegistry,
        pairing: SharedPairing,
        cert: &CertBundle,
    ) -> Result<ServerHandle, ServerError> {
        let acceptor = TlsAcceptor::from(rustls_server_config(cert)?);
        let (events, _) = broadcast::channel(128);
        let max_connections = config.max_connections.max(1);
        let rescan = config.rescan_interval;
        let inner = Arc::new(Inner {
            cfg: config,
            host,
            registry,
            pairing,
            clock: Arc::new(SystemClock),
            acceptor,
            fingerprint: cert.fingerprint(),
            events,
            pair_notify: Notify::new(),
            auth_lockout: Mutex::new(Lockout::new(vec![10, 30, 60, 300], 10)),
            conn_sem: Arc::new(Semaphore::new(max_connections)),
            unauth: AtomicUsize::new(0),
            next_session: AtomicU64::new(1),
            sessions: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            background: Mutex::new(Vec::new()),
        });
        inner.reconcile(true)?;

        let mut background = vec![tokio::spawn(ws::revocation_watch(inner.clone()))];
        if let Some(every) = rescan {
            let weak = Arc::downgrade(&inner);
            background.push(tokio::spawn(async move {
                let mut tick = tokio::time::interval(every);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let Some(inner) = weak.upgrade() else { return };
                    if let Ok(true) = inner.reconcile(false) {
                        inner.emit(ServerEvent::AddrsChanged(inner.bound_sockets()));
                    }
                }
            }));
        }
        *lock(&inner.background) = background;
        Ok(ServerHandle { inner })
    }
}

/// Cheap, cloneable control surface of a running server.
#[derive(Clone)]
pub struct ServerHandle {
    inner: Arc<Inner>,
}

impl ServerHandle {
    /// Socket addresses currently being listened on.
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    pub fn bound_addrs(&self) -> Vec<BoundAddr> {
        lock(&self.inner.listeners)
            .iter()
            .map(|l| l.bound.clone())
            .collect()
    }

    /// SHA-256 of the leaf certificate DER.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.inner.fingerprint
    }

    pub fn instance_id(&self) -> &str {
        &self.inner.cfg.instance_id
    }

    pub fn pc_name(&self) -> &str {
        &self.inner.cfg.pc_name
    }

    /// Generates a fresh one-time pairing secret (replacing any live one).
    pub fn arm_pairing(&self) -> ArmedPairing {
        self.inner.lock_pairing().arm()
    }

    pub fn disarm_pairing(&self) {
        self.inner.lock_pairing().disarm();
    }

    pub fn is_pairing_armed(&self) -> bool {
        self.inner.lock_pairing().is_armed()
    }

    pub fn pending_approvals(&self) -> Vec<PendingApproval> {
        self.inner.lock_pairing().pending_approvals()
    }

    /// The PC user's decision on a pairing request. Returns the new device on approval.
    pub fn resolve_approval(&self, id: &PairingId, approve: bool) -> Option<DeviceRecord> {
        let record = self.inner.lock_pairing().resolve(id, approve);
        self.inner.pair_notify.notify_waiters();
        if record.is_some() {
            self.inner.emit(ServerEvent::DevicesChanged);
        }
        record
    }

    pub fn sessions(&self) -> Vec<SessionInfo> {
        let mut v: Vec<_> = lock(&self.inner.sessions)
            .values()
            .map(|e| e.info.clone())
            .collect();
        v.sort_by_key(|s| s.id);
        v
    }

    pub fn kill_session(&self, id: SessionId) -> bool {
        self.inner.kill_where("killed from the PC", |s| s.id == id) > 0
    }

    /// Closes every session of `device` with code 4403 (the device stays paired).
    pub fn kick(&self, device: &DeviceId) -> usize {
        self.inner
            .kill_where("disconnected from the PC", |s| &s.device_id == device)
    }

    /// Kill switch: closes every session with code 4403. Devices stay paired.
    pub fn kill_all(&self) -> usize {
        self.inner.kill_where("killed from the PC", |_| true)
    }

    /// Revokes `device` in the registry and closes its sessions.
    pub fn revoke_device(&self, device: &DeviceId) -> bool {
        let revoked = self.inner.lock_registry().revoke(device).unwrap_or(true);
        self.inner
            .kill_where("device revoked", |s| &s.device_id == device);
        self.inner.emit(ServerEvent::DevicesChanged);
        revoked
    }

    /// Revokes every device and closes every session.
    pub fn revoke_all(&self) -> usize {
        let n = self.inner.lock_registry().revoke_all().unwrap_or(0);
        self.inner.kill_where("device revoked", |_| true);
        self.inner.emit(ServerEvent::DevicesChanged);
        n
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<ServerEvent> {
        self.inner.events.subscribe()
    }

    /// Closes every session (code 4403), then stops listening. Idempotent.
    pub async fn shutdown(&self) {
        self.inner.kill_where("server stopped", |_| true);
        for _ in 0..20 {
            if self.inner.session_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let background: Vec<_> = lock(&self.inner.background).drain(..).collect();
        // Aborting an accept loop drops its connection set, closing every remaining socket.
        let listeners: Vec<_> = lock(&self.inner.listeners)
            .drain(..)
            .map(|l| l.task)
            .collect();
        for t in background.into_iter().chain(listeners) {
            t.abort();
            let _ = t.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_follow_the_spec() {
        let c = ServerConfig::new("id", "pc");
        assert_eq!(c.port, 9477);
        assert!(!c.policy.allow_loopback);
        assert!(!c.phone_resize);
        assert_eq!(c.max_authenticated_sockets, 4);
        assert_eq!(c.hello_deadline, Duration::from_secs(3));
    }
}
