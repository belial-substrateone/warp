//! The `RemoteAccessService` singleton: owns the server, pairing manager and device registry and
//! exposes the API the GUI and TUI use.
//!
//! The server runs on a private tokio runtime (like `http_server`) and is started and stopped
//! synchronously from the main thread: binding is immediate and shutdown is bounded by a short
//! drain of live sessions. Server events travel back to the main thread through an unbounded
//! channel and become [`RemoteAccessEvent`]s.
//!
//! State lives in `<secure_state_dir or state_dir>/remote_access/`:
//! - `identity.json`: the persistent TLS certificate and private key plus the instance id
//!   (mode 0600; replaced atomically).
//! - `devices.json`: paired devices, token hashes only (mode 0600).
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ::remote_access::TerminalHost;
use ::remote_access::cert::{CertBundle, fingerprint_display, generate_self_signed};
use ::remote_access::clock::{Clock, SystemClock};
use ::remote_access::netfilter::{AddrKind, NetPolicy, candidate_bind_addrs};
use ::remote_access::pairing::{PairingConfig, PairingId, PairingManager, PendingApproval};
use ::remote_access::qr::QrPayload;
use ::remote_access::server::{Server, ServerConfig, ServerEvent, ServerHandle};
use ::remote_access::tokens::{
    DeviceId, DeviceRecord, DeviceRegistry, JsonFileTokenStore, RegistryConfig, SharedRegistry,
};
use anyhow::{Context as _, anyhow};
use base64::Engine as _;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use serde::{Deserialize, Serialize};
use warp_core::channel::{Channel, ChannelState};
use warpui::{Entity, ModelContext, SingletonEntity};

use super::api::{ActiveSession, PairingQr, RemoteAccessEvent};
use super::terminal_host::AppTerminalHost;

const STATE_SUBDIR: &str = "remote_access";
const IDENTITY_FILE: &str = "identity.json";
const DEVICES_FILE: &str = "devices.json";
const CERT_VALID_DAYS: u32 = 5 * 365;
const CERT_NAME: &str = "AnonWarp Remote Access";
const PORT_BASE: u16 = 9477;
const PORT_ENV: &str = "ANONWARP_REMOTE_PORT";

/// Default listening port: 9477 plus the same per-channel offset as the local HTTP server.
pub fn default_port() -> u16 {
    if let Some(port) = std::env::var(PORT_ENV)
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p != 0)
    {
        return port;
    }
    PORT_BASE
        + match ChannelState::channel() {
            Channel::Stable => 0,
            Channel::Preview => 1,
            Channel::Dev => 2,
            Channel::Local => 3,
            Channel::Integration => 4,
            Channel::Oss => 5,
        }
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    instance_id: String,
    cert_der_b64: String,
    key_pkcs8_b64: String,
}

struct Identity {
    instance_id: String,
    cert: CertBundle,
}

impl Identity {
    fn generate(instance_id: Option<String>) -> anyhow::Result<Self> {
        let ips: Vec<_> = candidate_bind_addrs(&NetPolicy::default())
            .iter()
            .map(|b| b.ip)
            .collect();
        let cert = generate_self_signed(&ips, CERT_NAME, CERT_VALID_DAYS)
            .map_err(|e| anyhow!("generating the certificate: {e}"))?;
        let instance_id = instance_id.unwrap_or_else(|| {
            let mut id = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
            hex::encode(id)
        });
        Ok(Self { instance_id, cert })
    }

    fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("reading the identity file"),
        };
        let f: IdentityFile =
            serde_json::from_slice(&bytes).context("parsing the identity file")?;
        anyhow::ensure!(
            f.version == 1,
            "unsupported identity file version {}",
            f.version
        );
        let b64 = base64::engine::general_purpose::STANDARD;
        let cert = CertBundle::from_der(
            b64.decode(&f.cert_der_b64)
                .context("decoding the certificate")?,
            b64.decode(&f.key_pkcs8_b64)
                .context("decoding the private key")?,
        )
        .map_err(|e| anyhow!("invalid stored certificate: {e}"))?;
        Ok(Some(Self {
            instance_id: f.instance_id,
            cert,
        }))
    }

    fn save(&self, path: &Path) -> anyhow::Result<()> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let json = serde_json::to_vec_pretty(&IdentityFile {
            version: 1,
            instance_id: self.instance_id.clone(),
            cert_der_b64: b64.encode(&self.cert.cert_der),
            key_pkcs8_b64: b64.encode(self.cert.key_der_pkcs8.as_slice()),
        })?;
        write_private_file(path, &json)
    }
}

/// Atomically writes `contents` to `path` with owner-only permissions.
fn write_private_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    let dir = path.parent().context("identity path has no parent")?;
    std::fs::create_dir_all(dir)?;
    let mut suffix = [0u8; 6];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut suffix);
    let tmp = dir.join(format!(".identity.{}.tmp", hex::encode(suffix)));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.context("writing the identity file")
}

fn state_dir() -> PathBuf {
    warp_core::paths::secure_state_dir()
        .unwrap_or_else(warp_core::paths::state_dir)
        .join(STATE_SUBDIR)
}

fn pc_name() -> String {
    #[cfg(unix)]
    let name = nix::unistd::gethostname()
        .ok()
        .map(|h| h.to_string_lossy().into_owned());
    #[cfg(not(unix))]
    let name = std::env::var("COMPUTERNAME").ok();
    name.filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "AnonWarp PC".to_string())
}

/// Everything that exists only while the server is running.
struct Running {
    handle: ServerHandle,
    host: Arc<dyn TerminalHost>,
    event_pump: tokio::task::JoinHandle<()>,
}

pub struct RemoteAccessService {
    state_dir: PathBuf,
    port: u16,
    runtime: Option<tokio::runtime::Runtime>,
    registry: Option<SharedRegistry>,
    identity: Option<Identity>,
    running: Option<Running>,
    last_error: Option<String>,
    /// Builds the terminal host when the server starts; the GUI's host when unset.
    host_factory: Option<HostFactory>,
}

/// Front-ends other than the GUI (the headless TUI) supply their own terminal host.
pub type HostFactory = Box<dyn Fn(&mut ModelContext<RemoteAccessService>) -> Arc<dyn TerminalHost>>;

impl RemoteAccessService {
    pub fn new(ctx: &mut ModelContext<Self>) -> Self {
        Self::with_state_dir(state_dir(), ctx)
    }

    fn with_state_dir(state_dir: PathBuf, _ctx: &mut ModelContext<Self>) -> Self {
        let registry = match open_registry(&state_dir) {
            Ok(r) => Some(r),
            Err(err) => {
                log::error!("remote access: cannot open the device registry: {err:#}");
                None
            }
        };
        let identity = match Identity::load(&state_dir.join(IDENTITY_FILE)) {
            Ok(i) => i,
            Err(err) => {
                log::warn!("remote access: ignoring unreadable identity: {err:#}");
                None
            }
        };
        Self {
            state_dir,
            port: default_port(),
            runtime: None,
            registry,
            identity,
            running: None,
            last_error: None,
            host_factory: None,
        }
    }

    /// Replaces how the terminal host is built the next time the server starts.
    pub fn set_host_factory(&mut self, factory: HostFactory) {
        self.host_factory = Some(factory);
    }

    /// Whether the remote-access server is running. Off by default and not persisted across
    /// restarts.
    pub fn is_enabled(&self) -> bool {
        self.running.is_some()
    }

    /// Why the last attempt to start the server failed, if it did. Cleared by a successful start
    /// and by disabling.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Port used the next time the server starts (default: 9477 plus the channel offset).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Changes the port for the next start. Does not restart a running server.
    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    /// Start or stop the server. Stopping also disarms pairing and closes every session.
    pub fn set_enabled(&mut self, enabled: bool, ctx: &mut ModelContext<Self>) {
        if enabled == self.running.is_some() {
            return;
        }
        if enabled {
            match self.start(ctx) {
                Ok(running) => {
                    self.running = Some(running);
                    self.last_error = None;
                }
                Err(err) => {
                    log::error!("remote access: failed to start: {err:#}");
                    self.last_error = Some(format!("{err:#}"));
                }
            }
        } else {
            self.stop();
            self.last_error = None;
        }
        ctx.emit(RemoteAccessEvent::StateChanged);
        ctx.emit(RemoteAccessEvent::SessionsChanged);
    }

    fn runtime(&mut self) -> anyhow::Result<&tokio::runtime::Runtime> {
        if self.runtime.is_none() {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("anonwarp-remote-access")
                .enable_all()
                .build()
                .context("starting the remote-access runtime")?;
            self.runtime = Some(rt);
        }
        self.runtime
            .as_ref()
            .ok_or_else(|| anyhow!("remote-access runtime unavailable"))
    }

    fn load_or_create_identity(&mut self) -> anyhow::Result<()> {
        if self.identity.is_some() {
            return Ok(());
        }
        let path = self.state_dir.join(IDENTITY_FILE);
        let identity = Identity::generate(None)?;
        identity.save(&path)?;
        self.identity = Some(identity);
        Ok(())
    }

    fn start(&mut self, ctx: &mut ModelContext<Self>) -> anyhow::Result<Running> {
        let registry = self
            .registry
            .clone()
            .ok_or_else(|| anyhow!("the paired-device store is unreadable; see the log"))?;
        self.load_or_create_identity()?;
        let host = match &self.host_factory {
            Some(factory) => factory(ctx),
            None => AppTerminalHost::new(ctx),
        };
        let (handle, event_pump, events) = self.launch(&registry, host.clone())?;
        ctx.spawn_stream_local(
            events,
            |me, event, ctx| me.on_server_event(event, ctx),
            |_, _| {},
        );
        Ok(Running {
            handle,
            host,
            event_pump,
        })
    }

    fn launch(
        &mut self,
        registry: &SharedRegistry,
        host: Arc<dyn TerminalHost>,
    ) -> anyhow::Result<(
        ServerHandle,
        tokio::task::JoinHandle<()>,
        UnboundedReceiver<ServerEvent>,
    )> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow!("no certificate"))?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let pairing = Arc::new(Mutex::new(PairingManager::new(
            PairingConfig::default(),
            clock,
            registry.clone(),
        )));
        let mut config = ServerConfig::new(identity.instance_id.clone(), pc_name());
        config.port = self.port;
        config.policy = NetPolicy::default();
        let cert = identity.cert.clone();
        let rt = self.runtime()?;
        let handle = rt
            .block_on(Server::start(
                config,
                host,
                registry.clone(),
                pairing.clone(),
                &cert,
            ))
            .map_err(|e| anyhow!("{e}"))?;
        let (tx, rx) = unbounded();
        let pump = rt.spawn(pump_events(handle.subscribe_events(), tx));
        Ok((handle, pump, rx))
    }

    fn stop(&mut self) {
        let Some(running) = self.running.take() else {
            return;
        };
        running.event_pump.abort();
        if let Some(rt) = &self.runtime {
            rt.block_on(running.handle.shutdown());
        }
    }

    fn on_server_event(&mut self, event: ServerEvent, ctx: &mut ModelContext<Self>) {
        match event {
            ServerEvent::ApprovalRequested(pending) => {
                ctx.emit(RemoteAccessEvent::ApprovalRequested(pending.id));
            }
            ServerEvent::DevicesChanged => ctx.emit(RemoteAccessEvent::DevicesChanged),
            ServerEvent::SessionConnected(_) | ServerEvent::SessionDisconnected { .. } => {
                ctx.emit(RemoteAccessEvent::SessionsChanged);
            }
            ServerEvent::LockedOut { .. } | ServerEvent::AddrsChanged(_) => {
                ctx.emit(RemoteAccessEvent::StateChanged);
            }
        }
    }

    /// Addresses the server is listening on (private LAN / Tailscale only). Empty when disabled.
    pub fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.running
            .as_ref()
            .map(|r| r.handle.listen_addrs())
            .unwrap_or_default()
    }

    /// Arm a one-time pairing secret and return the QR payload. Errors if disabled.
    pub fn arm_pairing(&mut self, ctx: &mut ModelContext<Self>) -> anyhow::Result<PairingQr> {
        let running = self
            .running
            .as_ref()
            .ok_or_else(|| anyhow!("remote access is not running"))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow!("no certificate"))?;
        let mut hosts: Vec<_> = running
            .handle
            .bound_addrs()
            .into_iter()
            .zip(running.handle.listen_addrs())
            .collect();
        anyhow::ensure!(!hosts.is_empty(), "no private network address to listen on");
        hosts.sort_by_key(|(bound, addr)| {
            let kind = match bound.kind {
                AddrKind::Lan => 0,
                AddrKind::Tailscale => 1,
                AddrKind::Loopback => 2,
            };
            (kind, addr.is_ipv6())
        });
        let armed = running.handle.arm_pairing();
        let fp = identity.cert.fingerprint();
        let payload = QrPayload {
            hosts: hosts
                .iter()
                .map(|(_, a)| *a)
                .take(::remote_access::qr::MAX_HOSTS)
                .collect(),
            secret: armed.secret.to_string(),
            fp,
            instance_id: identity.instance_id.clone(),
            expires_unix: armed.expires_at,
            pc_name: pc_name(),
        };
        let url = payload
            .try_to_url()
            .map_err(|e| anyhow!("building the pairing URL: {e}"))?;
        let app_url = payload
            .try_to_app_url()
            .map_err(|e| anyhow!("building the pairing URL: {e}"))?;
        ctx.emit(RemoteAccessEvent::StateChanged);
        Ok(PairingQr {
            url,
            app_url,
            expires_at: armed.expires_at,
            fingerprint_display: fingerprint_display(&fp),
            hosts: payload.hosts.iter().map(ToString::to_string).collect(),
        })
    }

    pub fn disarm_pairing(&mut self, ctx: &mut ModelContext<Self>) {
        if let Some(running) = &self.running {
            running.handle.disarm_pairing();
        }
        ctx.emit(RemoteAccessEvent::StateChanged);
    }

    /// Phones that submitted a valid secret and wait for approval.
    pub fn pending_approvals(&self) -> Vec<PendingApproval> {
        self.running
            .as_ref()
            .map(|r| r.handle.pending_approvals())
            .unwrap_or_default()
    }

    pub fn resolve_approval(
        &mut self,
        id: &PairingId,
        approve: bool,
        ctx: &mut ModelContext<Self>,
    ) {
        if let Some(running) = &self.running {
            running.handle.resolve_approval(id, approve);
        }
        ctx.emit(RemoteAccessEvent::DevicesChanged);
    }

    /// Paired (non-revoked) devices.
    pub fn devices(&self) -> Vec<DeviceRecord> {
        self.registry
            .as_ref()
            .map(|r| r.lock().unwrap_or_else(|e| e.into_inner()).list())
            .unwrap_or_default()
    }

    /// Revoke one device and close its sockets (close code 4403).
    pub fn revoke_device(&mut self, device_id: &str, ctx: &mut ModelContext<Self>) {
        let id = DeviceId(device_id.to_string());
        match &self.running {
            Some(running) => {
                running.handle.revoke_device(&id);
            }
            None => {
                if let Some(registry) = &self.registry
                    && let Err(err) = registry
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .revoke(&id)
                {
                    log::error!("remote access: revoking a device failed: {err}");
                }
            }
        }
        ctx.emit(RemoteAccessEvent::DevicesChanged);
    }

    pub fn active_sessions(&self) -> Vec<ActiveSession> {
        self.running
            .as_ref()
            .map(|r| {
                r.handle
                    .sessions()
                    .into_iter()
                    .map(|s| ActiveSession {
                        device_id: s.device_id.0,
                        label: s.label,
                        ip: s.ip,
                        since: s.since,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Kill switch: close every phone session now (code 4403) without revoking the devices.
    pub fn kill_all_sessions(&mut self, ctx: &mut ModelContext<Self>) {
        if let Some(running) = &self.running {
            running.handle.kill_all();
        }
        ctx.emit(RemoteAccessEvent::SessionsChanged);
    }

    /// Generate a new certificate; this revokes every paired device.
    pub fn rotate_certificate(&mut self, ctx: &mut ModelContext<Self>) {
        match self.rotate() {
            Ok(()) => self.last_error = None,
            Err(err) => {
                log::error!("remote access: certificate rotation failed: {err:#}");
                self.last_error = Some(format!("{err:#}"));
            }
        }
        if let Some(old) = self.running.take() {
            // Restart on the new certificate with the same terminal host.
            old.event_pump.abort();
            if let Some(rt) = &self.runtime {
                rt.block_on(old.handle.shutdown());
            }
            match self.restart(old.host, ctx) {
                Ok(running) => self.running = Some(running),
                Err(err) => {
                    log::error!("remote access: restart after rotation failed: {err:#}");
                    self.last_error = Some(format!("{err:#}"));
                }
            }
        }
        ctx.emit(RemoteAccessEvent::DevicesChanged);
        ctx.emit(RemoteAccessEvent::SessionsChanged);
        ctx.emit(RemoteAccessEvent::StateChanged);
    }

    fn rotate(&mut self) -> anyhow::Result<()> {
        let instance_id = self.identity.as_ref().map(|i| i.instance_id.clone());
        let identity = Identity::generate(instance_id)?;
        identity.save(&self.state_dir.join(IDENTITY_FILE))?;
        self.identity = Some(identity);
        if let Some(registry) = &self.registry {
            registry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .revoke_all()
                .map_err(|e| anyhow!("revoking devices: {e}"))?;
        }
        Ok(())
    }

    fn restart(
        &mut self,
        host: Arc<dyn TerminalHost>,
        ctx: &mut ModelContext<Self>,
    ) -> anyhow::Result<Running> {
        let registry = self
            .registry
            .clone()
            .ok_or_else(|| anyhow!("the paired-device store is unreadable; see the log"))?;
        let (handle, event_pump, events) = self.launch(&registry, host.clone())?;
        ctx.spawn_stream_local(
            events,
            |me, event, ctx| me.on_server_event(event, ctx),
            |_, _| {},
        );
        Ok(Running {
            handle,
            host,
            event_pump,
        })
    }

    /// SHA-256 fingerprint of the current certificate formatted `AB:CD:..`, if one exists.
    pub fn fingerprint_display(&self) -> Option<String> {
        self.identity
            .as_ref()
            .map(|i| fingerprint_display(&i.cert.fingerprint()))
    }
}

fn open_registry(dir: &Path) -> anyhow::Result<SharedRegistry> {
    let store = Arc::new(JsonFileTokenStore::new(dir.join(DEVICES_FILE)));
    let registry = DeviceRegistry::new(store, Arc::new(SystemClock), RegistryConfig::default())
        .map_err(|e| anyhow!("{e}"))?;
    Ok(Arc::new(Mutex::new(registry)))
}

async fn pump_events(
    mut events: tokio::sync::broadcast::Receiver<ServerEvent>,
    tx: UnboundedSender<ServerEvent>,
) {
    use tokio::sync::broadcast::error::RecvError;
    loop {
        match events.recv().await {
            Ok(event) => {
                if tx.unbounded_send(event).is_err() {
                    return;
                }
            }
            Err(RecvError::Lagged(_)) => {
                // Missed events: make views refresh everything.
                if tx.unbounded_send(ServerEvent::DevicesChanged).is_err() {
                    return;
                }
            }
            Err(RecvError::Closed) => return,
        }
    }
}

impl Entity for RemoteAccessService {
    type Event = RemoteAccessEvent;
}

impl SingletonEntity for RemoteAccessService {}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
