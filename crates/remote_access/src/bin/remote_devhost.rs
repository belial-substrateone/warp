//! Development host for the remote-access server: a mock terminal with three fake panes, loopback
//! allowed, a generated certificate, and the pairing URL printed as text.
//!
//! ```text
//! cargo run -p remote_access --features server,test-util --bin remote_devhost -- [--port N]
//!     [--approve-after SECS | --deny] [--phone-resize]
//! ```
//!
//! Lines starting with `PAIR_URL `, `LISTEN ` and `APPROVAL ` are machine-readable. Typing `kill`
//! or `revoke` followed by Enter in a pane exercises the kill switch / revocation (close code 4403).
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use remote_access::cert::{fingerprint_display, generate_self_signed};
use remote_access::clock::{Clock, SystemClock};
use remote_access::host::{
    HostError, MockTerminalHost, PaneNode, PaneStream, TabNode, TreeSnapshot, WindowNode,
};
use remote_access::netfilter::{NetPolicy, candidate_bind_addrs};
use remote_access::pairing::{PairingConfig, PairingManager};
use remote_access::qr::QrPayload;
use remote_access::server::{Server, ServerConfig, ServerEvent, ServerHandle};
use remote_access::tokens::{DeviceRegistry, MemoryTokenStore, RegistryConfig};
use remote_access::{PaneId, TerminalHost};
use tokio::sync::broadcast;

const PROMPT: &str = "\x1b[32muser@mockpc\x1b[0m:\x1b[34m~\x1b[0m$ ";

fn banner(pane: &str) -> String {
    format!(
        "\x1b[1;36mAnonWarp dev terminal\x1b[0m  ({pane})\r\nType anything. Control bytes are shown as <hex>.\r\nType \"revoke\" or \"kill\" + Enter to test the 4403 screen, \"big\" for a lot of output.\r\n"
    )
}

struct DevHost {
    inner: MockTerminalHost,
    lines: Mutex<HashMap<PaneId, String>>,
    handle: OnceLock<ServerHandle>,
}

impl DevHost {
    fn new() -> Self {
        let pane = |id: &str, title: &str, cwd: &str, cols, rows, focused| PaneNode {
            id: id.into(),
            session: format!("s-{id}"),
            title: title.into(),
            cwd: Some(cwd.into()),
            cols,
            rows,
            alt_screen: false,
            focused,
        };
        let tree = TreeSnapshot {
            windows: vec![WindowNode {
                id: "win:1".into(),
                title: "AnonWarp".into(),
                tabs: vec![
                    TabNode {
                        id: "tab:1".into(),
                        title: "dev".into(),
                        active: true,
                        panes: vec![
                            pane("pane:1", "zsh", "~/projects", 100, 30, true),
                            pane("pane:2", "logs", "/var/log", 80, 24, false),
                        ],
                    },
                    TabNode {
                        id: "tab:2".into(),
                        title: "monitor".into(),
                        active: false,
                        panes: vec![pane("pane:3", "htop", "~", 80, 24, true)],
                    },
                ],
            }],
        };
        let inner = MockTerminalHost::new(tree);
        for id in ["pane:1", "pane:2", "pane:3"] {
            inner.push_output(&PaneId::from(id), banner(id).as_bytes());
            inner.push_output(&PaneId::from(id), PROMPT.as_bytes());
        }
        Self {
            inner,
            lines: Mutex::default(),
            handle: OnceLock::new(),
        }
    }

    fn echo(&self, pane: &PaneId, bytes: &[u8]) {
        let mut lines = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        let line = lines.entry(pane.clone()).or_default();
        let out = |s: &str| self.inner.push_output(pane, s.as_bytes());
        for &b in bytes {
            match b {
                0x0d => {
                    out("\r\n");
                    let cmd = std::mem::take(line);
                    match cmd.trim() {
                        "revoke" => {
                            if let Some(h) = self.handle.get() {
                                h.revoke_all();
                            }
                        }
                        "kill" => {
                            if let Some(h) = self.handle.get() {
                                h.kill_all();
                            }
                        }
                        "big" => {
                            for i in 0..300 {
                                out(&format!("line {i} {}\r\n", "x".repeat(i % 60)));
                            }
                        }
                        _ => {}
                    }
                    out(PROMPT);
                }
                0x7f => {
                    if line.pop().is_some() {
                        out("\x08 \x08");
                    }
                }
                0x20..=0x7e => {
                    line.push(char::from(b));
                    out(&char::from(b).to_string());
                }
                0x80..=0xff => self.inner.push_output(pane, &[b]),
                _ => out(&format!("\x1b[33m<{b:02x}>\x1b[0m")),
            }
        }
    }
}

#[async_trait]
impl TerminalHost for DevHost {
    async fn tree(&self) -> Result<TreeSnapshot, HostError> {
        self.inner.tree().await
    }

    async fn attach(&self, pane: &PaneId, replay: bool) -> Result<PaneStream, HostError> {
        self.inner.attach(pane, replay).await
    }

    async fn send_input(&self, pane: &PaneId, bytes: Vec<u8>) -> Result<(), HostError> {
        self.inner.send_input(pane, bytes.clone()).await?;
        self.echo(pane, &bytes);
        Ok(())
    }

    async fn resize(&self, pane: &PaneId, cols: u16, rows: u16) -> Result<(), HostError> {
        self.inner.resize(pane, cols, rows).await
    }

    async fn action(
        &self,
        name: &str,
        target: serde_json::Value,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, HostError> {
        println!("ACTION {name} {target}");
        self.inner.action(name, target, params).await
    }

    fn subscribe_tree_changes(&self) -> broadcast::Receiver<()> {
        self.inner.subscribe_tree_changes()
    }
}

fn pair_url(handle: &ServerHandle) -> String {
    let armed = handle.arm_pairing();
    let mut hosts = handle.listen_addrs();
    hosts.sort_by_key(|a| !a.ip().is_loopback());
    QrPayload {
        hosts,
        secret: armed.secret.to_string(),
        fp: handle.fingerprint(),
        instance_id: handle.instance_id().to_string(),
        expires_unix: armed.expires_at,
        pc_name: handle.pc_name().to_string(),
    }
    .to_url()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |n: &str| args.iter().any(|a| a == n);
    let opt = |n: &str| {
        args.iter()
            .position(|a| a == n)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let port: u16 = opt("--port").and_then(|p| p.parse().ok()).unwrap_or(0);
    let approve_after: u64 = opt("--approve-after")
        .and_then(|p| p.parse().ok())
        .unwrap_or(1);
    let deny = flag("--deny");

    let policy = NetPolicy::with_loopback();
    let ips: Vec<_> = candidate_bind_addrs(&policy).iter().map(|b| b.ip).collect();
    let cert = generate_self_signed(&ips, "anonwarp-devhost", 30).expect("certificate");
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let registry = Arc::new(Mutex::new(
        DeviceRegistry::new(
            Arc::new(MemoryTokenStore::new()),
            clock.clone(),
            RegistryConfig::default(),
        )
        .expect("registry"),
    ));
    let pairing = Arc::new(Mutex::new(PairingManager::new(
        PairingConfig::default(),
        clock,
        registry.clone(),
    )));
    let mut config = ServerConfig::new("devhost", "DevHost");
    config.port = port;
    config.policy = policy;
    config.phone_resize = flag("--phone-resize");

    let host = Arc::new(DevHost::new());
    let handle = Server::start(config, host.clone(), registry, pairing, &cert)
        .await
        .expect("server start");
    let _ = host.handle.set(handle.clone());

    let addrs: Vec<SocketAddr> = handle.listen_addrs();
    for a in &addrs {
        println!("LISTEN {a}");
    }
    println!("FINGERPRINT {}", fingerprint_display(&handle.fingerprint()));
    println!("PAIR_URL {}", pair_url(&handle));

    let mut events = handle.subscribe_events();
    let h2 = handle.clone();
    tokio::spawn(async move {
        let mut rearm = tokio::time::interval(Duration::from_secs(100));
        rearm.tick().await;
        loop {
            tokio::select! {
                _ = rearm.tick() => println!("PAIR_URL {}", pair_url(&h2)),
                ev = events.recv() => match ev {
                    Ok(ServerEvent::ApprovalRequested(req)) => {
                        println!("APPROVAL {} {} {:?}", req.id, req.device_name, req.ip);
                        let h = h2.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(approve_after)).await;
                            h.resolve_approval(&req.id, !deny);
                        });
                    }
                    Ok(ServerEvent::DevicesChanged) => println!("PAIR_URL {}", pair_url(&h2)),
                    Ok(other) => println!("EVENT {other:?}"),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
            }
        }
    });
    std::future::pending::<()>().await;
}
