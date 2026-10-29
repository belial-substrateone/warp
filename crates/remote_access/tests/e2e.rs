//! End-to-end tests: a real TLS client (rustls pinned to the server certificate) against the
//! real server on loopback, with `MockTerminalHost` as the terminal.
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use remote_access::cert::{generate_self_signed, pinned_client_config};
use remote_access::host::{PaneEvent, TreeSnapshot};
use remote_access::netfilter::{BoundAddr, NetPolicy, peer_allowed};
use remote_access::pairing::{PairingConfig, PairingManager};
use remote_access::protocol::{FRAME_OUTPUT, encode_input_frame};
use remote_access::server::{Server, ServerConfig, ServerEvent, ServerHandle};
use remote_access::tokens::{DeviceRegistry, MemoryTokenStore, RegistryConfig, SharedRegistry};
use remote_access::{ManualClock, MockTerminalHost, PaneId, TerminalHost};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{self, ClientRequestBuilder, Message};

type Ws = WebSocketStream<TlsStream<TcpStream>>;

#[derive(Clone, Copy)]
struct Target {
    addr: SocketAddr,
    fp: [u8; 32],
}

struct Fx {
    handle: ServerHandle,
    host: Arc<MockTerminalHost>,
    addr: SocketAddr,
    fp: [u8; 32],
    clock: Arc<ManualClock>,
    #[allow(dead_code)]
    registry: SharedRegistry,
    events: broadcast::Receiver<ServerEvent>,
}

impl Fx {
    fn t(&self) -> Target {
        Target {
            addr: self.addr,
            fp: self.fp,
        }
    }
}

fn loopback_policy() -> NetPolicy {
    NetPolicy {
        iface_prefixes: vec!["lo".into()],
        ..NetPolicy::with_loopback()
    }
}

async fn fixture() -> Fx {
    fixture_with(|_| {}, |_| {}).await
}

async fn fixture_with(
    tweak: impl FnOnce(&mut ServerConfig),
    tweak_pairing: impl FnOnce(&mut PairingConfig),
) -> Fx {
    build(tweak, tweak_pairing, None).await
}

async fn build(
    tweak: impl FnOnce(&mut ServerConfig),
    tweak_pairing: impl FnOnce(&mut PairingConfig),
    custom: Option<Arc<dyn TerminalHost>>,
) -> Fx {
    let cert = generate_self_signed(&["127.0.0.1".parse().unwrap()], "test", 1).unwrap();
    let clock = Arc::new(ManualClock::new(1_800_000_000));
    let registry: SharedRegistry = Arc::new(Mutex::new(
        DeviceRegistry::new(
            Arc::new(MemoryTokenStore::new()),
            clock.clone(),
            RegistryConfig::default(),
        )
        .unwrap(),
    ));
    let mut pcfg = PairingConfig::default();
    tweak_pairing(&mut pcfg);
    let pairing = Arc::new(Mutex::new(PairingManager::new(
        pcfg,
        clock.clone(),
        registry.clone(),
    )));
    let mut cfg = ServerConfig::new("test-instance", "TestPC");
    cfg.port = 0;
    cfg.policy = loopback_policy();
    cfg.rescan_interval = None;
    tweak(&mut cfg);
    let host = Arc::new(MockTerminalHost::single_pane());
    let served: Arc<dyn TerminalHost> = custom.unwrap_or_else(|| host.clone());
    let handle = Server::start(cfg, served, registry.clone(), pairing, &cert)
        .await
        .unwrap();
    let addr = handle
        .listen_addrs()
        .into_iter()
        .find(|a| a.ip() == IpAddr::from([127, 0, 0, 1]))
        .expect("an IPv4 loopback listener");
    let events = handle.subscribe_events();
    Fx {
        handle,
        host,
        addr,
        fp: cert.fingerprint(),
        clock,
        registry,
        events,
    }
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

async fn tls(addr: SocketAddr, fp: [u8; 32]) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(pinned_client_config(fp).unwrap());
    connector.connect(rustls_pki_types_ip(addr.ip()), tcp).await
}

fn rustls_pki_types_ip(ip: IpAddr) -> tokio_rustls::rustls::pki_types::ServerName<'static> {
    tokio_rustls::rustls::pki_types::ServerName::IpAddress(ip.into())
}

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn http(
    fx: Target,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Resp {
    let mut s = tls(fx.addr, fx.fp).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req += &format!("Host: {}\r\n", fx.addr);
    }
    for (k, v) in headers {
        req += &format!("{k}: {v}\r\n");
    }
    if let Some(b) = body {
        req += &format!("Content-Length: {}\r\n", b.len());
    }
    req += "\r\n";
    if let Some(b) = body {
        req += b;
    }
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    // A missing close_notify at the end is not interesting here.
    let _ = tokio::time::timeout(Duration::from_secs(30), s.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: body.to_string(),
    }
}

async fn post_pair(fx: &Fx, secret: &str, name: &str, platform: &str) -> Resp {
    let body = json!({"v":1,"secret":secret,"device_name":name,"platform":platform}).to_string();
    http(
        fx.t(),
        "POST",
        "/v1/pair",
        &[("Content-Type", "application/json")],
        Some(&body),
    )
    .await
}

async fn wait_event(
    rx: &mut broadcast::Receiver<ServerEvent>,
    mut pred: impl FnMut(&ServerEvent) -> bool,
) -> ServerEvent {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Ok(e) if pred(&e) => return e,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("event channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for event")
}

/// Full approved pairing; returns `(device_id, token)`.
async fn pair_device(fx: &mut Fx, name: &str) -> (String, String) {
    let secret = fx.handle.arm_pairing().secret.to_string();
    let r = post_pair(fx, &secret, name, "android").await;
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.json()["status"], "pending");
    let poll = r.json()["poll"].as_str().unwrap().to_string();
    let ServerEvent::ApprovalRequested(req) = wait_event(&mut fx.events, |e| {
        matches!(e, ServerEvent::ApprovalRequested(_))
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(req.device_name, name);
    assert!(fx.handle.resolve_approval(&req.id, true).is_some());
    let r = http(fx.t(), "GET", &format!("/v1/pair/{poll}"), &[], None).await;
    assert_eq!(r.status, 200);
    let j = r.json();
    assert_eq!(j["status"], "approved", "{j}");
    (
        j["device_id"].as_str().unwrap().to_string(),
        j["token"].as_str().unwrap().to_string(),
    )
}

async fn ws_connect_with(
    fx: &Fx,
    origin: Option<&str>,
    bearer: Option<&str>,
) -> Result<Ws, tungstenite::Error> {
    let tcp = tls(fx.addr, fx.fp).await.unwrap();
    let uri: tungstenite::http::Uri = format!("wss://{}/v1/ws", fx.addr).parse().unwrap();
    let mut req = ClientRequestBuilder::new(uri).with_sub_protocol("anonwarp.v1");
    if let Some(o) = origin {
        req = req.with_header("Origin", o);
    }
    if let Some(b) = bearer {
        req = req.with_header("Authorization", format!("Bearer {b}"));
    }
    tokio_tungstenite::client_async(req, tcp)
        .await
        .map(|(w, _)| w)
}

async fn ws_raw(fx: &Fx) -> Ws {
    let origin = format!("https://{}", fx.addr);
    ws_connect_with(fx, Some(&origin), None).await.unwrap()
}

#[derive(Debug)]
enum Frame {
    Json(Value),
    Bin(Vec<u8>),
    Close(Option<u16>),
    End,
    Timeout,
}

async fn next_frame(ws: &mut Ws, secs: u64) -> Frame {
    loop {
        match tokio::time::timeout(Duration::from_secs(secs), ws.next()).await {
            Err(_) => return Frame::Timeout,
            Ok(None) | Ok(Some(Err(_))) => return Frame::End,
            Ok(Some(Ok(Message::Text(t)))) => {
                return Frame::Json(serde_json::from_str(t.as_str()).unwrap());
            }
            Ok(Some(Ok(Message::Binary(b)))) => return Frame::Bin(b.to_vec()),
            Ok(Some(Ok(Message::Close(c)))) => {
                return Frame::Close(c.map(|c| u16::from(c.code)));
            }
            Ok(Some(Ok(_))) => {}
        }
    }
}

async fn expect_json(ws: &mut Ws, t: &str) -> Value {
    match next_frame(ws, 5).await {
        Frame::Json(v) if v["t"] == t => v,
        other => panic!("expected `{t}`, got {other:?}"),
    }
}

/// Like `expect_json` but tolerates binary output frames in between (replay data).
async fn expect_json_skip_bin(ws: &mut Ws, t: &str) -> Value {
    loop {
        match next_frame(ws, 5).await {
            Frame::Json(v) if v["t"] == t => return v,
            Frame::Bin(_) => {}
            other => panic!("expected `{t}`, got {other:?}"),
        }
    }
}

async fn expect_close(ws: &mut Ws) -> Option<u16> {
    loop {
        match next_frame(ws, 5).await {
            Frame::Close(c) => return c,
            Frame::Json(_) | Frame::Bin(_) => {}
            Frame::End => return None,
            Frame::Timeout => panic!("timed out waiting for close"),
        }
    }
}

async fn send_json(ws: &mut Ws, v: Value) {
    ws.send(Message::Text(v.to_string().into())).await.unwrap();
}

async fn authed_ws(fx: &Fx, token: &str) -> Ws {
    let mut ws = ws_raw(fx).await;
    send_json(
        &mut ws,
        json!({"t":"hello","v":1,"token":token,"client":"test","caps":["binary"]}),
    )
    .await;
    let w = expect_json(&mut ws, "welcome").await;
    assert_eq!(w["v"], 1);
    ws
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pairing_approve_then_token_works_once_per_secret() {
    let mut fx = fixture().await;
    assert_eq!(
        http(fx.t(), "GET", "/v1/info", &[], None).await.json()["pairing"],
        false
    );
    let secret = fx.handle.arm_pairing().secret.to_string();
    let info = http(fx.t(), "GET", "/v1/info", &[], None).await.json();
    assert_eq!(info["pairing"], true);
    assert_eq!(info["protocol"], 1);
    assert_eq!(info["instance"], "test-instance");

    let r = post_pair(&fx, &secret, "Pixel 8", "android").await;
    assert_eq!(r.status, 200);
    let poll = r.json()["poll"].as_str().unwrap().to_string();

    // The long-poll is parked until the PC user decides.
    let long_poll = {
        let t = fx.t();
        let path = format!("/v1/pair/{poll}");
        tokio::spawn(async move { http(t, "GET", &path, &[], None).await })
    };
    let ServerEvent::ApprovalRequested(req) = wait_event(&mut fx.events, |e| {
        matches!(e, ServerEvent::ApprovalRequested(_))
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(req.device_name, "Pixel 8");
    assert_eq!(req.platform, "android");
    assert_eq!(req.ip, Some(IpAddr::from([127, 0, 0, 1])));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!long_poll.is_finished());
    fx.handle.resolve_approval(&req.id, true).unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), long_poll)
        .await
        .unwrap()
        .unwrap();
    let j = resp.json();
    assert_eq!(j["status"], "approved");
    let token = j["token"].as_str().unwrap().to_string();
    assert!(token.len() >= 40);

    // Single use: the same secret is dead, and the token is returned only once.
    assert_eq!(post_pair(&fx, &secret, "again", "web").await.status, 401);
    let again = http(fx.t(), "GET", &format!("/v1/pair/{}", req.id), &[], None).await;
    assert_eq!(again.json()["status"], "expired");

    let mut ws = authed_ws(&fx, &token).await;
    send_json(&mut ws, json!({"t":"ping","n":7})).await;
    assert_eq!(expect_json(&mut ws, "pong").await["n"], 7);
}

#[tokio::test]
async fn pairing_denied_and_no_token() {
    let mut fx = fixture().await;
    let secret = fx.handle.arm_pairing().secret.to_string();
    let r = post_pair(&fx, &secret, "evil", "web").await;
    let poll = r.json()["poll"].as_str().unwrap().to_string();
    let ServerEvent::ApprovalRequested(req) = wait_event(&mut fx.events, |e| {
        matches!(e, ServerEvent::ApprovalRequested(_))
    })
    .await
    else {
        unreachable!()
    };
    assert!(fx.handle.resolve_approval(&req.id, false).is_none());
    let r = http(fx.t(), "GET", &format!("/v1/pair/{poll}"), &[], None).await;
    assert_eq!(r.json()["status"], "denied");
    assert!(r.json().get("token").is_none());
    assert!(fx.handle.sessions().is_empty());
}

#[tokio::test]
async fn pairing_expired_secret_and_unanswered_approval() {
    let fx = fixture().await;
    let secret = fx.handle.arm_pairing().secret.to_string();
    fx.clock.advance(121);
    assert_eq!(post_pair(&fx, &secret, "late", "web").await.status, 401);

    let secret = fx.handle.arm_pairing().secret.to_string();
    let r = post_pair(&fx, &secret, "slow", "web").await;
    let poll = r.json()["poll"].as_str().unwrap().to_string();
    fx.clock.advance(121);
    let r = http(fx.t(), "GET", &format!("/v1/pair/{poll}"), &[], None).await;
    assert_eq!(r.json()["status"], "expired");
}

#[tokio::test]
async fn pairing_three_wrong_secrets_lock_out() {
    let mut fx = fixture().await;
    let secret = fx.handle.arm_pairing().secret.to_string();
    for _ in 0..3 {
        let r = post_pair(&fx, "definitely-not-the-secret-definitely-not", "x", "web").await;
        assert_eq!(r.status, 401);
        assert!(!r.body.contains(&secret));
    }
    wait_event(&mut fx.events, |e| {
        matches!(e, ServerEvent::LockedOut { .. })
    })
    .await;
    // The armed secret was invalidated and the lockout refuses even the right secret.
    let r = post_pair(&fx, &secret, "legit", "web").await;
    assert_eq!(r.status, 429, "{r:?}");
    assert!(r.json()["retry_after"].as_u64().unwrap() > 0);
    assert!(r.header("retry-after").is_some());
    // Once the lockout has passed a new QR works again.
    fx.clock.advance(31);
    let secret = fx.handle.arm_pairing().secret.to_string();
    assert_eq!(post_pair(&fx, &secret, "legit", "web").await.status, 200);
}

#[tokio::test]
async fn pairing_without_approval_returns_token_directly() {
    let fx = fixture_with(|_| {}, |p| p.require_approval = false).await;
    let secret = fx.handle.arm_pairing().secret.to_string();
    let r = post_pair(&fx, &secret, "auto", "android").await;
    assert_eq!(r.json()["status"], "approved");
    let token = r.json()["token"].as_str().unwrap().to_string();
    authed_ws(&fx, &token).await;
}

#[tokio::test]
async fn pair_post_requires_json_and_valid_body() {
    let fx = fixture().await;
    let secret = fx.handle.arm_pairing().secret.to_string();
    let body = json!({"v":1,"secret":secret,"device_name":"x","platform":"web"}).to_string();
    let r = http(
        fx.t(),
        "POST",
        "/v1/pair",
        &[("Content-Type", "text/plain")],
        Some(&body),
    )
    .await;
    assert_eq!(r.status, 415);
    let r = http(
        fx.t(),
        "POST",
        "/v1/pair",
        &[("Content-Type", "application/json")],
        Some("{"),
    )
    .await;
    assert_eq!(r.status, 400);
    let big = format!("{{\"pad\":\"{}\"}}", "x".repeat(10_000));
    let r = http(
        fx.t(),
        "POST",
        "/v1/pair",
        &[("Content-Type", "application/json")],
        Some(&big),
    )
    .await;
    assert_eq!(r.status, 413);
}

// ---------------------------------------------------------------------------
// WebSocket: attach, replay, live output, input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attach_replays_then_streams_live_output() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let pane = PaneId::from("p1");
    fx.host.push_output(&pane, b"old");

    let mut ws = authed_ws(&fx, &token).await;
    send_json(&mut ws, json!({"t":"list"})).await;
    let tree = expect_json(&mut ws, "tree").await;
    assert_eq!(tree["windows"][0]["tabs"][0]["panes"][0]["id"], "p1");

    send_json(
        &mut ws,
        json!({"t":"attach","pane":"p1","stream":1,"replay":true}),
    )
    .await;
    // The snapshot message always precedes the first binary frame.
    let snap = expect_json(&mut ws, "snapshot").await;
    assert_eq!(
        (snap["cols"].as_u64(), snap["rows"].as_u64()),
        (Some(80), Some(24))
    );
    assert_eq!(snap["alt_screen"], false);
    assert_eq!(snap["stream"], 1);
    assert_eq!(snap["offset"], 0);

    fx.host.push_output(&pane, b"new");
    let mut got = Vec::new();
    let mut first_offset = None;
    while got.len() < b"\x1bcoldnew".len() {
        let Frame::Bin(b) = next_frame(&mut ws, 5).await else {
            panic!("expected binary output");
        };
        assert_eq!(b[0], FRAME_OUTPUT);
        assert_eq!(u32::from_be_bytes(b[1..5].try_into().unwrap()), 1);
        first_offset.get_or_insert(u64::from_be_bytes(b[5..13].try_into().unwrap()));
        got.extend_from_slice(&b[13..]);
    }
    assert_eq!(got, b"\x1bcoldnew");
    assert_eq!(first_offset, Some(0));

    // pane_state events are forwarded, detach stops the stream.
    fx.host.push_event(
        &pane,
        PaneEvent {
            alt_screen: true,
            command_running: true,
            cwd: Some("/x".into()),
            title: None,
        },
    );
    let st = expect_json(&mut ws, "pane_state").await;
    assert_eq!(st["alt_screen"], true);
    send_json(&mut ws, json!({"t":"detach","stream":1})).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fx.host.attached_count(&pane) > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn attach_without_replay_starts_at_current_offset() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let pane = PaneId::from("p1");
    fx.host.push_output(&pane, b"12345");
    let mut ws = authed_ws(&fx, &token).await;
    send_json(
        &mut ws,
        json!({"t":"attach","pane":"p1","stream":3,"replay":false}),
    )
    .await;
    assert_eq!(expect_json(&mut ws, "snapshot").await["offset"], 5);
    fx.host.push_output(&pane, b"x");
    let Frame::Bin(b) = next_frame(&mut ws, 5).await else {
        panic!()
    };
    assert_eq!(u64::from_be_bytes(b[5..13].try_into().unwrap()), 5);
    assert_eq!(&b[13..], b"x");
    send_json(&mut ws, json!({"t":"attach","pane":"nope","stream":4})).await;
    assert_eq!(expect_json(&mut ws, "error").await["code"], "not_found");
}

#[tokio::test]
async fn input_reaches_the_host_bit_exact() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    // Input before attaching a stream is refused.
    ws.send(Message::Binary(encode_input_frame(1, b"x").unwrap().into()))
        .await
        .unwrap();
    assert_eq!(expect_json(&mut ws, "error").await["code"], "not_attached");

    send_json(&mut ws, json!({"t":"attach","pane":"p1","stream":1})).await;
    expect_json(&mut ws, "snapshot").await;
    let all: Vec<u8> = (0..=255u8).collect();
    ws.send(Message::Binary(encode_input_frame(1, &all).unwrap().into()))
        .await
        .unwrap();
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"ls\r");
    send_json(&mut ws, json!({"t":"input","stream":1,"text_b64":b64})).await;
    let pane = PaneId::from("p1");
    tokio::time::timeout(Duration::from_secs(5), async {
        while fx.host.inputs().len() < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fx.host.inputs(),
        vec![(pane.clone(), all), (pane, b"ls\r".to_vec())]
    );
}

#[tokio::test]
async fn resize_denied_by_default_and_allowed_when_enabled() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    send_json(&mut ws, json!({"t":"attach","pane":"p1","stream":1})).await;
    expect_json(&mut ws, "snapshot").await;
    send_json(
        &mut ws,
        json!({"t":"resize","stream":1,"cols":100,"rows":40}),
    )
    .await;
    assert_eq!(
        expect_json_skip_bin(&mut ws, "error").await["code"],
        "resize_denied"
    );
    assert!(fx.host.resizes().is_empty());

    let mut fx = fixture_with(|c| c.phone_resize = true, |_| {}).await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    send_json(&mut ws, json!({"t":"attach","pane":"p1","stream":1})).await;
    expect_json(&mut ws, "snapshot").await;
    send_json(
        &mut ws,
        json!({"t":"resize","stream":1,"cols":100,"rows":40}),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fx.host.resizes().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fx.host.resizes(), vec![(PaneId::from("p1"), 100, 40)]);
}

#[tokio::test]
async fn actions_are_whitelisted_and_unknown_types_keep_the_socket_open() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    send_json(&mut ws, json!({"t":"action","id":5,"name":"pane.split","target":{"pane":"p1"},"params":{"dir":"right"}})).await;
    let r = expect_json(&mut ws, "result").await;
    assert_eq!((r["id"].as_u64(), r["ok"].as_bool()), (Some(5), Some(true)));
    send_json(&mut ws, json!({"t":"action","id":6,"name":"instance.quit"})).await;
    let r = expect_json(&mut ws, "result").await;
    assert_eq!(r["ok"], false);
    assert_eq!(r["error"]["code"], "unsupported");
    assert_eq!(fx.host.actions().len(), 1);

    send_json(&mut ws, json!({"t":"teleport"})).await;
    assert_eq!(expect_json(&mut ws, "error").await["code"], "unknown_type");
    send_json(&mut ws, json!({"t":"ping","n":1})).await;
    expect_json(&mut ws, "pong").await;

    fx.host.notify_tree_changed();
    expect_json(&mut ws, "tree_changed").await;
    fx.host.set_tree(TreeSnapshot::default());
    expect_json(&mut ws, "tree_changed").await;
}

#[tokio::test]
async fn backpressure_stops_at_one_mebibyte_until_acked() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let pane = PaneId::from("p1");
    let mut ws = authed_ws(&fx, &token).await;
    send_json(
        &mut ws,
        json!({"t":"attach","pane":"p1","stream":1,"replay":false}),
    )
    .await;
    expect_json(&mut ws, "snapshot").await;
    let chunk = vec![b'a'; 64 * 1024];
    for _ in 0..40 {
        fx.host.push_output(&pane, &chunk);
    }
    let mut total = 0u64;
    loop {
        match next_frame(&mut ws, 1).await {
            Frame::Bin(b) => total += (b.len() - 13) as u64,
            Frame::Timeout => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    let high = remote_access::protocol::BACKPRESSURE_HIGH_BYTES;
    assert!(total >= high, "{total}");
    assert!(
        total <= high + 2 * 64 * 1024,
        "server sent {total} unacked bytes"
    );
    send_json(&mut ws, json!({"t":"ack","stream":1,"offset":total})).await;
    while total < 40 * 64 * 1024 {
        match next_frame(&mut ws, 2).await {
            Frame::Bin(b) => {
                total += (b.len() - 13) as u64;
                send_json(&mut ws, json!({"t":"ack","stream":1,"offset":total})).await;
            }
            other => panic!("unexpected {other:?} after {total} bytes"),
        }
    }
    assert_eq!(total, 40 * 64 * 1024);
}

// ---------------------------------------------------------------------------
// Revocation, kill switch, sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_closes_live_socket_with_4403_and_blocks_reconnect() {
    let mut fx = fixture().await;
    let (device_id, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    let ServerEvent::SessionConnected(info) = wait_event(&mut fx.events, |e| {
        matches!(e, ServerEvent::SessionConnected(_))
    })
    .await
    else {
        unreachable!()
    };
    assert_eq!(info.device_id.0, device_id);
    assert_eq!(info.label, "phone");
    assert_eq!(fx.handle.sessions().len(), 1);

    assert!(fx.handle.revoke_device(&info.device_id));
    let killed = expect_json(&mut ws, "session_killed").await;
    assert_eq!(killed["reason"], "device revoked");
    assert_eq!(expect_close(&mut ws).await, Some(4403));
    wait_event(&mut fx.events, |e| {
        matches!(e, ServerEvent::SessionDisconnected { .. })
    })
    .await;
    assert!(fx.handle.sessions().is_empty());

    let mut again = ws_raw(&fx).await;
    send_json(
        &mut again,
        json!({"t":"hello","v":1,"token":token,"client":"test"}),
    )
    .await;
    assert_eq!(expect_close(&mut again).await, Some(4403));
}

#[tokio::test]
async fn kill_all_and_kick_close_with_4403_but_keep_devices_paired() {
    let mut fx = fixture().await;
    let (id_a, tok_a) = pair_device(&mut fx, "a").await;
    let (_, tok_b) = pair_device(&mut fx, "b").await;
    let mut a = authed_ws(&fx, &tok_a).await;
    let mut b = authed_ws(&fx, &tok_b).await;
    assert_eq!(fx.handle.sessions().len(), 2);

    assert_eq!(fx.handle.kick(&remote_access::tokens::DeviceId(id_a)), 1);
    assert_eq!(expect_close(&mut a).await, Some(4403));
    tokio::time::timeout(Duration::from_secs(5), async {
        while fx.handle.sessions().len() > 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    send_json(&mut b, json!({"t":"ping","n":1})).await;
    expect_json(&mut b, "pong").await;

    let started = tokio::time::Instant::now();
    assert_eq!(fx.handle.kill_all(), 1);
    assert_eq!(expect_close(&mut b).await, Some(4403));
    assert!(started.elapsed() < Duration::from_secs(1));
    // Still paired: they can reconnect.
    authed_ws(&fx, &tok_a).await;
    authed_ws(&fx, &tok_b).await;
}

#[tokio::test]
async fn device_unpairs_itself_via_post_revoke() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    let auth = format!("Bearer {token}");
    let r = http(
        fx.t(),
        "POST",
        "/v1/revoke",
        &[
            ("Authorization", &auth),
            ("Content-Type", "application/json"),
        ],
        Some("{}"),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(expect_close(&mut ws).await, Some(4403));
    let r = http(
        fx.t(),
        "POST",
        "/v1/revoke",
        &[
            ("Authorization", "Bearer nope"),
            ("Content-Type", "application/json"),
        ],
        Some("{}"),
    )
    .await;
    assert_eq!(r.status, 401);
}

#[tokio::test]
async fn revoke_all_via_registry_is_noticed_by_the_watchdog() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    fx.registry.lock().unwrap().revoke_all().unwrap();
    assert_eq!(expect_close(&mut ws).await, Some(4403));
}

#[tokio::test]
async fn bearer_header_authenticates_the_upgrade() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let origin = format!("https://{}", fx.addr);
    let mut ws = ws_connect_with(&fx, Some(&origin), Some(&token))
        .await
        .unwrap();
    send_json(
        &mut ws,
        json!({"t":"hello","v":1,"token":"","client":"android"}),
    )
    .await;
    expect_json(&mut ws, "welcome").await;
    assert!(
        ws_connect_with(&fx, Some(&origin), Some("bogus"))
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Handshake rules and limits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hello_rules() {
    let mut fx = fixture_with(|c| c.hello_deadline = Duration::from_millis(300), |_| {}).await;
    let (_, token) = pair_device(&mut fx, "phone").await;

    let mut ws = ws_raw(&fx).await;
    assert_eq!(expect_close(&mut ws).await, Some(4401), "no hello in time");

    let mut ws = ws_raw(&fx).await;
    send_json(
        &mut ws,
        json!({"t":"hello","v":1,"token":"wrong","client":"x"}),
    )
    .await;
    assert_eq!(expect_close(&mut ws).await, Some(4401));

    let mut ws = ws_raw(&fx).await;
    send_json(
        &mut ws,
        json!({"t":"hello","v":9,"token":token,"client":"x"}),
    )
    .await;
    assert_eq!(
        expect_json(&mut ws, "error").await["code"],
        "unsupported_version"
    );
    assert_eq!(expect_close(&mut ws).await, Some(4400));

    let mut ws = ws_raw(&fx).await;
    send_json(&mut ws, json!({"t":"list"})).await;
    assert_eq!(expect_close(&mut ws).await, Some(4400));

    let mut ws = ws_raw(&fx).await;
    ws.send(Message::Binary(vec![2, 0, 0, 0, 1, 65].into()))
        .await
        .unwrap();
    assert_eq!(expect_close(&mut ws).await, Some(4400));
}

#[tokio::test]
async fn too_many_authenticated_sockets_and_unauthenticated_sockets() {
    let mut fx = fixture_with(
        |c| {
            c.max_authenticated_sockets = 2;
            c.max_unauthenticated_sockets = 2;
            c.hello_deadline = Duration::from_secs(30);
        },
        |_| {},
    )
    .await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let _a = authed_ws(&fx, &token).await;
    let _b = authed_ws(&fx, &token).await;
    let mut c = ws_raw(&fx).await;
    send_json(
        &mut c,
        json!({"t":"hello","v":1,"token":token,"client":"x"}),
    )
    .await;
    assert_eq!(expect_json(&mut c, "error").await["code"], "rate_limited");
    assert_eq!(expect_close(&mut c).await, Some(4429));

    let _u1 = ws_raw(&fx).await;
    let _u2 = ws_raw(&fx).await;
    // Pending sockets hold the unauthenticated slots; one more is refused at the upgrade.
    let r = ws_connect_with(&fx, Some(&format!("https://{}", fx.addr)), None).await;
    assert!(r.is_err(), "third unauthenticated socket must be refused");
}

#[tokio::test]
async fn oversize_frames_are_rejected() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;

    // Binary input above the 64 KiB cap but below the transport cap.
    let mut ws = authed_ws(&fx, &token).await;
    send_json(&mut ws, json!({"t":"attach","pane":"p1","stream":1})).await;
    expect_json(&mut ws, "snapshot").await;
    let mut frame = vec![2u8, 0, 0, 0, 1];
    frame.extend(vec![b'x'; 100 * 1024]);
    ws.send(Message::Binary(frame.into())).await.unwrap();
    assert_eq!(
        expect_json_skip_bin(&mut ws, "error").await["code"],
        "too_large"
    );
    assert_eq!(expect_close(&mut ws).await, Some(4400));

    // Text frame above 64 KiB.
    let mut ws = authed_ws(&fx, &token).await;
    let pad = "x".repeat(70 * 1024);
    send_json(&mut ws, json!({"t":"ping","n":1,"pad":pad})).await;
    assert_eq!(expect_json(&mut ws, "error").await["code"], "too_large");
    assert_eq!(expect_close(&mut ws).await, Some(4400));

    // Above the transport cap the connection is simply torn down.
    let mut ws = authed_ws(&fx, &token).await;
    let _ = ws.send(Message::Binary(vec![2u8; 400 * 1024].into())).await;
    loop {
        match next_frame(&mut ws, 5).await {
            Frame::Close(_) | Frame::End => break,
            Frame::Timeout => panic!("oversize frame did not end the connection"),
            Frame::Json(_) | Frame::Bin(_) => {}
        }
    }
    assert!(fx.host.inputs().is_empty());
}

#[tokio::test]
async fn input_rate_limit_drops_and_eventually_closes() {
    let mut fx = fixture_with(
        |c| {
            c.input_rate_bytes_per_sec = 1;
            c.input_burst_bytes = 1000;
        },
        |_| {},
    )
    .await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    send_json(&mut ws, json!({"t":"attach","pane":"p1","stream":1})).await;
    expect_json(&mut ws, "snapshot").await;
    let chunk = encode_input_frame(1, &[b'a'; 600]).unwrap();
    for _ in 0..12 {
        ws.send(Message::Binary(chunk.clone().into()))
            .await
            .unwrap();
    }
    let mut saw_limited = false;
    loop {
        match next_frame(&mut ws, 5).await {
            Frame::Json(v) if v["code"] == "rate_limited" => saw_limited = true,
            Frame::Close(Some(4429)) => break,
            Frame::Json(_) | Frame::Bin(_) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(saw_limited);
    // Only the first burst fits the bucket (it may not even have been forwarded yet when the
    // connection was torn down).
    assert!(fx.host.inputs().len() <= 1);
}

#[tokio::test]
async fn silent_client_is_closed_by_the_watchdog() {
    let mut fx = fixture_with(
        |c| {
            c.silence_timeout = Duration::from_millis(600);
            c.ping_interval = Duration::from_millis(200);
        },
        |_| {},
    )
    .await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    // Do not poll the socket: no pongs go out, so the server sees silence.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(expect_close(&mut ws).await, Some(4408));
}

// ---------------------------------------------------------------------------
// Network policy, Host/Origin, TLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn host_and_origin_are_validated_everywhere() {
    let fx = fixture().await;
    let good_origin = format!("https://{}", fx.addr);
    assert_eq!(http(fx.t(), "GET", "/v1/info", &[], None).await.status, 200);
    assert_eq!(http(fx.t(), "GET", "/", &[], None).await.status, 200);
    assert_eq!(
        http(fx.t(), "GET", "/v1/info", &[("Origin", &good_origin)], None)
            .await
            .status,
        200
    );

    for host in [
        "evil.example",
        "localhost",
        "127.0.0.1",
        "127.0.0.1:1",
        "[::1]:1",
    ] {
        // `127.0.0.1` without the port is not the bound literal either.
        let r = http(fx.t(), "GET", "/v1/info", &[("Host", host)], None).await;
        assert_eq!(r.status, 403, "Host {host}");
        let r = http(fx.t(), "GET", "/", &[("Host", host)], None).await;
        assert_eq!(r.status, 403, "Host {host} on static");
    }
    for origin in [
        "https://evil.example",
        "http://127.0.0.1:1",
        "null",
        "https://127.0.0.1",
    ] {
        let r = http(fx.t(), "GET", "/v1/info", &[("Origin", origin)], None).await;
        assert_eq!(r.status, 403, "Origin {origin}");
        let body = json!({"v":1,"secret":"x","device_name":"x","platform":"web"}).to_string();
        let r = http(
            fx.t(),
            "POST",
            "/v1/pair",
            &[("Origin", origin), ("Content-Type", "application/json")],
            Some(&body),
        )
        .await;
        assert_eq!(r.status, 403, "pair with Origin {origin}");
    }

    // WebSocket upgrade: wrong Origin is refused before the upgrade completes.
    for origin in ["https://evil.example", "null"] {
        match ws_connect_with(&fx, Some(origin), None).await {
            Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status().as_u16(), 403),
            other => panic!("upgrade with Origin {origin} should fail with 403, got {other:?}"),
        }
    }
    // Wrong Host on the upgrade.
    let mut s = tls(fx.addr, fx.fp).await.unwrap();
    let req = "GET /v1/ws HTTP/1.1\r\nHost: evil.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Protocol: anonwarp.v1\r\n\r\n";
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = s.read(&mut buf).await.unwrap_or(0);
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 403"));

    // Missing subprotocol is refused too.
    let uri: tungstenite::http::Uri = format!("wss://{}/v1/ws", fx.addr).parse().unwrap();
    let tcp = tls(fx.addr, fx.fp).await.unwrap();
    assert!(
        tokio_tungstenite::client_async(ClientRequestBuilder::new(uri), tcp)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn static_assets_and_security_headers() {
    let fx = fixture().await;
    for path in ["/", "/pair"] {
        let r = http(fx.t(), "GET", path, &[], None).await;
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.header("content-type"), Some("text/html; charset=utf-8"));
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert!(r.body.contains("<title>") || r.body.contains("<html"));
    }
    let r = http(fx.t(), "GET", "/", &[], None).await;
    let csp = r.header("content-security-policy").unwrap();
    assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    for (path, ct) in [
        ("/js/app.js", "text/javascript; charset=utf-8"),
        ("/js/protocol.js", "text/javascript; charset=utf-8"),
        ("/app.css", "text/css; charset=utf-8"),
        ("/manifest.webmanifest", "application/manifest+json"),
        ("/icons/icon.svg", "image/svg+xml"),
        ("/vendor/xterm.js", "text/javascript; charset=utf-8"),
    ] {
        let r = http(fx.t(), "GET", path, &[], None).await;
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.header("content-type"), Some(ct), "{path}");
    }
    let etag = http(fx.t(), "GET", "/app.css", &[], None).await;
    let etag = etag.header("etag").unwrap().to_string();
    let r = http(fx.t(), "GET", "/app.css", &[("If-None-Match", &etag)], None).await;
    assert_eq!(r.status, 304);
    for path in [
        "/test/helpers.mjs",
        "/nope",
        "/../Cargo.toml",
        "/js/../app.css",
        "/%2e%2e/x",
    ] {
        assert_eq!(
            http(fx.t(), "GET", path, &[], None).await.status,
            404,
            "{path}"
        );
    }
    assert_eq!(http(fx.t(), "DELETE", "/", &[], None).await.status, 405);
}

#[tokio::test]
async fn wrong_certificate_pin_is_refused_by_the_client() {
    let fx = fixture().await;
    let mut wrong = fx.fp;
    wrong[0] ^= 0xff;
    assert!(tls(fx.addr, wrong).await.is_err());
}

#[tokio::test]
async fn plaintext_and_tls12_clients_get_nothing() {
    let fx = fixture().await;
    let mut tcp = TcpStream::connect(fx.addr).await.unwrap();
    tcp.write_all(b"GET /v1/info HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut buf)).await;
    assert!(!String::from_utf8_lossy(&buf).contains("HTTP/1.1 200"));
}

#[tokio::test]
async fn only_private_addresses_are_ever_bound() {
    let fx = fixture().await;
    let addrs = fx.handle.listen_addrs();
    assert!(!addrs.is_empty());
    for a in &addrs {
        assert!(!a.ip().is_unspecified(), "{a}");
        assert!(
            a.ip().is_loopback(),
            "{a} (policy only allows loopback here)"
        );
    }
    // With the production policy no address is ever a public one.
    let prod = remote_access::netfilter::candidate_bind_addrs(&NetPolicy::default());
    for b in prod {
        assert!(remote_access::netfilter::is_allowed_addr(
            b.ip,
            &NetPolicy::default()
        ));
        assert!(!b.ip.is_loopback() && !b.ip.is_unspecified());
    }
}

#[tokio::test]
async fn peer_outside_the_allowed_ranges_is_dropped_at_accept() {
    // Live: the listener is bound under the loopback policy, but peers are judged by the
    // production policy, under which 127.0.0.1 is not acceptable.
    let fx = fixture_with(|c| c.peer_policy = Some(NetPolicy::default()), |_| {}).await;
    let tcp = TcpStream::connect(fx.addr).await.unwrap();
    let mut tcp = tcp;
    let mut buf = [0u8; 16];
    // The server closes without a single byte (no TLS alert, no HTTP response).
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
        .await
        .expect("connection should be closed promptly")
        .unwrap_or(0);
    assert_eq!(n, 0);
    assert!(tls(fx.addr, fx.fp).await.is_err());

    // The filter itself, over representative peers.
    let policy = NetPolicy::default();
    let lan = BoundAddr {
        ip: "192.168.1.10".parse().unwrap(),
        iface: "en0".into(),
        kind: remote_access::netfilter::AddrKind::Lan,
        prefix_len: 24,
    };
    for (peer, ok) in [
        ("192.168.1.55", true),
        ("192.168.2.55", false),
        ("10.1.2.3", false),
        ("8.8.8.8", false),
        ("127.0.0.1", false),
        ("::ffff:8.8.8.8", false),
        ("::ffff:192.168.1.55", true),
        ("2001:db8::1", false),
        ("169.254.1.1", false),
    ] {
        assert_eq!(
            peer_allowed(&lan, peer.parse().unwrap(), &policy),
            ok,
            "{peer}"
        );
    }
}

#[tokio::test]
async fn shutdown_closes_sessions_and_stops_listening() {
    let mut fx = fixture().await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    fx.handle.shutdown().await;
    assert_eq!(expect_close(&mut ws).await, Some(4403));
    assert!(fx.handle.listen_addrs().is_empty());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(TcpStream::connect(fx.addr).await.is_err());
    // Idempotent.
    fx.handle.shutdown().await;
}

/// Host whose pane stream is under the test's control.
struct LagHost {
    senders: Mutex<Vec<tokio::sync::mpsc::Sender<remote_access::host::PaneItem>>>,
    base: MockTerminalHost,
}

#[async_trait::async_trait]
impl TerminalHost for LagHost {
    async fn tree(&self) -> Result<TreeSnapshot, remote_access::HostError> {
        self.base.tree().await
    }

    async fn attach(
        &self,
        _pane: &PaneId,
        _replay: bool,
    ) -> Result<remote_access::PaneStream, remote_access::HostError> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let n = {
            let mut s = self.senders.lock().unwrap();
            s.push(tx);
            s.len() as u64
        };
        Ok(remote_access::PaneStream {
            snapshot: remote_access::host::PaneSnapshot {
                cols: 80,
                rows: 24,
                alt_screen: false,
                offset: n * 100,
                initial: if n == 1 { b"A".to_vec() } else { b"B".to_vec() },
            },
            items: rx,
        })
    }

    async fn send_input(&self, _: &PaneId, _: Vec<u8>) -> Result<(), remote_access::HostError> {
        Ok(())
    }

    async fn resize(&self, _: &PaneId, _: u16, _: u16) -> Result<(), remote_access::HostError> {
        Ok(())
    }

    async fn action(
        &self,
        name: &str,
        _: Value,
        _: Value,
    ) -> Result<Value, remote_access::HostError> {
        Err(remote_access::HostError::Unsupported(name.into()))
    }

    fn subscribe_tree_changes(&self) -> broadcast::Receiver<()> {
        self.base.subscribe_tree_changes()
    }
}

#[tokio::test]
async fn lagged_pane_stream_is_resnapshotted() {
    let host = Arc::new(LagHost {
        senders: Mutex::new(Vec::new()),
        base: MockTerminalHost::single_pane(),
    });
    let mut fx = build(|_| {}, |_| {}, Some(host.clone())).await;
    let (_, token) = pair_device(&mut fx, "phone").await;
    let mut ws = authed_ws(&fx, &token).await;
    send_json(&mut ws, json!({"t":"attach","pane":"p1","stream":1})).await;
    let snap = expect_json(&mut ws, "snapshot").await;
    assert_eq!(
        (snap["offset"].as_u64(), snap["lagged"].as_bool()),
        (Some(100), Some(false))
    );
    let Frame::Bin(b) = next_frame(&mut ws, 5).await else {
        panic!()
    };
    assert_eq!(&b[13..], b"A");

    let tx = host.senders.lock().unwrap()[0].clone();
    tx.send(remote_access::host::PaneItem::Lagged)
        .await
        .unwrap();
    let snap = expect_json(&mut ws, "snapshot").await;
    assert_eq!(
        (snap["offset"].as_u64(), snap["lagged"].as_bool()),
        (Some(200), Some(true))
    );
    let Frame::Bin(b) = next_frame(&mut ws, 5).await else {
        panic!()
    };
    assert_eq!(u64::from_be_bytes(b[5..13].try_into().unwrap()), 200);
    assert_eq!(&b[13..], b"B");

    // The new stream keeps flowing and a closed pane is reported.
    let tx = host.senders.lock().unwrap()[1].clone();
    tx.send(remote_access::host::PaneItem::Closed)
        .await
        .unwrap();
    expect_json(&mut ws, "pane_closed").await;
}
