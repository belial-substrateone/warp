//! The `/v1/ws` terminal socket: hello/auth, list/attach/detach/input/resize/action/ping/ack,
//! output pumping with ack-based backpressure, heartbeats and kill handling.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Extension;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;

use super::conn::PeerInfo;
use super::http::bearer;
use super::{Inner, LOG, ServerEvent, SessionInfo};
use crate::host::{HostError, PaneId, PaneItem, PaneSnapshot, PaneStream, TerminalHost};
use crate::protocol::{
    BACKPRESSURE_HIGH_BYTES, BinaryFrame, ClientMsg, Limits, MAX_BINARY_FRAME, PROTOCOL_VERSION,
    ParseError, ServerMsg, WS_SUBPROTOCOL, check_version, chunk_output, close_code,
    decode_binary_frame, encode_output_frame, error_code, parse_client_text,
};
use crate::ratelimit::TokenBucket;
use crate::tokens::{AuthError, DeviceId};

/// The only actions a remote client may request, whatever the host would accept.
pub const ALLOWED_ACTIONS: &[&str] = &[
    "tab.activate",
    "pane.focus",
    "pane.split",
    "tab.create",
    "tab.close",
    "pane.close",
];

const MAX_STREAMS: usize = 8;
const MAX_BACKGROUND_TASKS: usize = 16;
const OUT_QUEUE: usize = 32;
const WORK_QUEUE: usize = 64;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const ACK_STALL_TIMEOUT: Duration = Duration::from_secs(60);
const REVOCATION_CHECK: Duration = Duration::from_secs(2);
const MAX_RATE_VIOLATIONS: u32 = 10;

/// Removes the session from the registry and reports its end, even when the task is aborted.
pub(crate) struct SessionGuard {
    inner: Arc<Inner>,
    info: SessionInfo,
    reason: String,
}

impl SessionGuard {
    pub(super) fn new(inner: Arc<Inner>, info: SessionInfo) -> Self {
        Self {
            inner,
            info,
            reason: "connection closed".into(),
        }
    }

    fn set_reason(&mut self, reason: impl Into<String>) {
        self.reason = reason.into();
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.inner.remove_session(self.info.id) {
            log::info!(
                target: LOG,
                "session {} ({}) ended: {}",
                self.info.id,
                self.info.label,
                self.reason
            );
            self.inner.emit(ServerEvent::SessionDisconnected {
                session: self.info.clone(),
                reason: self.reason.clone(),
            });
        }
    }
}

struct UnauthSlot(Arc<Inner>);

impl UnauthSlot {
    fn try_acquire(inner: &Arc<Inner>) -> Option<Self> {
        let prev = inner.unauth.fetch_add(1, Ordering::AcqRel);
        if prev >= inner.cfg.max_unauthenticated_sockets {
            inner.unauth.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self(inner.clone()))
    }
}

impl Drop for UnauthSlot {
    fn drop(&mut self) {
        self.0.unauth.fetch_sub(1, Ordering::AcqRel);
    }
}

fn offers_subprotocol(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|p| p.trim() == WS_SUBPROTOCOL)
}

pub(super) async fn upgrade(
    State(inner): State<Arc<Inner>>,
    Extension(peer): Extension<PeerInfo>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !offers_subprotocol(&headers) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if inner.auth_locked_for().is_some() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let pre_auth = match bearer(&headers) {
        None => None,
        Some(token) => match inner
            .lock_registry()
            .authenticate(token, Some(peer.peer.ip()))
        {
            Ok(id) => Some(id),
            Err(_) => {
                inner.record_auth_failure();
                return StatusCode::UNAUTHORIZED.into_response();
            }
        },
    };
    let Some(slot) = UnauthSlot::try_acquire(&inner) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.protocols([WS_SUBPROTOCOL])
        .max_message_size(MAX_BINARY_FRAME)
        .max_frame_size(MAX_BINARY_FRAME)
        .on_upgrade(move |socket| run(inner, socket, peer.peer, pre_auth, slot))
}

/// Kills sessions whose device was revoked behind the server's back (e.g. directly in the registry).
pub(super) async fn revocation_watch(inner: Arc<Inner>) {
    let mut tick = tokio::time::interval(REVOCATION_CHECK);
    loop {
        tick.tick().await;
        let revoked: Vec<DeviceId> = {
            let registry = inner.lock_registry();
            inner
                .session_devices()
                .into_iter()
                .filter(|d| !registry.is_active(d))
                .collect()
        };
        for d in revoked {
            inner.kill_where("device revoked", |s| s.device_id == d);
        }
    }
}

// ---------------------------------------------------------------------------
// Frames and flow
// ---------------------------------------------------------------------------

enum Out {
    Msg(ServerMsg),
    Binary(Vec<u8>),
    Close(u16, &'static str),
}

enum Flow {
    Continue,
    Killed,
    Failed,
}

type KillRx = watch::Receiver<Option<String>>;

fn text(msg: &ServerMsg) -> Message {
    Message::Text(msg.to_text().into())
}

fn close_msg(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

async fn send(sock: &mut WebSocket, msg: Message, kill: &mut KillRx) -> Flow {
    tokio::select! {
        biased;
        _ = kill.changed() => Flow::Killed,
        r = tokio::time::timeout(WRITE_TIMEOUT, sock.send(msg)) => match r {
            Ok(Ok(())) => Flow::Continue,
            Ok(Err(_)) | Err(_) => Flow::Failed,
        },
    }
}

/// Sends a close frame and waits briefly for the peer so the frame is flushed before the TCP
/// connection goes away.
async fn close_socket(sock: &mut WebSocket, code: u16, reason: &str) {
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
        if sock.send(close_msg(code, reason)).await.is_ok() {
            while let Some(Ok(_)) = sock.recv().await {}
        }
    })
    .await;
}

struct HandshakeFail {
    code: u16,
    reason: &'static str,
    msg: Option<ServerMsg>,
}

impl HandshakeFail {
    fn new(code: u16, reason: &'static str) -> Self {
        Self {
            code,
            reason,
            msg: None,
        }
    }
}

/// Waits for the first frame, which must be `hello`, within the deadline, and authenticates it.
async fn handshake(
    inner: &Arc<Inner>,
    sock: &mut WebSocket,
    peer: SocketAddr,
    pre_auth: Option<DeviceId>,
) -> Result<DeviceId, HandshakeFail> {
    let first = tokio::time::timeout(inner.cfg.hello_deadline, async {
        loop {
            match sock.recv().await {
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                other => return other,
            }
        }
    })
    .await
    .map_err(|_| HandshakeFail::new(close_code::AUTH_FAILED, "hello timeout"))?;
    let Some(Ok(frame)) = first else {
        return Err(HandshakeFail::new(close_code::BAD_REQUEST, "closed"));
    };
    let Message::Text(t) = frame else {
        return Err(HandshakeFail::new(
            close_code::BAD_REQUEST,
            "hello must be the first frame",
        ));
    };
    let hello = match parse_client_text(t.as_str()) {
        Ok(ClientMsg::Hello { v, token, .. }) => (v, token),
        Ok(_) | Err(ParseError::UnknownType(_)) => {
            return Err(HandshakeFail::new(
                close_code::BAD_REQUEST,
                "hello must be the first frame",
            ));
        }
        Err(e) => {
            return Err(HandshakeFail {
                code: close_code::BAD_REQUEST,
                reason: "malformed hello",
                msg: Some(ServerMsg::error(e.error_code(), e.to_string())),
            });
        }
    };
    if let Err(msg) = check_version(hello.0) {
        return Err(HandshakeFail {
            code: close_code::BAD_REQUEST,
            reason: "unsupported version",
            msg: Some(msg),
        });
    }
    if let Some(device) = pre_auth {
        return Ok(device);
    }
    if inner.auth_locked_for().is_some() {
        return Err(HandshakeFail::new(close_code::RATE_LIMITED, "locked out"));
    }
    let auth = inner
        .lock_registry()
        .authenticate(hello.1.expose(), Some(peer.ip()));
    match auth {
        Ok(id) => Ok(id),
        Err(e) => {
            inner.record_auth_failure();
            Err(match e {
                AuthError::Revoked => HandshakeFail::new(close_code::KILLED, "device revoked"),
                AuthError::Unknown => HandshakeFail::new(close_code::AUTH_FAILED, "auth failed"),
                AuthError::Expired => HandshakeFail::new(close_code::AUTH_FAILED, "token expired"),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Output streams
// ---------------------------------------------------------------------------

/// Flow-control accounting for one attached stream.
struct Acct {
    sent: AtomicU64,
    acked: AtomicU64,
    wake: Notify,
}

impl Acct {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sent: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            wake: Notify::new(),
        })
    }

    fn in_flight(&self) -> u64 {
        self.sent
            .load(Ordering::Acquire)
            .saturating_sub(self.acked.load(Ordering::Acquire))
    }

    fn ack(&self, offset: u64) {
        self.acked.fetch_max(offset, Ordering::AcqRel);
        self.wake.notify_one();
    }

    fn reset_to(&self, offset: u64) {
        self.sent.store(offset, Ordering::Release);
        self.acked.store(offset, Ordering::Release);
    }
}

struct StreamHandle {
    pane: PaneId,
    abort: AbortHandle,
    acct: Arc<Acct>,
}

/// Returns false if the connection is gone.
async fn send_output(
    out: &mpsc::Sender<Out>,
    acct: &Acct,
    stream: u32,
    offset: u64,
    bytes: &[u8],
) -> bool {
    for (off, chunk) in chunk_output(offset, bytes) {
        while acct.in_flight() > BACKPRESSURE_HIGH_BYTES {
            let waited = tokio::time::timeout(ACK_STALL_TIMEOUT, acct.wake.notified()).await;
            if waited.is_err() {
                let _ = out.send(Out::Close(close_code::IDLE, "ack stall")).await;
                return false;
            }
        }
        let Ok(frame) = encode_output_frame(stream, off, chunk) else {
            return false;
        };
        acct.sent
            .fetch_max(off + chunk.len() as u64, Ordering::AcqRel);
        if out.send(Out::Binary(frame)).await.is_err() {
            return false;
        }
    }
    true
}

async fn send_snapshot(
    out: &mpsc::Sender<Out>,
    acct: &Acct,
    stream: u32,
    pane: &PaneId,
    snap: &PaneSnapshot,
    lagged: bool,
) -> bool {
    acct.reset_to(snap.offset);
    let msg = ServerMsg::Snapshot {
        stream,
        pane: pane.clone(),
        cols: snap.cols,
        rows: snap.rows,
        alt_screen: snap.alt_screen,
        offset: snap.offset,
        lagged,
    };
    if out.send(Out::Msg(msg)).await.is_err() {
        return false;
    }
    send_output(out, acct, stream, snap.offset, &snap.initial).await
}

fn host_error_msg(e: &HostError) -> ServerMsg {
    ServerMsg::error(e.code(), e.to_string())
}

async fn pump(
    host: Arc<dyn TerminalHost>,
    pane: PaneId,
    stream: u32,
    replay: bool,
    acct: Arc<Acct>,
    out: mpsc::Sender<Out>,
) {
    let mut ps: PaneStream = match host.attach(&pane, replay).await {
        Ok(ps) => ps,
        Err(e) => {
            let _ = out.send(Out::Msg(host_error_msg(&e))).await;
            return;
        }
    };
    if !send_snapshot(&out, &acct, stream, &pane, &ps.snapshot, false).await {
        return;
    }
    loop {
        let Some(item) = ps.items.recv().await else {
            let _ = out
                .send(Out::Msg(ServerMsg::PaneClosed { pane: pane.clone() }))
                .await;
            return;
        };
        match item {
            PaneItem::Output(chunk) => {
                if !send_output(&out, &acct, stream, chunk.offset, &chunk.bytes).await {
                    return;
                }
            }
            PaneItem::Event(e) => {
                let msg = ServerMsg::PaneState {
                    pane: pane.clone(),
                    alt_screen: e.alt_screen,
                    command_running: e.command_running,
                    cwd: e.cwd,
                    title: e.title,
                };
                if out.send(Out::Msg(msg)).await.is_err() {
                    return;
                }
            }
            PaneItem::Lagged => match host.attach(&pane, true).await {
                Ok(fresh) => {
                    ps = fresh;
                    if !send_snapshot(&out, &acct, stream, &pane, &ps.snapshot, true).await {
                        return;
                    }
                }
                Err(e) => {
                    let _ = out.send(Out::Msg(host_error_msg(&e))).await;
                    return;
                }
            },
            PaneItem::Closed => {
                let _ = out
                    .send(Out::Msg(ServerMsg::PaneClosed { pane: pane.clone() }))
                    .await;
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The connection
// ---------------------------------------------------------------------------

enum Work {
    Input(PaneId, Vec<u8>),
    Resize(PaneId, u16, u16),
}

async fn run(
    inner: Arc<Inner>,
    mut sock: WebSocket,
    peer: SocketAddr,
    pre_auth: Option<DeviceId>,
    slot: UnauthSlot,
) {
    let device = match handshake(&inner, &mut sock, peer, pre_auth).await {
        Ok(d) => d,
        Err(fail) => {
            if let Some(msg) = fail.msg {
                let _ = sock.send(text(&msg)).await;
            }
            log::debug!(target: LOG, "websocket from {} rejected: {}", peer.ip(), fail.reason);
            close_socket(&mut sock, fail.code, fail.reason).await;
            return;
        }
    };
    drop(slot);

    let label = inner
        .lock_registry()
        .get(&device)
        .map(|r| r.label)
        .unwrap_or_default();
    let Some((mut guard, mut kill)) =
        inner.register_session(device.clone(), label, Some(peer.ip()))
    else {
        let msg = ServerMsg::error(error_code::RATE_LIMITED, "too many remote sessions");
        let _ = sock.send(text(&msg)).await;
        close_socket(&mut sock, close_code::RATE_LIMITED, "too many sessions").await;
        return;
    };
    log::info!(target: LOG, "session started for device {}", device.0);

    let outcome = serve(&inner, &mut sock, &device, &mut kill).await;
    match outcome {
        Outcome::Killed => {
            let reason = kill
                .borrow()
                .clone()
                .unwrap_or_else(|| "killed from the PC".into());
            guard.set_reason(reason.clone());
            let _ = tokio::time::timeout(
                CLOSE_TIMEOUT,
                sock.send(text(&ServerMsg::SessionKilled {
                    reason: reason.clone(),
                })),
            )
            .await;
            close_socket(&mut sock, close_code::KILLED, "killed").await;
        }
        Outcome::Close(code, reason) => {
            guard.set_reason(reason);
            close_socket(&mut sock, code, reason).await;
        }
        Outcome::Gone => guard.set_reason("connection lost"),
    }
}

enum Outcome {
    Killed,
    Close(u16, &'static str),
    Gone,
}

struct Pending {
    msgs: Vec<Message>,
}

#[allow(clippy::too_many_lines)]
async fn serve(
    inner: &Arc<Inner>,
    sock: &mut WebSocket,
    device: &DeviceId,
    kill: &mut KillRx,
) -> Outcome {
    let cfg = &inner.cfg;
    let host = inner.host.clone();
    let (out_tx, mut out_rx) = mpsc::channel::<Out>(OUT_QUEUE);
    let (work_tx, mut work_rx) = mpsc::channel::<Work>(WORK_QUEUE);
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut streams: HashMap<u32, StreamHandle> = HashMap::new();
    let mut bucket = TokenBucket::new(cfg.input_rate_bytes_per_sec, cfg.input_burst_bytes);
    let mut violations = 0u32;
    let started = Instant::now();
    let mut tree_rx = host.subscribe_tree_changes();
    let mut tree_open = true;

    {
        let host = host.clone();
        let out = out_tx.clone();
        tasks.spawn(async move {
            while let Some(work) = work_rx.recv().await {
                let result = match work {
                    Work::Input(pane, bytes) => host.send_input(&pane, bytes).await,
                    Work::Resize(pane, cols, rows) => host.resize(&pane, cols, rows).await,
                };
                if let Err(e) = result
                    && out.send(Out::Msg(host_error_msg(&e))).await.is_err()
                {
                    return;
                }
            }
        });
    }

    let welcome = ServerMsg::Welcome {
        v: PROTOCOL_VERSION,
        device: device.0.clone(),
        server: cfg.server_name.clone(),
        limits: Limits::default(),
        phone_resize: cfg.phone_resize,
    };
    match send(sock, text(&welcome), kill).await {
        Flow::Continue => {}
        Flow::Killed => return Outcome::Killed,
        Flow::Failed => return Outcome::Gone,
    }

    let mut ping = tokio::time::interval(cfg.ping_interval);
    ping.tick().await;
    let silence = tokio::time::sleep(cfg.silence_timeout);
    tokio::pin!(silence);

    loop {
        let mut pending = Pending { msgs: Vec::new() };
        let mut close: Option<(u16, &'static str)> = None;
        tokio::select! {
            biased;
            _ = kill.changed() => return Outcome::Killed,
            () = &mut silence => return Outcome::Close(close_code::IDLE, "silence timeout"),
            _ = ping.tick() => pending.msgs.push(Message::Ping(Vec::new().into())),
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            out = out_rx.recv() => match out {
                Some(Out::Msg(m)) => pending.msgs.push(text(&m)),
                Some(Out::Binary(b)) => pending.msgs.push(Message::Binary(b.into())),
                Some(Out::Close(code, reason)) => close = Some((code, reason)),
                None => return Outcome::Gone,
            },
            changed = tree_rx.recv(), if tree_open => match changed {
                Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    pending.msgs.push(text(&ServerMsg::TreeChanged {}));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => tree_open = false,
            },
            frame = sock.recv() => {
                let Some(Ok(frame)) = frame else { return Outcome::Gone };
                silence
                    .as_mut()
                    .reset(tokio::time::Instant::now() + cfg.silence_timeout);
                match frame {
                    Message::Close(_) => return Outcome::Gone,
                    Message::Ping(_) | Message::Pong(_) => {}
                    Message::Text(t) => match parse_client_text(t.as_str()) {
                        Err(ParseError::TooLarge) => {
                            pending.msgs.push(text(&ServerMsg::error(
                                error_code::TOO_LARGE,
                                "text frame too large",
                            )));
                            close = Some((close_code::BAD_REQUEST, "frame too large"));
                        }
                        Err(e) => pending
                            .msgs
                            .push(text(&ServerMsg::error(e.error_code(), e.to_string()))),
                        Ok(msg) => {
                            let mut cx = Cx {
                                inner,
                                host: &host,
                                out: &out_tx,
                                work: &work_tx,
                                tasks: &mut tasks,
                                streams: &mut streams,
                                bucket: &mut bucket,
                                violations: &mut violations,
                                started,
                            };
                            if let Some(c) = handle_msg(&mut cx, msg, &mut pending) {
                                close = Some(c);
                            }
                        }
                    },
                    Message::Binary(b) => match decode_binary_frame(&b) {
                        Err(crate::protocol::FrameError::TooLarge) => {
                            pending.msgs.push(text(&ServerMsg::error(
                                error_code::TOO_LARGE,
                                "binary frame too large",
                            )));
                            close = Some((close_code::BAD_REQUEST, "frame too large"));
                        }
                        Err(e) => pending.msgs.push(text(&ServerMsg::error(
                            error_code::BAD_REQUEST,
                            e.to_string(),
                        ))),
                        Ok(BinaryFrame::Output { .. }) => pending.msgs.push(text(
                            &ServerMsg::error(error_code::BAD_REQUEST, "clients cannot send output"),
                        )),
                        Ok(BinaryFrame::Input { stream, payload }) => {
                            let mut cx = Cx {
                                inner,
                                host: &host,
                                out: &out_tx,
                                work: &work_tx,
                                tasks: &mut tasks,
                                streams: &mut streams,
                                bucket: &mut bucket,
                                violations: &mut violations,
                                started,
                            };
                            if let Some(c) = handle_input(&mut cx, stream, payload.to_vec(), &mut pending) {
                                close = Some(c);
                            }
                        }
                    },
                }
            }
        }

        for m in pending.msgs {
            match send(sock, m, kill).await {
                Flow::Continue => {}
                Flow::Killed => return Outcome::Killed,
                Flow::Failed => return Outcome::Gone,
            }
        }
        if let Some((code, reason)) = close {
            return Outcome::Close(code, reason);
        }
    }
}

struct Cx<'a> {
    inner: &'a Arc<Inner>,
    host: &'a Arc<dyn TerminalHost>,
    out: &'a mpsc::Sender<Out>,
    work: &'a mpsc::Sender<Work>,
    tasks: &'a mut JoinSet<()>,
    streams: &'a mut HashMap<u32, StreamHandle>,
    bucket: &'a mut TokenBucket,
    violations: &'a mut u32,
    started: Instant,
}

fn err_msg(code: &str, message: &str) -> Message {
    text(&ServerMsg::error(code, message))
}

fn handle_input(
    cx: &mut Cx<'_>,
    stream: u32,
    payload: Vec<u8>,
    pending: &mut Pending,
) -> Option<(u16, &'static str)> {
    let Some(handle) = cx.streams.get(&stream) else {
        pending
            .msgs
            .push(err_msg(error_code::NOT_ATTACHED, "stream is not attached"));
        return None;
    };
    let now_ms = u64::try_from(cx.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if !cx.bucket.try_take(payload.len() as u64, now_ms) {
        *cx.violations += 1;
        pending.msgs.push(err_msg(
            error_code::RATE_LIMITED,
            "input rate limit exceeded",
        ));
        return (*cx.violations >= MAX_RATE_VIOLATIONS)
            .then_some((close_code::RATE_LIMITED, "input rate limit"));
    }
    if cx
        .work
        .try_send(Work::Input(handle.pane.clone(), payload))
        .is_err()
    {
        pending
            .msgs
            .push(err_msg(error_code::RATE_LIMITED, "input queue full"));
    }
    None
}

fn handle_msg(
    cx: &mut Cx<'_>,
    msg: ClientMsg,
    pending: &mut Pending,
) -> Option<(u16, &'static str)> {
    match msg {
        ClientMsg::Hello { .. } => pending
            .msgs
            .push(err_msg(error_code::BAD_REQUEST, "already authenticated")),
        ClientMsg::List {} => {
            if cx.tasks.len() >= MAX_BACKGROUND_TASKS {
                pending.msgs.push(err_msg(
                    error_code::RATE_LIMITED,
                    "too many pending requests",
                ));
                return None;
            }
            let host = cx.host.clone();
            let out = cx.out.clone();
            cx.tasks.spawn(async move {
                let msg = match host.tree().await {
                    Ok(tree) => ServerMsg::Tree(tree),
                    Err(e) => host_error_msg(&e),
                };
                let _ = out.send(Out::Msg(msg)).await;
            });
        }
        ClientMsg::Attach {
            pane,
            stream,
            replay,
        } => {
            if let Some(old) = cx.streams.remove(&stream) {
                old.abort.abort();
            } else if cx.streams.len() >= MAX_STREAMS {
                pending.msgs.push(err_msg(
                    error_code::RATE_LIMITED,
                    "too many attached streams",
                ));
                return None;
            }
            let acct = Acct::new();
            let abort = cx.tasks.spawn(pump(
                cx.host.clone(),
                pane.clone(),
                stream,
                replay,
                acct.clone(),
                cx.out.clone(),
            ));
            cx.streams
                .insert(stream, StreamHandle { pane, abort, acct });
        }
        ClientMsg::Detach { stream } => {
            if let Some(h) = cx.streams.remove(&stream) {
                h.abort.abort();
            }
        }
        ClientMsg::Input { stream, text_b64 } => {
            match base64::engine::general_purpose::STANDARD.decode(text_b64.as_bytes()) {
                Ok(bytes) if bytes.len() <= crate::protocol::MAX_INPUT_PAYLOAD => {
                    return handle_input(cx, stream, bytes, pending);
                }
                Ok(_) => {
                    pending
                        .msgs
                        .push(err_msg(error_code::TOO_LARGE, "input too large"));
                    return Some((close_code::BAD_REQUEST, "frame too large"));
                }
                Err(_) => pending
                    .msgs
                    .push(err_msg(error_code::BAD_REQUEST, "text_b64 is not base64")),
            }
        }
        ClientMsg::Resize { stream, cols, rows } => {
            if !cx.inner.cfg.phone_resize {
                pending.msgs.push(err_msg(
                    error_code::RESIZE_DENIED,
                    "phone resize is disabled",
                ));
            } else if let Some(h) = cx.streams.get(&stream) {
                if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
                    pending
                        .msgs
                        .push(err_msg(error_code::BAD_REQUEST, "invalid size"));
                } else if cx
                    .work
                    .try_send(Work::Resize(h.pane.clone(), cols, rows))
                    .is_err()
                {
                    pending
                        .msgs
                        .push(err_msg(error_code::RATE_LIMITED, "input queue full"));
                }
            } else {
                pending
                    .msgs
                    .push(err_msg(error_code::NOT_ATTACHED, "stream is not attached"));
            }
        }
        ClientMsg::Action {
            id,
            name,
            target,
            params,
        } => {
            if !ALLOWED_ACTIONS.contains(&name.as_str()) {
                pending.msgs.push(text(&ServerMsg::action_err(
                    id,
                    "unsupported",
                    "unknown action",
                )));
            } else if cx.tasks.len() >= MAX_BACKGROUND_TASKS {
                pending.msgs.push(text(&ServerMsg::action_err(
                    id,
                    error_code::RATE_LIMITED,
                    "too many pending requests",
                )));
            } else {
                let host = cx.host.clone();
                let out = cx.out.clone();
                cx.tasks.spawn(async move {
                    let msg = match host.action(&name, target, params).await {
                        Ok(data) => ServerMsg::action_ok(id, data),
                        Err(e) => ServerMsg::action_err(id, e.code(), e.to_string()),
                    };
                    let _ = out.send(Out::Msg(msg)).await;
                });
            }
        }
        ClientMsg::Ping { n } => pending.msgs.push(text(&ServerMsg::Pong { n })),
        ClientMsg::Ack { stream, offset } => {
            if let Some(h) = cx.streams.get(&stream) {
                h.acct.ack(offset);
            }
        }
    }
    None
}
