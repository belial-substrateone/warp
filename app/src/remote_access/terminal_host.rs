//! The app side of the remote-access server's [`TerminalHost`]: window/tab/pane snapshots, a
//! per-pane PTY mirror fed by the existing PTY-read broadcast, raw input injection, and an
//! allowlisted bridge onto the local-control layout handlers.
//!
//! Threading: everything that touches WarpUI entities (views, models, the terminal model) runs on
//! the main thread through a [`ModelSpawner`]. The only state shared with server threads is
//! [`Shared`], whose mirrors are plain `Mutex`-guarded byte rings and bounded channels. The
//! per-pane pump task that drains the PTY broadcast runs on the background executor and only
//! touches that mutex-guarded state.
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use ::local_control::protocol::{
    PaneTarget, SessionTarget, TabCloseMode, TabCloseParams, TabTarget, TargetSelector,
    WindowTarget,
};
use ::local_control::{Action, ActionKind, ControlError, ErrorCode};
use ::remote_access::host::{
    HostError, OutputChunk, PaneEvent, PaneId, PaneItem, PaneNode, PaneSnapshot, PaneStream,
    TabNode, TerminalHost, TreeSnapshot, WindowNode,
};
use async_trait::async_trait;
use futures::future::Either;
use serde_json::{Value, json};
use tokio::sync::{broadcast, mpsc};
use warpui::r#async::Timer;
use warpui::{AppContext, ModelContext, ModelHandle, ModelSpawner, ViewHandle};

use super::RemoteAccessService;
use crate::local_control::LocalControlBridge;
use crate::terminal::TerminalView;
use crate::workspace::Workspace;

/// Bytes of recent output kept per mirrored pane for late joiners.
const RING_CAPACITY: usize = 1024 * 1024;
/// Output is split into pieces of at most this size before it is queued for a client.
const OUTPUT_PIECE_BYTES: usize = 16 * 1024;
/// Queue depth per client; with [`OUTPUT_PIECE_BYTES`] this bounds a client at about 4 MiB.
const CLIENT_QUEUE_ITEMS: usize = 256;
/// How often the main thread re-reads the window tree and per-pane state.
const POLL_INTERVAL: Duration = Duration::from_millis(300);
const RESET_TERMINAL: &[u8] = b"\x1bc";
const ENTER_ALT_SCREEN: &[u8] = b"\x1b[?1049h";
const ALT_SCREEN_ENTERS: [&[u8]; 3] = [b"\x1b[?1049h", b"\x1b[?1047h", b"\x1b[?47h"];

/// Constructor namespace for the app's [`TerminalHost`].
pub struct AppTerminalHost;

impl AppTerminalHost {
    /// The GUI host: panes are the terminal views of every workspace window, and layout actions
    /// go through the local-control bridge.
    pub fn new(ctx: &mut ModelContext<RemoteAccessService>) -> Arc<dyn TerminalHost> {
        // A private bridge model instead of the singleton: the singleton only exists when
        // local control is enabled, and its request path is gated by local-control settings.
        let bridge = ctx.add_model(LocalControlBridge::new);
        let bridge_spawner = bridge.update(ctx, |_, ctx| ctx.spawner());
        keep_alive(bridge, ctx);
        Self::build(Arc::new(GuiPaneSource), Some(bridge_spawner), ctx)
    }

    /// A host over any [`PaneSource`] (the headless TUI supplies its own). Layout actions that
    /// the source does not handle itself are reported as unsupported.
    pub fn with_source(
        source: Arc<dyn PaneSource>,
        ctx: &mut ModelContext<RemoteAccessService>,
    ) -> Arc<dyn TerminalHost> {
        Self::build(source, None, ctx)
    }

    fn build(
        source: Arc<dyn PaneSource>,
        bridge_spawner: Option<ModelSpawner<LocalControlBridge>>,
        ctx: &mut ModelContext<RemoteAccessService>,
    ) -> Arc<dyn TerminalHost> {
        let (tree_tx, _) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            mirrors: Mutex::new(HashMap::new()),
            tree_tx,
            last_tree: Mutex::new(None),
            source,
        });
        schedule_poll(Arc::downgrade(&shared), ctx);
        Arc::new(AppTerminalHostImpl {
            shared,
            spawner: ctx.spawner(),
            bridge_spawner,
        })
    }
}

/// Retains a model for as long as `ctx`'s model lives.
fn keep_alive(
    handle: ModelHandle<LocalControlBridge>,
    ctx: &mut ModelContext<RemoteAccessService>,
) {
    ctx.spawn(futures::future::pending::<()>(), move |_, _, _| {
        drop(handle);
    });
}

fn schedule_poll(shared: Weak<Shared>, ctx: &mut ModelContext<RemoteAccessService>) {
    ctx.spawn(Timer::after(POLL_INTERVAL), move |_, _, ctx| {
        let Some(strong) = shared.upgrade() else {
            return;
        };
        strong.poll(ctx);
        drop(strong);
        schedule_poll(shared, ctx);
    });
}

struct AppTerminalHostImpl {
    shared: Arc<Shared>,
    spawner: ModelSpawner<RemoteAccessService>,
    bridge_spawner: Option<ModelSpawner<LocalControlBridge>>,
}

#[async_trait]
impl TerminalHost for AppTerminalHostImpl {
    async fn tree(&self) -> Result<TreeSnapshot, HostError> {
        let source = self.shared.source.clone();
        self.on_main(move |_, ctx| source.collect(ctx).0).await
    }

    async fn attach(&self, pane: &PaneId, replay: bool) -> Result<PaneStream, HostError> {
        let shared = self.shared.clone();
        let pane = pane.clone();
        self.on_main(move |_, ctx| shared.attach(&pane, replay, ctx))
            .await?
    }

    async fn send_input(&self, pane: &PaneId, bytes: Vec<u8>) -> Result<(), HostError> {
        let pane = pane.clone();
        let source = self.shared.source.clone();
        self.on_main(move |_, ctx| {
            let (_, runtimes) = source.collect(ctx);
            let runtime = runtimes
                .get(&pane.0)
                .ok_or_else(|| HostError::NotFound(pane.to_string()))?;
            if runtime.backend.is_read_only(ctx) {
                return Err(HostError::Denied("pane is read-only".into()));
            }
            runtime.backend.write_input(bytes, ctx);
            Ok(())
        })
        .await?
    }

    async fn resize(&self, pane: &PaneId, _cols: u16, _rows: u16) -> Result<(), HostError> {
        Err(HostError::Unsupported(format!(
            "resizing {pane} from a remote client is not supported"
        )))
    }

    async fn action(&self, name: &str, target: Value, params: Value) -> Result<Value, HostError> {
        let (kind, params) = plan_action(name, params)?;
        let source = self.shared.source.clone();
        let (own_name, own_target, own_params) = (name.to_owned(), target.clone(), params.clone());
        if let Some(result) = self
            .on_main(move |_, ctx| source.layout_action(&own_name, &own_target, &own_params, ctx))
            .await?
        {
            return result;
        }
        let bridge_spawner = self
            .bridge_spawner
            .as_ref()
            .ok_or_else(|| HostError::Unsupported(format!("action {name} is not supported here")))?;
        let target = parse_target(&target)?;
        let action = Action { kind, params };
        bridge_spawner
            .spawn(move |bridge, ctx| bridge.execute_remote_action(action, target, ctx))
            .await
            .map_err(|_| HostError::Failed("the app is shutting down".into()))?
            .map_err(host_error_from_control)
    }

    fn subscribe_tree_changes(&self) -> broadcast::Receiver<()> {
        self.shared.tree_tx.subscribe()
    }
}

impl AppTerminalHostImpl {
    async fn on_main<R: Send + 'static>(
        &self,
        work: impl FnOnce(&mut RemoteAccessService, &mut ModelContext<RemoteAccessService>) -> R
        + Send
        + 'static,
    ) -> Result<R, HostError> {
        self.spawner
            .spawn(work)
            .await
            .map_err(|_| HostError::Failed("the app is shutting down".into()))
    }
}

struct Shared {
    mirrors: Mutex<HashMap<String, Mirror>>,
    tree_tx: broadcast::Sender<()>,
    last_tree: Mutex<Option<TreeSnapshot>>,
    source: Arc<dyn PaneSource>,
}

/// A live subscription to one pane's PTY reads. Dropping it stops the pump, which drops the
/// broadcast receiver so the terminal stops copying bytes.
struct Mirror {
    state: Arc<Mutex<MirrorState>>,
    _stop: async_channel::Sender<()>,
}

impl Shared {
    fn attach(
        &self,
        pane: &PaneId,
        replay: bool,
        ctx: &mut ModelContext<RemoteAccessService>,
    ) -> Result<PaneStream, HostError> {
        let (tree, runtimes) = self.source.collect(ctx);
        let node = tree
            .find_pane(pane)
            .ok_or_else(|| HostError::NotFound(pane.to_string()))?;
        let runtime = &runtimes[&pane.0];
        let mut mirrors = lock(&self.mirrors);
        if !mirrors.contains_key(&pane.0) {
            let rx = runtime
                .backend
                .subscribe_pty_reads(ctx)
                .ok_or_else(|| {
                    HostError::Unsupported("this pane has no local PTY byte stream".into())
                })?;
            let state = Arc::new(Mutex::new(MirrorState::new(
                RING_CAPACITY,
                pane_event(node, runtime),
            )));
            let (stop_tx, stop_rx) = async_channel::bounded(1);
            ctx.background_executor()
                .spawn(pump(rx, state.clone(), stop_rx))
                .detach();
            mirrors.insert(
                pane.0.clone(),
                Mirror {
                    state,
                    _stop: stop_tx,
                },
            );
        }
        let mirror = &mirrors[&pane.0];
        let stream = lock(&mirror.state).subscribe(replay, node.cols, node.rows, node.alt_screen);
        Ok(stream)
    }

    fn poll(&self, ctx: &mut ModelContext<RemoteAccessService>) {
        let watching_tree = self.tree_tx.receiver_count() > 0;
        if !watching_tree && lock(&self.mirrors).is_empty() {
            return;
        }
        let (tree, runtimes) = self.source.collect(ctx);
        if watching_tree {
            let mut last = lock(&self.last_tree);
            if last.as_ref() != Some(&tree) {
                *last = Some(tree.clone());
                let _ = self.tree_tx.send(());
            }
        }
        lock(&self.mirrors).retain(|id, mirror| {
            let mut state = lock(&mirror.state);
            state.prune();
            if state.subscriber_count() == 0 {
                return false;
            }
            let pane = PaneId(id.clone());
            let Some(node) = tree.find_pane(&pane) else {
                state.close();
                return false;
            };
            state.publish_event(pane_event(node, &runtimes[id]));
            true
        });
    }
}

async fn pump(
    mut rx: async_broadcast::Receiver<Arc<Vec<u8>>>,
    state: Arc<Mutex<MirrorState>>,
    stop: async_channel::Receiver<()>,
) {
    loop {
        let next = futures::future::select(Box::pin(rx.recv()), Box::pin(stop.recv())).await;
        match next {
            Either::Left((Ok(bytes), _)) => lock(&state).push(&bytes),
            Either::Left((Err(async_broadcast::RecvError::Overflowed(_)), _)) => {
                lock(&state).lag_all();
            }
            Either::Left((Err(async_broadcast::RecvError::Closed), _)) => {
                lock(&state).close();
                return;
            }
            Either::Right(_) => return,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Per-pane data that must stay on the main thread.
pub struct PaneRuntime {
    pub backend: Box<dyn PaneBackend>,
    pub command_running: bool,
}

/// Main-thread access to one pane's PTY.
pub trait PaneBackend {
    /// Subscribes to the raw PTY reads (`None` if the pane has no local PTY stream). The channel
    /// only copies bytes while a receiver is alive.
    fn subscribe_pty_reads(
        &self,
        ctx: &AppContext,
    ) -> Option<async_broadcast::Receiver<Arc<Vec<u8>>>>;
    fn is_read_only(&self, ctx: &AppContext) -> bool;
    /// Injects raw bytes as if typed into the pane.
    fn write_input(&self, bytes: Vec<u8>, ctx: &mut ModelContext<RemoteAccessService>);
}

/// Where a host gets its window/tab/pane tree from. Only ever called on the main thread.
pub trait PaneSource: Send + Sync + 'static {
    /// Every pane, keyed by the pane id string used in the tree.
    fn collect(&self, ctx: &AppContext) -> (TreeSnapshot, HashMap<String, PaneRuntime>);

    /// Runs an allowlisted layout action itself, or returns `None` to use the local-control
    /// bridge (the GUI behaviour). `name` has already passed the allowlist.
    fn layout_action(
        &self,
        _name: &str,
        _target: &Value,
        _params: &Value,
        _ctx: &mut ModelContext<RemoteAccessService>,
    ) -> Option<Result<Value, HostError>> {
        None
    }
}

/// Panes of the GUI app: the terminal views of every workspace window.
struct GuiPaneSource;

impl PaneSource for GuiPaneSource {
    fn collect(&self, ctx: &AppContext) -> (TreeSnapshot, HashMap<String, PaneRuntime>) {
        collect(ctx)
    }
}

struct GuiPane {
    view: ViewHandle<TerminalView>,
}

impl PaneBackend for GuiPane {
    fn subscribe_pty_reads(
        &self,
        ctx: &AppContext,
    ) -> Option<async_broadcast::Receiver<Arc<Vec<u8>>>> {
        self.view.as_ref(ctx).subscribe_pty_reads(ctx)
    }

    fn is_read_only(&self, ctx: &AppContext) -> bool {
        self.view.as_ref(ctx).model.lock().is_read_only()
    }

    fn write_input(&self, bytes: Vec<u8>, ctx: &mut ModelContext<RemoteAccessService>) {
        self.view.clone().update(ctx, |view, ctx| {
            view.write_to_pty(bytes, ctx);
        });
    }
}

fn pane_event(node: &PaneNode, runtime: &PaneRuntime) -> PaneEvent {
    PaneEvent {
        alt_screen: node.alt_screen,
        command_running: runtime.command_running,
        cwd: node.cwd.clone(),
        title: Some(node.title.clone()),
    }
}

/// Reads every window, tab and terminal pane. Ids are the same strings `local_control` uses.
fn collect(ctx: &AppContext) -> (TreeSnapshot, HashMap<String, PaneRuntime>) {
    let mut window_ids = ctx.window_ids().collect::<Vec<_>>();
    window_ids.sort_by_key(ToString::to_string);
    let mut runtimes = HashMap::new();
    let mut windows = Vec::new();
    for (window_index, window_id) in window_ids.into_iter().enumerate() {
        let Some(workspace) = ctx
            .views_of_type::<Workspace>(window_id)
            .and_then(|views| views.into_iter().next())
        else {
            continue;
        };
        let (tabs, active_tab) = workspace.read(ctx, |workspace, _| {
            (
                workspace.tab_views().cloned().collect::<Vec<_>>(),
                workspace.active_tab_index(),
            )
        });
        let mut tab_nodes = Vec::new();
        for (tab_index, pane_group) in tabs.into_iter().enumerate() {
            let (title, focused, pane_ids) = pane_group.read(ctx, |pane_group, ctx| {
                (
                    pane_group.display_title(ctx),
                    pane_group.focused_pane_id(ctx),
                    pane_group.visible_pane_ids(),
                )
            });
            let mut panes = Vec::new();
            for pane_id in pane_ids {
                let Some(view) = pane_group.read(ctx, |pane_group, ctx| {
                    pane_group.terminal_view_from_pane_id(pane_id, ctx)
                }) else {
                    continue;
                };
                let pane_title = pane_group.read(ctx, |pane_group, ctx| {
                    pane_group
                        .pane_by_id(pane_id)
                        .map(|pane| pane.pane_configuration().as_ref(ctx).title().to_owned())
                        .unwrap_or_default()
                });
                let (cols, rows, cwd, alt_screen, command_running) = {
                    let terminal = view.as_ref(ctx);
                    let size = terminal.size_info();
                    let model = terminal.model.lock();
                    (
                        size.columns(),
                        size.rows(),
                        terminal.pwd(),
                        model.is_alt_screen_active(),
                        model.block_list().active_block().is_executing(),
                    )
                };
                let id = pane_id.to_string();
                panes.push(PaneNode {
                    id: PaneId(id.clone()),
                    session: id.clone(),
                    title: pane_title,
                    cwd,
                    cols: u16::try_from(cols).unwrap_or(u16::MAX),
                    rows: u16::try_from(rows).unwrap_or(u16::MAX),
                    alt_screen,
                    focused: pane_id == focused,
                });
                runtimes.insert(
                    id,
                    PaneRuntime {
                        backend: Box::new(GuiPane { view }),
                        command_running,
                    },
                );
            }
            tab_nodes.push(TabNode {
                id: pane_group.id().to_string(),
                title,
                active: tab_index == active_tab,
                panes,
            });
        }
        windows.push(WindowNode {
            id: window_id.to_string(),
            title: format!("Window {}", window_index + 1),
            tabs: tab_nodes,
        });
    }
    (TreeSnapshot { windows }, runtimes)
}

/// Byte ring that remembers where its contents sit in the pane's output stream.
struct Ring {
    bytes: VecDeque<u8>,
    capacity: usize,
    end_offset: u64,
}

impl Ring {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            capacity,
            end_offset: 0,
        }
    }

    /// Appends `data` and returns the stream offset of its first byte.
    fn push(&mut self, data: &[u8]) -> u64 {
        let start = self.end_offset;
        self.end_offset += data.len() as u64;
        if data.len() >= self.capacity {
            self.bytes.clear();
            self.bytes.extend(&data[data.len() - self.capacity..]);
        } else {
            let overflow = (self.bytes.len() + data.len()).saturating_sub(self.capacity);
            self.bytes.drain(..overflow);
            self.bytes.extend(data);
        }
        start
    }

    fn base_offset(&self) -> u64 {
        self.end_offset - self.bytes.len() as u64
    }

    fn contents(&self) -> Vec<u8> {
        let (front, back) = self.bytes.as_slices();
        [front, back].concat()
    }
}

struct Subscriber {
    tx: mpsc::Sender<PaneItem>,
}

/// The ring and subscribers of one mirrored pane.
struct MirrorState {
    ring: Ring,
    subscribers: Vec<Subscriber>,
    last_event: PaneEvent,
}

impl MirrorState {
    fn new(ring_capacity: usize, initial_event: PaneEvent) -> Self {
        Self {
            ring: Ring::new(ring_capacity),
            subscribers: Vec::new(),
            last_event: initial_event,
        }
    }

    fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Registers a client. `replay` yields `ESC c` plus the ring; otherwise the client starts at
    /// the live end of the stream.
    fn subscribe(&mut self, replay: bool, cols: u16, rows: u16, alt_screen: bool) -> PaneStream {
        let (tx, items) = mpsc::channel(CLIENT_QUEUE_ITEMS);
        self.subscribers.push(Subscriber { tx });
        let (offset, initial) = if replay {
            (self.ring.base_offset(), self.replay_bytes(alt_screen))
        } else {
            (self.ring.end_offset, Vec::new())
        };
        PaneStream {
            snapshot: PaneSnapshot {
                cols,
                rows,
                alt_screen,
                offset,
                initial,
            },
            items,
        }
    }

    fn replay_bytes(&self, alt_screen: bool) -> Vec<u8> {
        let ring = self.ring.contents();
        let mut initial = Vec::with_capacity(ring.len() + 16);
        initial.extend_from_slice(RESET_TERMINAL);
        if alt_screen && !ALT_SCREEN_ENTERS.iter().any(|enter| contains(&ring, enter)) {
            initial.extend_from_slice(ENTER_ALT_SCREEN);
        }
        initial.extend_from_slice(&ring);
        initial
    }

    /// Appends PTY output and queues it for every client. A client whose queue is nearly full
    /// receives [`PaneItem::Lagged`] in the slot reserved for it and is dropped; the server
    /// resnapshots it by attaching again.
    fn push(&mut self, data: &[u8]) {
        for piece in data.chunks(OUTPUT_PIECE_BYTES) {
            let offset = self.ring.push(piece);
            self.subscribers.retain(|subscriber| {
                if subscriber.tx.is_closed() {
                    return false;
                }
                if subscriber.tx.capacity() <= 1 {
                    let _ = subscriber.tx.try_send(PaneItem::Lagged);
                    return false;
                }
                subscriber
                    .tx
                    .try_send(PaneItem::Output(OutputChunk {
                        offset,
                        bytes: piece.to_vec(),
                    }))
                    .is_ok()
            });
        }
    }

    /// Tells every client that bytes were lost upstream.
    fn lag_all(&mut self) {
        for subscriber in self.subscribers.drain(..) {
            let _ = subscriber.tx.try_send(PaneItem::Lagged);
        }
    }

    /// Sends `event` to every client if it differs from the last one published.
    fn publish_event(&mut self, event: PaneEvent) {
        if event == self.last_event {
            return;
        }
        self.last_event = event.clone();
        self.subscribers.retain(|subscriber| {
            !subscriber.tx.is_closed()
                && subscriber.tx.capacity() > 1
                && subscriber
                    .tx
                    .try_send(PaneItem::Event(event.clone()))
                    .is_ok()
        });
    }

    fn prune(&mut self) {
        self.subscribers
            .retain(|subscriber| !subscriber.tx.is_closed());
    }

    fn close(&mut self) {
        for subscriber in self.subscribers.drain(..) {
            let _ = subscriber.tx.try_send(PaneItem::Closed);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Maps a wire action name onto the local-control action it may run, normalizing and restricting
/// its parameters. Everything not listed here is denied.
fn plan_action(name: &str, params: Value) -> Result<(ActionKind, Value), HostError> {
    let kind = match name {
        "tab.activate" => ActionKind::TabActivate,
        "tab.create" => ActionKind::TabCreate,
        "tab.close" => ActionKind::TabClose,
        "pane.focus" => ActionKind::PaneFocus,
        "pane.split" => ActionKind::PaneSplit,
        "pane.close" => ActionKind::PaneClose,
        "session.activate" => ActionKind::SessionActivate,
        _ => return Err(HostError::Denied(format!("action {name} is not allowed"))),
    };
    let mut params = match params {
        Value::Null => json!({}),
        Value::Object(map) => Value::Object(map),
        _ => return Err(HostError::Failed("params must be an object".into())),
    };
    let object = params.as_object_mut().expect("params is an object");
    match kind {
        ActionKind::TabActivate => {
            object.entry("mode").or_insert_with(|| json!("target"));
        }
        ActionKind::TabClose => {
            object.entry("mode").or_insert_with(|| json!("target"));
            let mode = serde_json::from_value::<TabCloseParams>(params.clone())
                .map_err(|err| HostError::Failed(format!("invalid tab.close params: {err}")))?
                .mode;
            if !matches!(mode, TabCloseMode::Target | TabCloseMode::Active) {
                return Err(HostError::Denied("tab.close may only close one tab".into()));
            }
        }
        ActionKind::TabCreate => {
            let tab_type = object.get("tab_type").and_then(Value::as_str);
            if !matches!(tab_type, None | Some("terminal" | "default")) {
                return Err(HostError::Denied(
                    "tab.create may only create terminal tabs".into(),
                ));
            }
        }
        _ => {}
    }
    Ok((kind, params))
}

/// Accepts a [`TargetSelector`], or the shorthand `{"pane": "<id>"}` (likewise `tab`, `window`,
/// `session`) where a bare string stands for an id selector.
fn parse_target(target: &Value) -> Result<TargetSelector, HostError> {
    let invalid = |err: serde_json::Error| HostError::Failed(format!("invalid target: {err}"));
    let mut selector = TargetSelector::default();
    let object = match target {
        Value::Null => return Ok(selector),
        Value::Object(object) => object,
        _ => return Err(HostError::Failed("target must be an object".into())),
    };
    let field = |key: &str| {
        object
            .get(key)
            .filter(|value| !value.is_null())
            .map(|value| match value {
                Value::String(id) => json!({ "type": "id", "id": id }),
                other => other.clone(),
            })
    };
    if let Some(value) = field("window") {
        selector.window = Some(serde_json::from_value::<WindowTarget>(value).map_err(invalid)?);
    }
    if let Some(value) = field("tab") {
        selector.tab = Some(serde_json::from_value::<TabTarget>(value).map_err(invalid)?);
    }
    if let Some(value) = field("pane") {
        selector.pane = Some(serde_json::from_value::<PaneTarget>(value).map_err(invalid)?);
    }
    if let Some(value) = field("session") {
        selector.session = Some(serde_json::from_value::<SessionTarget>(value).map_err(invalid)?);
    }
    Ok(selector)
}

fn host_error_from_control(error: ControlError) -> HostError {
    let message = error.message;
    match error.code {
        ErrorCode::StaleTarget | ErrorCode::MissingTarget => HostError::NotFound(message),
        ErrorCode::NotAllowlisted | ErrorCode::InsufficientPermissions => {
            HostError::Denied(message)
        }
        ErrorCode::UnsupportedAction => HostError::Unsupported(message),
        ErrorCode::LocalControlDisabled
        | ErrorCode::UnauthorizedLocalClient
        | ErrorCode::ProtocolVersionUnsupported
        | ErrorCode::InvalidRequest
        | ErrorCode::InvalidSelector
        | ErrorCode::InvalidParams
        | ErrorCode::NoInstance
        | ErrorCode::AmbiguousInstance
        | ErrorCode::AmbiguousTarget
        | ErrorCode::TargetStateConflict
        | ErrorCode::TransportUnavailable
        | ErrorCode::BridgeUnavailable
        | ErrorCode::Internal => HostError::Failed(message),
    }
}

#[cfg(test)]
#[path = "terminal_host_tests.rs"]
mod tests;
