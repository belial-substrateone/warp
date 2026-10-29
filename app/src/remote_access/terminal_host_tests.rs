use ::local_control::ActionKind;
use ::remote_access::host::{HostError, PaneEvent, PaneItem};
use serde_json::json;

use super::*;
use crate::workspace::view::tests::{initialize_app, mock_workspace};

fn event(alt_screen: bool) -> PaneEvent {
    PaneEvent {
        alt_screen,
        command_running: false,
        cwd: None,
        title: None,
    }
}

fn drain(stream: &mut PaneStream) -> Vec<PaneItem> {
    let mut items = Vec::new();
    while let Ok(item) = stream.items.try_recv() {
        items.push(item);
    }
    items
}

fn outputs(items: &[PaneItem]) -> Vec<(u64, Vec<u8>)> {
    items
        .iter()
        .filter_map(|item| match item {
            PaneItem::Output(chunk) => Some((chunk.offset, chunk.bytes.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn ring_keeps_only_the_newest_bytes_and_tracks_offsets() {
    let mut ring = Ring::new(8);
    assert_eq!(ring.push(b"abcd"), 0);
    assert_eq!(ring.push(b"efgh"), 4);
    assert_eq!(ring.base_offset(), 0);
    assert_eq!(ring.push(b"ij"), 8);
    assert_eq!(ring.contents(), b"cdefghij");
    assert_eq!(ring.base_offset(), 2);
    assert_eq!(ring.push(b"0123456789"), 10);
    assert_eq!(ring.contents(), b"23456789");
    assert_eq!(ring.base_offset(), 12);
    assert_eq!(ring.end_offset, 20);
}

#[test]
fn replay_resets_the_terminal_then_sends_the_ring_in_order() {
    let mut state = MirrorState::new(64, event(false));
    state.push(b"one ");
    state.push(b"two");
    let stream = state.subscribe(true, 80, 24, false);
    assert_eq!(stream.snapshot.initial, b"\x1bcone two");
    assert_eq!(stream.snapshot.offset, 0);
    assert_eq!((stream.snapshot.cols, stream.snapshot.rows), (80, 24));
}

#[test]
fn live_join_starts_at_the_end_of_the_stream() {
    let mut state = MirrorState::new(64, event(false));
    state.push(b"old");
    let mut stream = state.subscribe(false, 80, 24, false);
    assert!(stream.snapshot.initial.is_empty());
    assert_eq!(stream.snapshot.offset, 3);
    state.push(b"new");
    assert_eq!(outputs(&drain(&mut stream)), vec![(3, b"new".to_vec())]);
}

#[test]
fn replay_after_ring_wrap_reports_the_ring_start_offset() {
    let mut state = MirrorState::new(4, event(false));
    state.push(b"abcdef");
    let stream = state.subscribe(true, 80, 24, false);
    assert_eq!(stream.snapshot.initial, b"\x1bccdef");
    assert_eq!(stream.snapshot.offset, 2);
}

#[test]
fn alt_screen_replay_restores_the_alt_screen_when_the_ring_lost_it() {
    let mut state = MirrorState::new(64, event(true));
    state.push(b"frame");
    let stream = state.subscribe(true, 80, 24, true);
    assert_eq!(stream.snapshot.initial, b"\x1bc\x1b[?1049hframe");

    let mut state = MirrorState::new(64, event(true));
    state.push(b"\x1b[?1049hframe");
    let stream = state.subscribe(true, 80, 24, true);
    assert_eq!(stream.snapshot.initial, b"\x1bc\x1b[?1049hframe");
}

#[test]
fn large_output_is_split_and_offsets_stay_contiguous() {
    let mut state = MirrorState::new(RING_CAPACITY, event(false));
    let mut stream = state.subscribe(false, 80, 24, false);
    state.push(&vec![b'x'; OUTPUT_PIECE_BYTES * 2 + 5]);
    let chunks = outputs(&drain(&mut stream));
    assert_eq!(chunks.len(), 3);
    let mut expected = 0;
    for (offset, bytes) in chunks {
        assert_eq!(offset, expected);
        expected += bytes.len() as u64;
    }
    assert_eq!(expected, (OUTPUT_PIECE_BYTES * 2 + 5) as u64);
}

#[test]
fn slow_client_gets_lagged_in_its_reserved_slot_and_is_dropped() {
    let mut state = MirrorState::new(RING_CAPACITY, event(false));
    let mut slow = state.subscribe(false, 80, 24, false);
    for _ in 0..CLIENT_QUEUE_ITEMS * 2 {
        state.push(b"x");
    }
    assert_eq!(state.subscriber_count(), 0);
    let items = drain(&mut slow);
    assert_eq!(items.last(), Some(&PaneItem::Lagged));
    assert_eq!(items.len(), CLIENT_QUEUE_ITEMS);
    assert!(
        items[..items.len() - 1]
            .iter()
            .all(|item| matches!(item, PaneItem::Output(_)))
    );

    let fresh = state.subscribe(true, 80, 24, false);
    assert_eq!(fresh.snapshot.offset, 0);
    assert_eq!(
        fresh.snapshot.initial.len(),
        2 + CLIENT_QUEUE_ITEMS * 2,
        "resnapshot replays everything the slow client missed"
    );
}

#[test]
fn a_slow_client_does_not_affect_a_fast_one() {
    let mut state = MirrorState::new(RING_CAPACITY, event(false));
    let _slow = state.subscribe(false, 80, 24, false);
    let mut fast = state.subscribe(false, 80, 24, false);
    let mut received = 0;
    for _ in 0..CLIENT_QUEUE_ITEMS * 2 {
        state.push(b"x");
        received += outputs(&drain(&mut fast)).len();
    }
    assert_eq!(received, CLIENT_QUEUE_ITEMS * 2);
    assert_eq!(state.subscriber_count(), 1);
}

#[test]
fn dropped_clients_are_pruned() {
    let mut state = MirrorState::new(64, event(false));
    let stream = state.subscribe(false, 80, 24, false);
    assert_eq!(state.subscriber_count(), 1);
    drop(stream);
    state.prune();
    assert_eq!(state.subscriber_count(), 0);
}

#[test]
fn events_are_published_only_on_change() {
    let mut state = MirrorState::new(64, event(false));
    let mut stream = state.subscribe(false, 80, 24, false);
    state.publish_event(event(false));
    assert!(drain(&mut stream).is_empty());
    state.publish_event(event(true));
    state.publish_event(event(true));
    assert_eq!(drain(&mut stream), vec![PaneItem::Event(event(true))]);
}

#[test]
fn close_notifies_every_client_once() {
    let mut state = MirrorState::new(64, event(false));
    let mut a = state.subscribe(false, 80, 24, false);
    let mut b = state.subscribe(false, 80, 24, false);
    state.close();
    assert_eq!(drain(&mut a), vec![PaneItem::Closed]);
    assert_eq!(drain(&mut b), vec![PaneItem::Closed]);
    assert_eq!(state.subscriber_count(), 0);
}

#[test]
fn lag_all_tells_clients_to_resnapshot() {
    let mut state = MirrorState::new(64, event(false));
    let mut a = state.subscribe(false, 80, 24, false);
    state.lag_all();
    assert_eq!(drain(&mut a), vec![PaneItem::Lagged]);
}

#[test]
fn allowlisted_actions_map_to_local_control_kinds() {
    let cases = [
        ("tab.activate", ActionKind::TabActivate),
        ("tab.create", ActionKind::TabCreate),
        ("tab.close", ActionKind::TabClose),
        ("pane.focus", ActionKind::PaneFocus),
        ("pane.split", ActionKind::PaneSplit),
        ("pane.close", ActionKind::PaneClose),
        ("session.activate", ActionKind::SessionActivate),
    ];
    for (name, kind) in cases {
        let (planned, _) = plan_action(name, json!({})).unwrap();
        assert_eq!(planned, kind, "{name}");
    }
}

#[test]
fn everything_else_is_denied() {
    for name in [
        "window.close",
        "window.create",
        "app.focus",
        "theme.set",
        "setting.set",
        "setting.toggle",
        "keybinding.get",
        "input.insert",
        "tab.rename",
        "tab.move",
        "pane.resize",
        "surface.settings.open",
        "",
        "TAB.ACTIVATE",
    ] {
        let err = plan_action(name, json!({})).unwrap_err();
        assert_eq!(err.code(), "denied", "{name}");
    }
}

#[test]
fn bulk_tab_close_and_non_terminal_tabs_are_denied() {
    for mode in ["others", "right_of"] {
        let err = plan_action("tab.close", json!({ "mode": mode })).unwrap_err();
        assert!(matches!(err, HostError::Denied(_)), "{mode}");
    }
    assert!(plan_action("tab.close", json!({ "mode": "active" })).is_ok());
    let (_, params) = plan_action("tab.close", json!(null)).unwrap();
    assert_eq!(params, json!({ "mode": "target" }));
    let err = plan_action("tab.create", json!({ "tab_type": "agent" })).unwrap_err();
    assert!(matches!(err, HostError::Denied(_)));
    assert!(plan_action("tab.create", json!({ "tab_type": "terminal" })).is_ok());
    let (_, params) = plan_action("tab.activate", json!({})).unwrap();
    assert_eq!(params, json!({ "mode": "target" }));
    assert!(plan_action("pane.focus", json!("not an object")).is_err());
}

#[test]
fn targets_accept_shorthand_ids_and_typed_selectors() {
    let target = parse_target(&json!({
        "pane": "terminal_pane_1",
        "tab": { "type": "index", "index": 2 },
    }))
    .unwrap();
    assert!(matches!(target.pane, Some(PaneTarget::Id { id }) if id.0 == "terminal_pane_1"));
    assert!(matches!(target.tab, Some(TabTarget::Index { index: 2 })));
    assert!(target.window.is_none() && target.session.is_none());
    assert_eq!(
        parse_target(&json!(null)).unwrap(),
        TargetSelector::default()
    );
    assert!(parse_target(&json!("pane")).is_err());
    assert!(parse_target(&json!({ "pane": { "type": "bogus" } })).is_err());
}

#[test]
fn control_errors_map_to_host_errors() {
    let map = |code| host_error_from_control(ControlError::new(code, "x")).code();
    assert_eq!(map(ErrorCode::StaleTarget), "not_found");
    assert_eq!(map(ErrorCode::NotAllowlisted), "denied");
    assert_eq!(map(ErrorCode::UnsupportedAction), "unsupported");
    assert_eq!(map(ErrorCode::InvalidParams), "host_error");
}

fn active_pane(host_tree: &TreeSnapshot) -> PaneId {
    host_tree
        .windows
        .iter()
        .flat_map(|window| &window.tabs)
        .flat_map(|tab| &tab.panes)
        .find(|pane| pane.focused)
        .expect("a focused pane")
        .id
        .clone()
}

#[test]
fn attached_client_sees_terminal_output_and_late_replay() {
    warpui::App::test((), |mut app| async move {
        initialize_app(&mut app);
        let service = app.add_singleton_model(RemoteAccessService::new);
        let workspace = mock_workspace(&mut app);
        let host = service.update(&mut app, |_, ctx| AppTerminalHost::new(ctx));

        let tree = host.tree().await.expect("tree");
        assert_eq!(tree.windows.len(), 1);
        let pane = active_pane(&tree);
        let view = workspace.read(&app, |workspace, ctx| {
            workspace
                .active_tab_pane_group()
                .as_ref(ctx)
                .focused_session_view(ctx)
                .expect("focused terminal view")
        });
        let send = |bytes: &'static [u8]| {
            view.read(&app, |view, _| {
                view.model.lock().event_proxy.send_pty_read_event(bytes)
            })
        };
        let has_pty_stream =
            |app: &warpui::App| view.read(app, |view, ctx| view.subscribe_pty_reads(ctx).is_some());
        assert!(has_pty_stream(&app));

        // Nothing is copied while nobody is attached.
        send(b"before");
        let mut stream = host.attach(&pane, true).await.expect("attach");
        assert_eq!(stream.snapshot.initial, b"\x1bc");

        send(b"hello ");
        send(b"world");
        let mut seen = Vec::new();
        while seen.len() < 2 {
            match stream.items.recv().await.expect("stream open") {
                PaneItem::Output(chunk) => seen.push((chunk.offset, chunk.bytes)),
                PaneItem::Event(_) => {}
                other => panic!("unexpected item {other:?}"),
            }
        }
        assert_eq!(seen, vec![(0, b"hello ".to_vec()), (6, b"world".to_vec())]);

        let late = host.attach(&pane, true).await.expect("late attach");
        assert_eq!(late.snapshot.initial, b"\x1bchello world");
        drop(late);

        drop(stream);
        let missing = host.attach(&PaneId::from("nope"), true).await;
        assert!(matches!(missing, Err(HostError::NotFound(_))));
        assert!(matches!(
            host.resize(&pane, 100, 30).await,
            Err(HostError::Unsupported(_))
        ));
        let denied = host
            .action("window.close", json!({}), json!({}))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), "denied");
    });
}

/// A front-end without a workspace (the headless TUI) supplies its own panes.
struct FakeSource {
    reads: async_broadcast::InactiveReceiver<Arc<Vec<u8>>>,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
    handle_actions: bool,
}

struct FakeBackend {
    reads: async_broadcast::InactiveReceiver<Arc<Vec<u8>>>,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl PaneBackend for FakeBackend {
    fn subscribe_pty_reads(
        &self,
        _ctx: &AppContext,
    ) -> Option<async_broadcast::Receiver<Arc<Vec<u8>>>> {
        Some(self.reads.activate_cloned())
    }

    fn is_read_only(&self, _ctx: &AppContext) -> bool {
        false
    }

    fn write_input(&self, bytes: Vec<u8>, _ctx: &mut ModelContext<RemoteAccessService>) {
        lock(&self.writes).push(bytes);
    }
}

impl PaneSource for FakeSource {
    fn collect(&self, _ctx: &AppContext) -> (TreeSnapshot, HashMap<String, PaneRuntime>) {
        let pane = PaneNode {
            id: PaneId::from("pane:1"),
            session: "1".into(),
            title: "Terminal 1".into(),
            cwd: None,
            cols: 80,
            rows: 24,
            alt_screen: false,
            focused: true,
        };
        let tree = TreeSnapshot {
            windows: vec![WindowNode {
                id: "w".into(),
                title: "w".into(),
                tabs: vec![TabNode {
                    id: "tab:1".into(),
                    title: "t".into(),
                    active: true,
                    panes: vec![pane],
                }],
            }],
        };
        let runtime = PaneRuntime {
            backend: Box::new(FakeBackend {
                reads: self.reads.clone(),
                writes: self.writes.clone(),
            }),
            command_running: false,
        };
        (tree, HashMap::from([("pane:1".to_owned(), runtime)]))
    }

    fn layout_action(
        &self,
        name: &str,
        _target: &Value,
        _params: &Value,
        _ctx: &mut ModelContext<RemoteAccessService>,
    ) -> Option<Result<Value, HostError>> {
        self.handle_actions.then(|| Ok(json!({ "handled": name })))
    }
}

#[test]
fn a_custom_pane_source_gets_mirroring_input_and_the_action_allowlist() {
    warpui::App::test((), |mut app| async move {
        initialize_app(&mut app);
        let service = app.add_singleton_model(RemoteAccessService::new);
        let (tx, rx) = async_broadcast::broadcast(16);
        let writes = Arc::new(Mutex::new(Vec::new()));
        let make = |handle_actions| {
            Arc::new(FakeSource {
                reads: rx.clone().deactivate(),
                writes: writes.clone(),
                handle_actions,
            })
        };
        let host = service.update(&mut app, |_, ctx| AppTerminalHost::with_source(make(true), ctx));

        let tree = host.tree().await.expect("tree");
        let pane = tree.windows[0].tabs[0].panes[0].id.clone();
        let mut stream = host.attach(&pane, true).await.expect("attach");
        tx.broadcast(Arc::new(b"from the pty".to_vec())).await.expect("send");
        loop {
            match stream.items.recv().await.expect("stream open") {
                PaneItem::Output(chunk) => {
                    assert_eq!(chunk.bytes, b"from the pty");
                    break;
                }
                PaneItem::Event(_) => {}
                other => panic!("unexpected item {other:?}"),
            }
        }

        host.send_input(&pane, b"ls\r".to_vec()).await.expect("input");
        assert_eq!(*lock(&writes), vec![b"ls\r".to_vec()]);
        assert!(matches!(
            host.send_input(&PaneId::from("nope"), vec![1]).await,
            Err(HostError::NotFound(_))
        ));

        // Allowlisted layout actions go to the source; everything else is still denied.
        let ok = host.action("tab.create", json!({}), json!({})).await.expect("action");
        assert_eq!(ok, json!({ "handled": "tab.create" }));
        let denied = host.action("window.close", json!({}), json!({})).await.unwrap_err();
        assert_eq!(denied.code(), "denied");
        let denied = host
            .action("tab.create", json!({}), json!({ "tab_type": "agent" }))
            .await
            .unwrap_err();
        assert_eq!(denied.code(), "denied");

        // A source that does not handle layout actions and has no bridge: unsupported.
        let bare = service.update(&mut app, |_, ctx| AppTerminalHost::with_source(make(false), ctx));
        let unsupported = bare.action("tab.create", json!({}), json!({})).await.unwrap_err();
        assert_eq!(unsupported.code(), "unsupported");
    });
}
