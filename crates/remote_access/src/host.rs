//! The terminal-facing side of the server, implemented by the app (WP-B) and by
//! [`MockTerminalHost`] in tests.
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

/// Opaque pane selector (a `local_control` selector string).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PaneId(pub String);

impl fmt::Debug for PaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PaneId({})", self.0)
    }
}

impl fmt::Display for PaneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for PaneId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaneNode {
    pub id: PaneId,
    pub session: String,
    pub title: String,
    #[serde(default)]
    pub cwd: Option<String>,
    pub cols: u16,
    pub rows: u16,
    pub alt_screen: bool,
    pub focused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabNode {
    pub id: String,
    pub title: String,
    pub active: bool,
    pub panes: Vec<PaneNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowNode {
    pub id: String,
    pub title: String,
    pub tabs: Vec<TabNode>,
}

/// Payload of the `tree` server message.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TreeSnapshot {
    pub windows: Vec<WindowNode>,
}

impl TreeSnapshot {
    pub fn find_pane(&self, id: &PaneId) -> Option<&PaneNode> {
        self.windows
            .iter()
            .flat_map(|w| &w.tabs)
            .flat_map(|t| &t.panes)
            .find(|p| &p.id == id)
    }
}

/// State a late joiner needs before live output: the server sends
/// `snapshot {..}` and then `initial` as the first output bytes (typically
/// `ESC c` followed by the ring contents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneSnapshot {
    pub cols: u16,
    pub rows: u16,
    pub alt_screen: bool,
    /// Stream offset of the first byte of `initial`.
    pub offset: u64,
    pub initial: Vec<u8>,
}

/// Mode changes mirrored to clients as `pane_state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneEvent {
    pub alt_screen: bool,
    pub command_running: bool,
    pub cwd: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaneItem {
    Output(OutputChunk),
    Event(PaneEvent),
    /// The mirror dropped this client's queue; the server must resnapshot.
    Lagged,
    /// The pane went away.
    Closed,
}

/// Result of `attach`: the snapshot first, then a bounded item stream.
/// Dropping the stream detaches.
#[derive(Debug)]
pub struct PaneStream {
    pub snapshot: PaneSnapshot,
    pub items: mpsc::Receiver<PaneItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("denied: {0}")]
    Denied(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Failed(String),
}

impl HostError {
    /// Stable wire code for `error`/`result` messages.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "not_found",
            Self::Denied(_) => "denied",
            Self::Unsupported(_) => "unsupported",
            Self::Failed(_) => "host_error",
        }
    }
}

#[async_trait]
pub trait TerminalHost: Send + Sync + 'static {
    async fn tree(&self) -> Result<TreeSnapshot, HostError>;
    async fn attach(&self, pane: &PaneId, replay: bool) -> Result<PaneStream, HostError>;
    async fn send_input(&self, pane: &PaneId, bytes: Vec<u8>) -> Result<(), HostError>;
    async fn resize(&self, pane: &PaneId, cols: u16, rows: u16) -> Result<(), HostError>;
    async fn action(
        &self,
        name: &str,
        target: serde_json::Value,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, HostError>;
    fn subscribe_tree_changes(&self) -> broadcast::Receiver<()>;
}

#[cfg(any(test, feature = "test-util"))]
pub use mock::MockTerminalHost;

#[cfg(any(test, feature = "test-util"))]
mod mock {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct State {
        tree: TreeSnapshot,
        /// Bytes seen so far per pane (acts as the replay ring).
        ring: HashMap<PaneId, Vec<u8>>,
        subscribers: HashMap<PaneId, Vec<mpsc::Sender<PaneItem>>>,
        inputs: Vec<(PaneId, Vec<u8>)>,
        resizes: Vec<(PaneId, u16, u16)>,
        actions: Vec<(String, serde_json::Value, serde_json::Value)>,
    }

    /// In-memory host: output is injected with [`push_output`](Self::push_output)
    /// and everything the server sends is recorded for assertions.
    pub struct MockTerminalHost {
        state: Mutex<State>,
        tree_tx: broadcast::Sender<()>,
        queue: usize,
    }

    impl Default for MockTerminalHost {
        fn default() -> Self {
            Self::new(TreeSnapshot::default())
        }
    }

    impl MockTerminalHost {
        pub fn new(tree: TreeSnapshot) -> Self {
            let (tree_tx, _) = broadcast::channel(16);
            Self {
                state: Mutex::new(State {
                    tree,
                    ..State::default()
                }),
                tree_tx,
                queue: 64,
            }
        }

        /// A host with one window, one tab and one 80x24 pane `p1`.
        pub fn single_pane() -> Self {
            Self::new(TreeSnapshot {
                windows: vec![WindowNode {
                    id: "w1".into(),
                    title: "window".into(),
                    tabs: vec![TabNode {
                        id: "t1".into(),
                        title: "tab".into(),
                        active: true,
                        panes: vec![PaneNode {
                            id: "p1".into(),
                            session: "s1".into(),
                            title: "zsh".into(),
                            cwd: Some("/tmp".into()),
                            cols: 80,
                            rows: 24,
                            alt_screen: false,
                            focused: true,
                        }],
                    }],
                }],
            })
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// Replaces the tree and notifies subscribers.
        pub fn set_tree(&self, tree: TreeSnapshot) {
            self.lock().tree = tree;
            let _ = self.tree_tx.send(());
        }

        /// Feeds PTY output to the replay ring and every attached client.
        pub fn push_output(&self, pane: &PaneId, bytes: &[u8]) {
            let mut st = self.lock();
            let ring = st.ring.entry(pane.clone()).or_default();
            let offset = ring.len() as u64;
            ring.extend_from_slice(bytes);
            let item = PaneItem::Output(OutputChunk {
                offset,
                bytes: bytes.to_vec(),
            });
            if let Some(subs) = st.subscribers.get_mut(pane) {
                subs.retain(|s| match s.try_send(item.clone()) {
                    Ok(()) => true,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        let _ = s.try_send(PaneItem::Lagged);
                        true
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                });
            }
        }

        pub fn push_event(&self, pane: &PaneId, event: PaneEvent) {
            let mut st = self.lock();
            if let Some(subs) = st.subscribers.get_mut(pane) {
                subs.retain(|s| s.try_send(PaneItem::Event(event.clone())).is_ok());
            }
        }

        /// Closes the pane for attached clients.
        pub fn close_pane(&self, pane: &PaneId) {
            let mut st = self.lock();
            if let Some(subs) = st.subscribers.remove(pane) {
                for s in subs {
                    let _ = s.try_send(PaneItem::Closed);
                }
            }
        }

        pub fn notify_tree_changed(&self) {
            let _ = self.tree_tx.send(());
        }

        pub fn inputs(&self) -> Vec<(PaneId, Vec<u8>)> {
            self.lock().inputs.clone()
        }

        pub fn resizes(&self) -> Vec<(PaneId, u16, u16)> {
            self.lock().resizes.clone()
        }

        pub fn actions(&self) -> Vec<(String, serde_json::Value, serde_json::Value)> {
            self.lock().actions.clone()
        }

        pub fn attached_count(&self, pane: &PaneId) -> usize {
            self.lock()
                .subscribers
                .get(pane)
                .map(|v| v.iter().filter(|s| !s.is_closed()).count())
                .unwrap_or(0)
        }
    }

    #[async_trait]
    impl TerminalHost for MockTerminalHost {
        async fn tree(&self) -> Result<TreeSnapshot, HostError> {
            Ok(self.lock().tree.clone())
        }

        async fn attach(&self, pane: &PaneId, replay: bool) -> Result<PaneStream, HostError> {
            let mut st = self.lock();
            let node = st
                .tree
                .find_pane(pane)
                .cloned()
                .ok_or_else(|| HostError::NotFound(pane.to_string()))?;
            let ring = st.ring.get(pane).cloned().unwrap_or_default();
            let (tx, rx) = mpsc::channel(self.queue);
            st.subscribers.entry(pane.clone()).or_default().push(tx);
            let snapshot = if replay {
                let mut initial = b"\x1bc".to_vec();
                initial.extend_from_slice(&ring);
                PaneSnapshot {
                    cols: node.cols,
                    rows: node.rows,
                    alt_screen: node.alt_screen,
                    offset: 0,
                    initial,
                }
            } else {
                PaneSnapshot {
                    cols: node.cols,
                    rows: node.rows,
                    alt_screen: node.alt_screen,
                    offset: ring.len() as u64,
                    initial: Vec::new(),
                }
            };
            Ok(PaneStream {
                snapshot,
                items: rx,
            })
        }

        async fn send_input(&self, pane: &PaneId, bytes: Vec<u8>) -> Result<(), HostError> {
            let mut st = self.lock();
            if st.tree.find_pane(pane).is_none() {
                return Err(HostError::NotFound(pane.to_string()));
            }
            st.inputs.push((pane.clone(), bytes));
            Ok(())
        }

        async fn resize(&self, pane: &PaneId, cols: u16, rows: u16) -> Result<(), HostError> {
            let mut st = self.lock();
            if st.tree.find_pane(pane).is_none() {
                return Err(HostError::NotFound(pane.to_string()));
            }
            st.resizes.push((pane.clone(), cols, rows));
            Ok(())
        }

        async fn action(
            &self,
            name: &str,
            target: serde_json::Value,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, HostError> {
            const KNOWN: &[&str] = &[
                "tab.activate",
                "pane.focus",
                "pane.split",
                "tab.create",
                "tab.close",
                "pane.close",
            ];
            if !KNOWN.contains(&name) {
                return Err(HostError::Unsupported(name.to_string()));
            }
            self.lock().actions.push((name.to_string(), target, params));
            Ok(serde_json::json!({}))
        }

        fn subscribe_tree_changes(&self) -> broadcast::Receiver<()> {
            self.tree_tx.subscribe()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_attach_replay_and_live() {
        let host = MockTerminalHost::single_pane();
        let p = PaneId::from("p1");
        host.push_output(&p, b"old");
        let mut s = host.attach(&p, true).await.unwrap();
        assert_eq!(s.snapshot.initial, b"\x1bcold");
        assert_eq!((s.snapshot.cols, s.snapshot.rows), (80, 24));
        host.push_output(&p, b"new");
        assert_eq!(
            s.items.recv().await.unwrap(),
            PaneItem::Output(OutputChunk {
                offset: 3,
                bytes: b"new".to_vec()
            })
        );
        assert_eq!(host.attached_count(&p), 1);
        drop(s);
        assert_eq!(host.attached_count(&p), 0);

        let s = host.attach(&p, false).await.unwrap();
        assert!(s.snapshot.initial.is_empty());
        assert_eq!(s.snapshot.offset, 6);
    }

    #[tokio::test]
    async fn mock_records_input_and_errors() {
        let host = MockTerminalHost::single_pane();
        let p = PaneId::from("p1");
        host.send_input(&p, b"ls\n".to_vec()).await.unwrap();
        host.resize(&p, 100, 30).await.unwrap();
        assert_eq!(host.inputs(), vec![(p.clone(), b"ls\n".to_vec())]);
        assert_eq!(host.resizes(), vec![(p.clone(), 100, 30)]);
        let missing = PaneId::from("nope");
        assert_eq!(
            host.send_input(&missing, vec![]).await,
            Err(HostError::NotFound("nope".into()))
        );
        assert!(host.attach(&missing, true).await.is_err());
        assert!(
            host.action("tab.create", serde_json::json!({}), serde_json::json!({}))
                .await
                .is_ok()
        );
        let err = host
            .action("rm.rf", serde_json::Value::Null, serde_json::Value::Null)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "unsupported");
        assert_eq!(host.actions().len(), 1);
    }

    #[tokio::test]
    async fn mock_tree_changes_close_and_lag() {
        let host = MockTerminalHost::single_pane();
        let mut rx = host.subscribe_tree_changes();
        host.notify_tree_changed();
        rx.recv().await.unwrap();
        host.set_tree(TreeSnapshot::default());
        rx.recv().await.unwrap();
        assert!(host.tree().await.unwrap().windows.is_empty());

        let host = MockTerminalHost::single_pane();
        let p = PaneId::from("p1");
        let mut s = host.attach(&p, false).await.unwrap();
        for _ in 0..200 {
            host.push_output(&p, b"x");
        }
        let mut received = 0;
        while s.items.try_recv().is_ok() {
            received += 1;
        }
        // The queue is bounded: overflow is dropped, not buffered forever.
        assert!(received <= 64);
        host.close_pane(&p);
        assert_eq!(host.attached_count(&p), 0);
    }

    #[test]
    fn host_error_codes() {
        assert_eq!(HostError::Denied("x".into()).code(), "denied");
        assert_eq!(HostError::Failed("x".into()).code(), "host_error");
    }

    #[test]
    fn pane_id_serde_is_plain_string() {
        assert_eq!(serde_json::to_string(&PaneId::from("a")).unwrap(), "\"a\"");
    }
}
