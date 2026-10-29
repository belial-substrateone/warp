//! The headless TUI's side of phone remote access: exposes every terminal session as a one-pane
//! tab so a paired phone can mirror and type into it.
//!
//! The server, pairing, mirroring and input plumbing are shared with the GUI
//! (`warp::remote_access::terminal_host`); this only supplies the TUI's window/tab/pane tree and
//! the few layout actions that make sense without split panes.

use std::collections::HashMap;
use std::sync::Arc;

use remote_access::host::{
    HostError, PaneId, PaneNode, TabNode, TreeSnapshot, WindowNode,
};
use serde_json::{Value, json};
use warp::remote_access::{
    AppTerminalHost, PaneBackend, PaneRuntime, PaneSource, RemoteAccessService,
};
use warpui::{AppContext, ModelContext, SingletonEntity, ViewHandle};

use crate::session_registry::{TuiSessionId, TuiSessions};
use crate::terminal_session_view::TuiTerminalSessionView;

const WINDOW_ID: &str = "tui";

/// Makes the remote-access service mirror the TUI's sessions (no-op without the service).
pub(crate) fn install(ctx: &mut AppContext) {
    if !ctx.has_singleton_model::<RemoteAccessService>() {
        return;
    }
    RemoteAccessService::handle(ctx).update(ctx, |service, _| {
        service.set_host_factory(Box::new(|ctx| {
            AppTerminalHost::with_source(Arc::new(TuiPaneSource), ctx)
        }));
    });
}

fn session_key(id: TuiSessionId) -> String {
    id.surface_id().to_string()
}

fn tab_id(id: TuiSessionId) -> String {
    format!("tab:{}", session_key(id))
}

fn pane_id(id: TuiSessionId) -> String {
    format!("pane:{}", session_key(id))
}

/// Resolves `tab:<n>` / `pane:<n>` / `session:<n>` (or a bare `<n>`) to a registered session.
fn resolve_session(selector: &str, ctx: &AppContext) -> Option<TuiSessionId> {
    let key = selector.rsplit(':').next().unwrap_or(selector);
    TuiSessions::as_ref(ctx)
        .terminal_sessions()
        .into_iter()
        .map(|(id, _)| id)
        .find(|id| session_key(*id) == key)
}

/// The first selector string found under `tab`, `pane` or `session` in a layout-action target.
fn target_selector(target: &Value) -> Option<String> {
    ["tab", "pane", "session"].iter().find_map(|key| {
        match target.get(*key)? {
            Value::String(id) => Some(id.clone()),
            Value::Object(object) => object.get("id").and_then(Value::as_str).map(str::to_owned),
            _ => None,
        }
    })
}

struct TuiPaneSource;

impl PaneSource for TuiPaneSource {
    fn collect(&self, ctx: &AppContext) -> (TreeSnapshot, HashMap<String, PaneRuntime>) {
        let sessions = TuiSessions::as_ref(ctx);
        let focused = sessions.focused_session_id();
        let mut runtimes = HashMap::new();
        let mut tabs = Vec::new();
        for (index, (id, view)) in sessions.terminal_sessions().into_iter().enumerate() {
            let info = view.as_ref(ctx).remote_pane_info(ctx);
            let title = format!("Terminal {}", index + 1);
            let pane = PaneNode {
                id: PaneId(pane_id(id)),
                session: session_key(id),
                title: title.clone(),
                cwd: info.cwd,
                cols: info.cols,
                rows: info.rows,
                alt_screen: info.alt_screen,
                focused: true,
            };
            runtimes.insert(
                pane.id.0.clone(),
                PaneRuntime {
                    backend: Box::new(TuiPane {
                        view,
                        read_only: info.read_only,
                    }),
                    command_running: info.command_running,
                },
            );
            tabs.push(TabNode {
                id: tab_id(id),
                title,
                active: focused == Some(id),
                panes: vec![pane],
            });
        }
        let windows = if tabs.is_empty() {
            Vec::new()
        } else {
            vec![WindowNode {
                id: WINDOW_ID.to_owned(),
                title: "AnonWarp TUI".to_owned(),
                tabs,
            }]
        };
        (TreeSnapshot { windows }, runtimes)
    }

    fn layout_action(
        &self,
        name: &str,
        target: &Value,
        _params: &Value,
        ctx: &mut ModelContext<RemoteAccessService>,
    ) -> Option<Result<Value, HostError>> {
        Some(run_layout_action(name, target, ctx))
    }
}

fn run_layout_action(
    name: &str,
    target: &Value,
    ctx: &mut ModelContext<RemoteAccessService>,
) -> Result<Value, HostError> {
    let sessions = TuiSessions::handle(ctx);
    match name {
        "tab.create" => {
            let window_id = sessions
                .as_ref(ctx)
                .terminal_sessions()
                .first()
                .map(|(_, view)| view.window_id(ctx))
                .ok_or_else(|| {
                    HostError::Failed("no terminal session to open a tab next to".into())
                })?;
            let (id, _) = TuiSessions::create_local_terminal_session(
                &sessions, window_id, false, false, None, ctx,
            );
            Ok(json!({ "tab": tab_id(id), "pane": pane_id(id) }))
        }
        "tab.activate" | "pane.focus" | "session.activate" => {
            let id = selected_session(target, ctx)?;
            sessions.update(ctx, |sessions, ctx| {
                sessions.focus_session(id, ctx);
            });
            Ok(json!({}))
        }
        "tab.close" | "pane.close" => {
            let id = selected_session(target, ctx)?;
            if sessions.as_ref(ctx).terminal_sessions().len() <= 1 {
                return Err(HostError::Denied(
                    "the last terminal session cannot be closed remotely".into(),
                ));
            }
            sessions.update(ctx, |sessions, ctx| sessions.remove_session(id, ctx));
            Ok(json!({}))
        }
        other => Err(HostError::Unsupported(format!(
            "{other} is not available in the TUI (it has no split panes)"
        ))),
    }
}

fn selected_session(target: &Value, ctx: &AppContext) -> Result<TuiSessionId, HostError> {
    let selector = target_selector(target)
        .ok_or_else(|| HostError::Failed("target needs a tab, pane or session id".into()))?;
    resolve_session(&selector, ctx).ok_or_else(|| HostError::NotFound(selector))
}

struct TuiPane {
    view: ViewHandle<TuiTerminalSessionView>,
    read_only: bool,
}

impl PaneBackend for TuiPane {
    fn subscribe_pty_reads(
        &self,
        ctx: &AppContext,
    ) -> Option<async_broadcast::Receiver<Arc<Vec<u8>>>> {
        Some(self.view.as_ref(ctx).subscribe_pty_reads())
    }

    fn is_read_only(&self, _ctx: &AppContext) -> bool {
        self.read_only
    }

    fn write_input(&self, bytes: Vec<u8>, ctx: &mut ModelContext<RemoteAccessService>) {
        self.view.clone().update(ctx, |view, ctx| {
            view.write_remote_input(bytes, ctx);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_selectors_accept_shorthand_and_typed_ids() {
        assert_eq!(
            target_selector(&json!({ "tab": "tab:7" })).as_deref(),
            Some("tab:7")
        );
        assert_eq!(
            target_selector(&json!({ "pane": { "type": "id", "id": "pane:9" } })).as_deref(),
            Some("pane:9")
        );
        assert_eq!(target_selector(&json!({})), None);
        assert_eq!(target_selector(&json!({ "tab": 3 })), None);
    }
}
