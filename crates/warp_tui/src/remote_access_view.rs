//! `/remote-access`: TUI front-end for the phone remote-access service.
//!
//! Shows the enable toggle, listening addresses and certificate fingerprint, arms pairing and
//! renders its QR code with unicode half-blocks, lists paired devices (revoke) and active sessions
//! (kill all), and hosts the Approve/Deny prompt for incoming pairing requests. All state lives in
//! the shared `RemoteAccessService` singleton; this view only mirrors it.

use std::time::Duration;

use qrcode::{Color as QrColor, QrCode};
use warp::remote_access::{PairingQr, RemoteAccessEvent, RemoteAccessService};
use warpui::SingletonEntity;
use warpui_core::elements::tui::{
    Color, Modifier, TuiAnimated, TuiContainer, TuiElement, TuiFlex, TuiStyle, TuiText,
};
use warpui_core::keymap::macros::*;
use warpui_core::keymap::FixedBinding;
use warpui_core::{AppContext, Entity, TuiView, TypedActionView, ViewContext};

use crate::keybindings::{TUI_BINDING_GROUP, is_tui_owned_binding};
use crate::tui_builder::TuiUiBuilder;

const ACTIVE: &str = "TuiRemoteAccessActive";
const APPROVAL: &str = "TuiRemoteAccessApproval";
const PAIRING: &str = "TuiRemoteAccessPairing";
const QUIET_ZONE: usize = 2;
const URL_CHUNK: usize = 64;

pub(crate) fn init(app: &mut AppContext) {
    let active = id!(TuiRemoteAccessView::ui_name()) & id!(ACTIVE);
    let browsing = active.clone() & !id!(APPROVAL);
    let approving = active & id!(APPROVAL);
    let fixed = |key: &'static str, action, predicate: warpui_core::keymap::ContextPredicate| {
        FixedBinding::new(key, action, predicate).with_group(TUI_BINDING_GROUP)
    };
    app.register_fixed_bindings([
        fixed("escape", TuiRemoteAccessAction::Close, browsing.clone()),
        fixed("t", TuiRemoteAccessAction::ToggleEnabled, browsing.clone()),
        fixed("p", TuiRemoteAccessAction::TogglePairing, browsing.clone()),
        fixed("up", TuiRemoteAccessAction::SelectPrevious, browsing.clone()),
        fixed("down", TuiRemoteAccessAction::SelectNext, browsing.clone()),
        fixed("r", TuiRemoteAccessAction::RevokeSelected, browsing.clone()),
        fixed("k", TuiRemoteAccessAction::KillAllSessions, browsing),
        // Deliberately no Enter/Escape here: nothing is pre-selected, the user must press y or n.
        fixed("y", TuiRemoteAccessAction::Approve, approving.clone()),
        fixed("n", TuiRemoteAccessAction::Deny, approving),
    ]);
    app.register_tui_binding_validator::<TuiRemoteAccessView>(is_tui_owned_binding);
}

#[derive(Clone, Debug)]
pub(crate) enum TuiRemoteAccessAction {
    Close,
    ToggleEnabled,
    TogglePairing,
    SelectPrevious,
    SelectNext,
    RevokeSelected,
    KillAllSessions,
    Approve,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TuiRemoteAccessEvent {
    Closed,
}

pub(crate) struct TuiRemoteAccessView {
    qr: Option<ArmedPairing>,
    selected_device: usize,
    message: Option<String>,
}

struct ArmedPairing {
    qr: PairingQr,
    lines: Vec<String>,
}

impl TuiRemoteAccessView {
    pub(crate) fn new(ctx: &mut ViewContext<Self>) -> Self {
        let service = RemoteAccessService::handle(ctx);
        ctx.subscribe_to_model(&service, |view, _, event, ctx| {
            match event {
                // A completed pairing consumes the armed secret.
                RemoteAccessEvent::DevicesChanged => view.qr = None,
                RemoteAccessEvent::StateChanged => {
                    if !RemoteAccessService::as_ref(ctx).is_enabled() {
                        view.qr = None;
                    }
                }
                RemoteAccessEvent::ApprovalRequested(_) | RemoteAccessEvent::SessionsChanged => {}
            }
            ctx.notify();
        });
        Self {
            qr: None,
            selected_device: 0,
            message: None,
        }
    }

    pub(crate) fn focus(&self, ctx: &mut ViewContext<Self>) {
        ctx.focus_self();
    }

    fn live_devices(app: &AppContext) -> Vec<remote_access::tokens::DeviceRecord> {
        RemoteAccessService::as_ref(app)
            .devices()
            .into_iter()
            .filter(|device| !device.revoked)
            .collect()
    }

    fn render_body(&self, app: &AppContext) -> TuiFlex {
        let builder = TuiUiBuilder::from_app(app);
        let service = RemoteAccessService::as_ref(app);
        let primary = builder.primary_text_style();
        let muted = builder.muted_text_style();
        let bold = primary.add_modifier(Modifier::BOLD);
        let mut body = TuiFlex::column().child(text("Remote access (phone)", bold));

        if let Some(approval) = service.pending_approvals().first() {
            let lines = approval_prompt_lines(
                &approval.device_name,
                &approval.platform,
                approval.ip.map(|ip| ip.to_string()).as_deref(),
                service.fingerprint_display().as_deref(),
            );
            body = body.child(text(" ", muted));
            for (index, line) in lines.into_iter().enumerate() {
                let style = if index == 0 { bold } else { primary };
                body = body.child(text(line, style));
            }
            body = body.child(text(" ", muted));
            body = body.child(
                TuiText::from_spans([
                    ("y ".to_owned(), primary),
                    ("Approve   ".to_owned(), muted),
                    ("n ".to_owned(), primary),
                    ("Deny".to_owned(), muted),
                ])
                .truncate()
                .finish(),
            );
            return body;
        }

        let enabled = service.is_enabled();
        body = body.child(text(" ", muted));
        body = body.child(text(
            if enabled { "Status: ON" } else { "Status: OFF" },
            if enabled {
                builder.success_glyph_style()
            } else {
                muted
            },
        ));
        if enabled {
            let addrs = service
                .listen_addrs()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            body = body.child(text(
                if addrs.is_empty() {
                    "Listening on: (no private-network address found)".to_owned()
                } else {
                    format!("Listening on: {}", addrs.join(", "))
                },
                primary,
            ));
            if let Some(fingerprint) = service.fingerprint_display() {
                body = body.child(text(format!("Cert fingerprint: {fingerprint}"), primary));
            }
        }

        if let Some(armed) = &self.qr {
            body = body.child(text(" ", muted));
            let qr_style = TuiStyle::default().fg(Color::Black).bg(Color::White);
            for line in &armed.lines {
                body = body.child(text(line.clone(), qr_style));
            }
            body = body.child(text(" ", muted));
            for chunk in wrap_chunks(&armed.qr.url, URL_CHUNK) {
                body = body.child(text(chunk, primary));
            }
            let expires_at = armed.qr.expires_at;
            body = body.child(
                TuiAnimated::new(Duration::from_secs(1), move || {
                    let remaining = expires_at - now_unix();
                    let style = if remaining > 0 { primary } else { muted };
                    text(pairing_expiry_text(remaining), style)
                })
                .finish(),
            );
            body = body.child(text(" ", muted));
            body = body.child(hint_row(&[("p ", "Cancel pairing   "), ("Esc ", "Cancel")], &builder));
        } else {
            if enabled {
                let devices = Self::live_devices(app);
                let now = now_unix();
                body = body.child(text(" ", muted));
                body = body.child(text(format!("Paired devices ({})", devices.len()), bold));
                if devices.is_empty() {
                    body = body.child(text("  none yet", muted));
                }
                for (index, device) in devices.iter().enumerate() {
                    let selected = index == self.selected_device.min(devices.len() - 1);
                    body = body.child(text(
                        device_row_text(device, now, selected),
                        if selected { primary } else { muted },
                    ));
                }
                let sessions = service.active_sessions();
                body = body.child(text(" ", muted));
                body = body.child(text(format!("Active sessions ({})", sessions.len()), bold));
                for session in &sessions {
                    body = body.child(text(session_row_text(session, now), muted));
                }
            }
            body = body.child(text(" ", muted));
            let mut hints = vec![("t ", if enabled { "Disable   " } else { "Enable   " })];
            if enabled {
                hints.push(("p ", "Pair a phone   "));
                hints.push(("↑↓ ", "Select   "));
                hints.push(("r ", "Revoke   "));
                hints.push(("k ", "Kill all sessions   "));
            }
            hints.push(("Esc ", "Close"));
            body = body.child(hint_row(&hints, &builder));
        }
        if let Some(message) = &self.message {
            body = body.child(text(message.clone(), builder.error_text_style()));
        }
        body
    }
}

fn text(content: impl Into<String>, style: TuiStyle) -> Box<dyn TuiElement> {
    TuiText::new(content.into())
        .with_style(style)
        .truncate()
        .finish()
}

fn hint_row(hints: &[(&str, &str)], builder: &TuiUiBuilder) -> Box<dyn TuiElement> {
    let spans = hints.iter().flat_map(|(key, label)| {
        [
            ((*key).to_owned(), builder.primary_text_style()),
            ((*label).to_owned(), builder.muted_text_style()),
        ]
    });
    TuiText::from_spans(spans.collect::<Vec<_>>())
        .truncate()
        .finish()
}

pub(crate) fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Splits `s` into pieces of at most `width` characters.
pub(crate) fn wrap_chunks(s: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    chars
        .chunks(width.max(1))
        .map(|chunk| chunk.iter().collect())
        .collect()
}

/// Renders `data` as a QR code using `▀ ▄ █` and space: two matrix rows per text row, with a
/// light quiet zone of [`QUIET_ZONE`] modules. Dark modules are the foreground (paint with a black
/// foreground on a white background so it scans regardless of the terminal theme).
pub(crate) fn qr_half_block_lines(data: &str) -> Option<Vec<String>> {
    let code = QrCode::new(data.as_bytes()).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let dark = |x: isize, y: isize| -> bool {
        x >= 0
            && y >= 0
            && (x as usize) < width
            && (y as usize) < width
            && colors[y as usize * width + x as usize] == QrColor::Dark
    };
    let q = QUIET_ZONE as isize;
    let total = width as isize + 2 * q;
    let mut lines = Vec::new();
    let mut y = -q;
    while y < total - q {
        let line = (-q..total - q)
            .map(|x| match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            })
            .collect();
        lines.push(line);
        y += 2;
    }
    Some(lines)
}

/// "Expires in 4:32", or a re-arm hint once the secret has expired.
pub(crate) fn pairing_expiry_text(remaining_secs: i64) -> String {
    if remaining_secs <= 0 {
        "Code expired. Press p to cancel, then p again for a new one.".to_owned()
    } else {
        format!(
            "Expires in {}:{:02}",
            remaining_secs / 60,
            remaining_secs % 60
        )
    }
}

/// Text of the approval prompt (title first). `fingerprint` is the certificate fingerprint the
/// phone is expected to be displaying/pinning, for comparison.
pub(crate) fn approval_prompt_lines(
    name: &str,
    platform: &str,
    ip: Option<&str>,
    fingerprint: Option<&str>,
) -> Vec<String> {
    let mut lines = vec![
        "A phone wants to pair".to_owned(),
        format!("Name:        {name}"),
        format!("Platform:    {platform}"),
        format!("IP address:  {}", ip.unwrap_or("unknown")),
    ];
    if let Some(fingerprint) = fingerprint {
        lines.push(format!("Fingerprint: {fingerprint}"));
    }
    lines.push("Only approve if this is your phone and the fingerprint matches.".to_owned());
    lines
}

fn relative_age(now: i64, then: i64) -> String {
    let secs = (now - then).max(0);
    match secs {
        0..=59 => "just now".to_owned(),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

pub(crate) fn device_row_text(
    device: &remote_access::tokens::DeviceRecord,
    now: i64,
    selected: bool,
) -> String {
    format!(
        "{} {} ({}) {} seen {}",
        if selected { ">" } else { " " },
        device.label,
        device.platform,
        device
            .last_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".to_owned()),
        relative_age(now, device.last_seen),
    )
}

fn session_row_text(session: &warp::remote_access::ActiveSession, now: i64) -> String {
    format!(
        "  {} {} connected {}",
        session.label,
        session
            .ip
            .map(|ip| format!("({ip})"))
            .unwrap_or_default(),
        relative_age(now, session.since),
    )
}

/// Status-line indicator text while at least one phone is connected.
pub(crate) fn status_indicator_text(sessions: usize) -> Option<String> {
    match sessions {
        0 => None,
        1 => Some("📱 phone connected".to_owned()),
        n => Some(format!("📱 {n} phones connected")),
    }
}

impl Entity for TuiRemoteAccessView {
    type Event = TuiRemoteAccessEvent;
}

impl TuiView for TuiRemoteAccessView {
    fn ui_name() -> &'static str {
        "TuiRemoteAccessView"
    }

    fn keymap_context(&self, app: &AppContext) -> warpui_core::keymap::Context {
        let mut context = Self::default_keymap_context();
        context.set.insert(ACTIVE);
        if !RemoteAccessService::as_ref(app).pending_approvals().is_empty() {
            context.set.insert(APPROVAL);
        }
        if self.qr.is_some() {
            context.set.insert(PAIRING);
        }
        context
    }

    fn render(&self, app: &AppContext) -> Box<dyn TuiElement> {
        let builder = TuiUiBuilder::from_app(app);
        TuiContainer::new(self.render_body(app).finish())
            .with_padding(1)
            .with_background(builder.question_surface_background())
            .finish()
    }
}

impl TypedActionView for TuiRemoteAccessView {
    type Action = TuiRemoteAccessAction;

    fn handle_action(&mut self, action: &Self::Action, ctx: &mut ViewContext<Self>) {
        let service = RemoteAccessService::handle(ctx);
        self.message = None;
        match action {
            TuiRemoteAccessAction::Close => {
                if self.qr.take().is_some() {
                    service.update(ctx, |service, ctx| service.disarm_pairing(ctx));
                }
                ctx.emit(TuiRemoteAccessEvent::Closed);
            }
            TuiRemoteAccessAction::ToggleEnabled => {
                let enabled = service.as_ref(ctx).is_enabled();
                self.qr = None;
                service.update(ctx, |service, ctx| service.set_enabled(!enabled, ctx));
            }
            TuiRemoteAccessAction::TogglePairing => {
                if !service.as_ref(ctx).is_enabled() {
                    self.message = Some("Enable remote access first (t).".to_owned());
                } else if self.qr.take().is_some() {
                    service.update(ctx, |service, ctx| service.disarm_pairing(ctx));
                } else {
                    match service.update(ctx, |service, ctx| service.arm_pairing(ctx)) {
                        Ok(qr) => match qr_half_block_lines(&qr.url) {
                            Some(lines) => self.qr = Some(ArmedPairing { qr, lines }),
                            None => self.message = Some("Could not render the QR code.".to_owned()),
                        },
                        Err(error) => self.message = Some(format!("Could not start pairing: {error}")),
                    }
                }
            }
            TuiRemoteAccessAction::SelectPrevious => {
                self.selected_device = self.selected_device.saturating_sub(1);
            }
            TuiRemoteAccessAction::SelectNext => {
                let count = Self::live_devices(ctx).len();
                self.selected_device = (self.selected_device + 1).min(count.saturating_sub(1));
            }
            TuiRemoteAccessAction::RevokeSelected => {
                let devices = Self::live_devices(ctx);
                if let Some(device) = devices.get(self.selected_device.min(devices.len().saturating_sub(1))) {
                    let id = device.id.0.clone();
                    service.update(ctx, |service, ctx| service.revoke_device(&id, ctx));
                }
            }
            TuiRemoteAccessAction::KillAllSessions => {
                service.update(ctx, |service, ctx| service.kill_all_sessions(ctx));
            }
            TuiRemoteAccessAction::Approve | TuiRemoteAccessAction::Deny => {
                let approve = matches!(action, TuiRemoteAccessAction::Approve);
                if let Some(pending) = service.as_ref(ctx).pending_approvals().first() {
                    let id = pending.id.clone();
                    service.update(ctx, |service, ctx| service.resolve_approval(&id, approve, ctx));
                }
            }
        }
        ctx.notify();
    }
}

#[cfg(test)]
#[path = "remote_access_view_tests.rs"]
mod tests;
