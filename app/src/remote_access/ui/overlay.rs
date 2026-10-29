//! Overlay view hosting the two remote-access dialogs the workspace can show:
//!
//! - the **approval prompt** (a phone presented a valid pairing secret and waits for the user), and
//! - the **pairing QR modal** (opened from Settings or the command palette).
//!
//! The approval prompt takes precedence. It is deliberately hard to approve by accident: nothing is
//! focused by default, Enter does nothing, Escape denies, the Approve button is disabled for the
//! first moments after the prompt appears, and Deny is the visually primary button.
use std::time::{Duration, Instant};

use pathfinder_color::ColorU;
use pathfinder_geometry::vector::vec2f;
use warp_core::ui::theme::Fill;
use warpui::elements::{
    Align, ChildAnchor, ConstrainedBox, Container, CrossAxisAlignment, Element, Empty, Flex,
    MainAxisSize, MouseStateHandle, OffsetPositioning, ParentAnchor, ParentElement,
    ParentOffsetBounds, Stack, Text,
};
use warpui::keymap::FixedBinding;
use warpui::platform::Cursor;
use warpui::r#async::Timer;
use warpui::ui_components::button::ButtonVariant;
use warpui::ui_components::components::{Coords, UiComponent, UiComponentStyles};
use warpui::{
    AppContext, Entity, SingletonEntity, TypedActionView, View, ViewContext, ViewHandle,
};

use ::remote_access::pairing::{PairingId, PendingApproval};

use super::view_model::{
    APPROVAL_TIMEOUT_SECS, APPROVE_ARM_DELAY_MS, fingerprint_lines, format_countdown, format_ip,
    now_unix, seconds_remaining,
};
use crate::appearance::Appearance;
use crate::drive::sharing::qr_code::{QUIET_ZONE_MODULES, QrMatrix, qr_matrix_for_url};
use crate::remote_access::api::{PairingQr, RemoteAccessEvent};
use crate::remote_access::RemoteAccessService;
use crate::ui_components::dialog::{Dialog, dialog_styles};

const QR_VISUAL_SIZE: f32 = 200.;
const DIALOG_WIDTH: f32 = 460.;
const BODY_FONT_SIZE: f32 = 13.;

pub fn init(app: &mut AppContext) {
    use warpui::keymap::macros::*;
    app.register_fixed_bindings([FixedBinding::new(
        "escape",
        RemoteAccessOverlayAction::Escape,
        id!("RemoteAccessOverlay"),
    )]);
}

struct PairingState {
    qr: Option<PairingQr>,
    matrix: Option<QrMatrix>,
    error: Option<String>,
    /// Number of paired devices when the modal opened; the modal closes itself when it grows.
    devices_at_open: usize,
}

struct ApprovalState {
    pending: PendingApproval,
    shown_at: Instant,
}

pub struct RemoteAccessOverlay {
    pairing: Option<PairingState>,
    approval: Option<ApprovalState>,
    ticking: bool,
    approve_button: MouseStateHandle,
    deny_button: MouseStateHandle,
    cancel_button: MouseStateHandle,
    regenerate_button: MouseStateHandle,
}

#[derive(Debug, Clone)]
pub enum RemoteAccessOverlayEvent {
    /// The overlay became visible and wants focus.
    Opened,
    /// The overlay closed; the workspace should return focus to the terminal.
    Closed,
}

#[derive(Debug, Clone)]
pub enum RemoteAccessOverlayAction {
    Approve,
    Deny,
    CancelPairing,
    Regenerate,
    Escape,
}

impl RemoteAccessOverlay {
    pub fn new(ctx: &mut ViewContext<Self>) -> Self {
        // The service is only registered for app launches that support remote access; views
        // built elsewhere (e.g. tests) simply never receive its events.
        if ctx.has_singleton_model::<RemoteAccessService>() {
            ctx.subscribe_to_model(&RemoteAccessService::handle(ctx), |me, _, event, ctx| {
                me.handle_service_event(event, ctx);
            });
        }
        Self {
            pairing: None,
            approval: None,
            ticking: false,
            approve_button: Default::default(),
            deny_button: Default::default(),
            cancel_button: Default::default(),
            regenerate_button: Default::default(),
        }
    }

    pub fn is_visible(&self) -> bool {
        self.pairing.is_some() || self.approval.is_some()
    }

    /// Opens the pairing QR modal and arms a fresh one-time secret.
    pub fn show_pairing(&mut self, ctx: &mut ViewContext<Self>) {
        let devices_at_open = RemoteAccessService::as_ref(ctx).devices().len();
        self.pairing = Some(PairingState {
            qr: None,
            matrix: None,
            error: None,
            devices_at_open,
        });
        self.arm(ctx);
        ctx.emit(RemoteAccessOverlayEvent::Opened);
        self.start_ticking(ctx);
        ctx.notify();
    }

    fn arm(&mut self, ctx: &mut ViewContext<Self>) {
        let result = RemoteAccessService::handle(ctx).update(ctx, |s, ctx| s.arm_pairing(ctx));
        let Some(state) = self.pairing.as_mut() else {
            return;
        };
        match result {
            Ok(qr) => match qr_matrix_for_url(&qr.url) {
                Ok(matrix) => {
                    state.matrix = Some(matrix);
                    state.qr = Some(qr);
                    state.error = None;
                }
                Err(err) => {
                    state.matrix = None;
                    state.qr = None;
                    state.error = Some(format!("Could not render QR code: {err}"));
                }
            },
            Err(err) => {
                state.matrix = None;
                state.qr = None;
                state.error = Some(format!("{err}"));
            }
        }
    }

    fn close_pairing(&mut self, disarm: bool, ctx: &mut ViewContext<Self>) {
        if self.pairing.take().is_some() {
            if disarm {
                RemoteAccessService::handle(ctx).update(ctx, |s, ctx| s.disarm_pairing(ctx));
            }
            if !self.is_visible() {
                ctx.emit(RemoteAccessOverlayEvent::Closed);
            }
            ctx.notify();
        }
    }

    fn close_approval(&mut self, ctx: &mut ViewContext<Self>) {
        if self.approval.take().is_some() {
            if !self.is_visible() {
                ctx.emit(RemoteAccessOverlayEvent::Closed);
            }
            ctx.notify();
        }
    }

    fn handle_service_event(&mut self, event: &RemoteAccessEvent, ctx: &mut ViewContext<Self>) {
        match event {
            RemoteAccessEvent::ApprovalRequested(id) => self.on_approval_requested(id, ctx),
            RemoteAccessEvent::StateChanged => {
                if !RemoteAccessService::as_ref(ctx).is_enabled() {
                    self.close_pairing(false, ctx);
                    self.close_approval(ctx);
                }
            }
            RemoteAccessEvent::DevicesChanged => {
                self.drop_approval_if_gone(ctx);
                let count = RemoteAccessService::as_ref(ctx).devices().len();
                if self
                    .pairing
                    .as_ref()
                    .is_some_and(|p| count > p.devices_at_open)
                {
                    // A phone finished pairing: the one-time secret is spent.
                    self.close_pairing(false, ctx);
                }
            }
            RemoteAccessEvent::SessionsChanged => {}
        }
    }

    fn on_approval_requested(&mut self, id: &PairingId, ctx: &mut ViewContext<Self>) {
        // Show in the focused window only (or everywhere when no window is focused, so the
        // prompt is not lost while the app is in the background).
        let active = ctx.windows().active_window();
        if active.is_some() && active != Some(ctx.window_id()) {
            return;
        }
        let Some(pending) = RemoteAccessService::as_ref(ctx)
            .pending_approvals()
            .into_iter()
            .find(|p| &p.id == id)
        else {
            return;
        };
        self.approval = Some(ApprovalState {
            pending,
            shown_at: Instant::now(),
        });
        ctx.emit(RemoteAccessOverlayEvent::Opened);
        self.start_ticking(ctx);
        ctx.notify();
    }

    fn drop_approval_if_gone(&mut self, ctx: &mut ViewContext<Self>) {
        let Some(current) = self.approval.as_ref().map(|a| a.pending.id.clone()) else {
            return;
        };
        let still_pending = RemoteAccessService::as_ref(ctx)
            .pending_approvals()
            .iter()
            .any(|p| p.id == current);
        if !still_pending {
            self.close_approval(ctx);
        }
    }

    fn start_ticking(&mut self, ctx: &mut ViewContext<Self>) {
        if self.ticking {
            return;
        }
        self.ticking = true;
        self.schedule_tick(ctx);
    }

    fn schedule_tick(&mut self, ctx: &mut ViewContext<Self>) {
        ctx.spawn(
            async { Timer::after(Duration::from_secs(1)).await },
            |me, _, ctx| me.on_tick(ctx),
        );
    }

    fn on_tick(&mut self, ctx: &mut ViewContext<Self>) {
        let now = now_unix();
        self.drop_approval_if_gone(ctx);
        if let Some(approval) = &self.approval
            && seconds_remaining(approval.pending.requested_at + APPROVAL_TIMEOUT_SECS, now) < -5
        {
            // The service should have dropped it already; never leave a stale prompt up.
            self.close_approval(ctx);
        }
        let expired = self
            .pairing
            .as_ref()
            .and_then(|p| p.qr.as_ref())
            .is_some_and(|qr| seconds_remaining(qr.expires_at, now) <= 0);
        if expired {
            self.arm(ctx);
        }
        if self.is_visible() {
            ctx.notify();
            self.schedule_tick(ctx);
        } else {
            self.ticking = false;
        }
    }

    // --- rendering -------------------------------------------------------------------------

    fn text(
        &self,
        appearance: &Appearance,
        text: impl Into<std::borrow::Cow<'static, str>>,
        dim: bool,
    ) -> Box<dyn Element> {
        let theme = appearance.theme();
        let color: ColorU = if dim {
            theme.disabled_ui_text_color().into()
        } else {
            theme.active_ui_text_color().into()
        };
        Text::new(text, appearance.ui_font_family(), BODY_FONT_SIZE)
            .with_color(color)
            .finish()
    }

    fn labelled(
        &self,
        appearance: &Appearance,
        label: &'static str,
        lines: Vec<String>,
    ) -> Box<dyn Element> {
        let mut col = Flex::column().with_child(self.text(appearance, label, true));
        for line in lines {
            col.add_child(self.text(appearance, line, false));
        }
        Container::new(col.finish()).with_margin_top(10.).finish()
    }

    fn render_qr_matrix(matrix: &QrMatrix) -> Box<dyn Element> {
        let modules_with_quiet_zone = matrix.width().saturating_add(QUIET_ZONE_MODULES * 2);
        let module_size = QR_VISUAL_SIZE / modules_with_quiet_zone as f32;
        let mut column = Flex::column().with_main_axis_size(MainAxisSize::Max);
        for y in 0..modules_with_quiet_zone {
            let mut row = Flex::row().with_main_axis_size(MainAxisSize::Max);
            for x in 0..modules_with_quiet_zone {
                let matrix_x = x.saturating_sub(QUIET_ZONE_MODULES);
                let matrix_y = y.saturating_sub(QUIET_ZONE_MODULES);
                let is_dark = x >= QUIET_ZONE_MODULES
                    && y >= QUIET_ZONE_MODULES
                    && matrix_x < matrix.width()
                    && matrix_y < matrix.width()
                    && matrix.is_dark(matrix_x, matrix_y);
                let color = if is_dark {
                    ColorU::black()
                } else {
                    ColorU::white()
                };
                row.add_child(
                    ConstrainedBox::new(
                        Container::new(Empty::new().finish())
                            .with_background_color(color)
                            .finish(),
                    )
                    .with_width(module_size)
                    .with_height(module_size)
                    .finish(),
                );
            }
            column.add_child(row.finish());
        }
        ConstrainedBox::new(column.finish())
            .with_width(QR_VISUAL_SIZE)
            .with_height(QR_VISUAL_SIZE)
            .finish()
    }

    fn button(
        appearance: &Appearance,
        variant: ButtonVariant,
        mouse: &MouseStateHandle,
        label: &str,
        action: Option<RemoteAccessOverlayAction>,
    ) -> Box<dyn Element> {
        let builder = appearance
            .ui_builder()
            .button(variant, mouse.clone())
            .with_centered_text_label(label.to_owned())
            .with_style(UiComponentStyles {
                font_size: Some(14.),
                width: Some(150.),
                height: Some(36.),
                ..Default::default()
            });
        match action {
            Some(action) => builder
                .build()
                .with_cursor(Cursor::PointingHand)
                .on_click(move |ctx, _, _| ctx.dispatch_typed_action(action.clone()))
                .finish(),
            None => builder.disabled().build().finish(),
        }
    }

    fn render_approval(
        &self,
        approval: &ApprovalState,
        fingerprint: Option<String>,
        appearance: &Appearance,
    ) -> Box<dyn Element> {
        let pending = &approval.pending;
        let remaining = seconds_remaining(pending.requested_at + APPROVAL_TIMEOUT_SECS, now_unix());
                let armed = approval.shown_at.elapsed().as_millis() >= APPROVE_ARM_DELAY_MS;

        let mut body = Flex::column().with_child(self.text(
            appearance,
            "A phone wants permission to view and type into ALL of your terminal panes. \
             Only approve a device you are holding right now.",
            false,
        ));
        body.add_child(self.labelled(
            appearance,
            "Device name",
            vec![if pending.device_name.is_empty() {
                "(none)".to_owned()
            } else {
                pending.device_name.clone()
            }],
        ));
        body.add_child(self.labelled(appearance, "Platform", vec![pending.platform.clone()]));
        body.add_child(self.labelled(appearance, "IP address", vec![format_ip(pending.ip)]));
        if let Some(fp) = fingerprint {
            body.add_child(self.labelled(
                appearance,
                "Certificate fingerprint (must match what the phone shows)",
                fingerprint_lines(&fp, 16),
            ));
        }
        body.add_child(
            Container::new(self.text(
                appearance,
                format!("This request expires in {}", format_countdown(remaining)),
                true,
            ))
            .with_margin_top(10.)
            .finish(),
        );

        let deny = Self::button(
            appearance,
            ButtonVariant::Accent,
            &self.deny_button,
            "Deny",
            Some(RemoteAccessOverlayAction::Deny),
        );
        let approve = Self::button(
            appearance,
            ButtonVariant::Basic,
            &self.approve_button,
            if armed { "Approve" } else { "Approve (wait)" },
            armed.then_some(RemoteAccessOverlayAction::Approve),
        );
        Self::wrap_dialog(
            appearance,
            Dialog::new("Approve phone?".into(), None, Self::dialog_style(appearance))
                .with_child(body.finish())
                .with_bottom_row_child(deny)
                .with_bottom_row_child(Container::new(approve).with_margin_left(8.).finish())
                .build()
                .finish(),
        )
    }

    fn dialog_style(appearance: &Appearance) -> UiComponentStyles {
        UiComponentStyles {
            width: Some(DIALOG_WIDTH),
            padding: Some(Coords::uniform(24.)),
            ..dialog_styles(appearance)
        }
    }

    fn render_pairing(&self, pairing: &PairingState, appearance: &Appearance) -> Box<dyn Element> {
        let mut body = Flex::column().with_cross_axis_alignment(CrossAxisAlignment::Start);
        if let (Some(qr), Some(matrix)) = (&pairing.qr, &pairing.matrix) {
            let remaining = seconds_remaining(qr.expires_at, now_unix());
            body.add_child(self.text(
                appearance,
                "Scan with the AnonWarp app, or with your phone camera to open the web client. \
                 Your phone must be on the same LAN or Tailscale network.",
                false,
            ));
            body.add_child(
                Container::new(Align::new(Self::render_qr_matrix(matrix)).finish())
                    .with_margin_top(12.)
                    .finish(),
            );
            body.add_child(
                Container::new(self.text(
                    appearance,
                    format!("Code expires in {}", format_countdown(remaining)),
                    false,
                ))
                .with_margin_top(8.)
                .finish(),
            );
            body.add_child(self.labelled(
                appearance,
                "Certificate fingerprint (compare with the phone)",
                fingerprint_lines(&qr.fingerprint_display, 16),
            ));
            body.add_child(self.labelled(appearance, "Reachable at", qr.hosts.clone()));
        } else {
            body.add_child(self.text(
                appearance,
                pairing
                    .error
                    .clone()
                    .unwrap_or_else(|| "Preparing pairing code...".to_owned()),
                false,
            ));
        }
        let cancel = Self::button(
            appearance,
            ButtonVariant::Accent,
            &self.cancel_button,
            "Cancel",
            Some(RemoteAccessOverlayAction::CancelPairing),
        );
        let regenerate = Self::button(
            appearance,
            ButtonVariant::Basic,
            &self.regenerate_button,
            "New code",
            Some(RemoteAccessOverlayAction::Regenerate),
        );
        Self::wrap_dialog(
            appearance,
            Dialog::new("Pair a phone".into(), None, Self::dialog_style(appearance))
                .with_child(body.finish())
                .with_bottom_row_child(cancel)
                .with_bottom_row_child(Container::new(regenerate).with_margin_left(8.).finish())
                .build()
                .finish(),
        )
    }

    fn wrap_dialog(_appearance: &Appearance, dialog: Box<dyn Element>) -> Box<dyn Element> {
        let mut stack = Stack::new();
        stack.add_positioned_child(
            Container::new(dialog).with_margin_top(35.).finish(),
            OffsetPositioning::offset_from_parent(
                vec2f(0., 0.),
                ParentOffsetBounds::WindowByPosition,
                ParentAnchor::Center,
                ChildAnchor::Center,
            ),
        );
        // Blurs and blocks the background.
        Container::new(Align::new(stack.finish()).finish())
            .with_background_color(Fill::blur().into())
            .finish()
    }
}

impl Entity for RemoteAccessOverlay {
    type Event = RemoteAccessOverlayEvent;
}

impl View for RemoteAccessOverlay {
    fn ui_name() -> &'static str {
        "RemoteAccessOverlay"
    }

    fn render(&self, app: &AppContext) -> Box<dyn Element> {
        let appearance = Appearance::as_ref(app);
        if let Some(approval) = &self.approval {
            self.render_approval(
                approval,
                RemoteAccessService::as_ref(app).fingerprint_display(),
                appearance,
            )
        } else if let Some(pairing) = &self.pairing {
            self.render_pairing(pairing, appearance)
        } else {
            Empty::new().finish()
        }
    }
}

impl TypedActionView for RemoteAccessOverlay {
    type Action = RemoteAccessOverlayAction;

    fn handle_action(&mut self, action: &Self::Action, ctx: &mut ViewContext<Self>) {
        match action {
            RemoteAccessOverlayAction::Approve | RemoteAccessOverlayAction::Deny => {
                let approve = matches!(action, RemoteAccessOverlayAction::Approve);
                let Some(state) = self.approval.as_ref() else {
                    return;
                };
                if approve && state.shown_at.elapsed().as_millis() < APPROVE_ARM_DELAY_MS {
                    return;
                }
                let id = state.pending.id.clone();
                RemoteAccessService::handle(ctx)
                    .update(ctx, |s, ctx| s.resolve_approval(&id, approve, ctx));
                self.close_approval(ctx);
            }
            RemoteAccessOverlayAction::CancelPairing => self.close_pairing(true, ctx),
            RemoteAccessOverlayAction::Regenerate => {
                self.arm(ctx);
                ctx.notify();
            }
            RemoteAccessOverlayAction::Escape => {
                // Escape always takes the safe option.
                if self.approval.is_some() {
                    self.handle_action(&RemoteAccessOverlayAction::Deny, ctx);
                } else {
                    self.close_pairing(true, ctx);
                }
            }
        }
    }
}

/// Convenience for the workspace: handle type of the overlay.
pub type RemoteAccessOverlayHandle = ViewHandle<RemoteAccessOverlay>;
