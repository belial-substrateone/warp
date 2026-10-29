//! Settings UI for phone remote access (view and control terminals from a paired phone over
//! LAN/Tailscale). See `REMOTE_CONTROL.md` section 5.1.
use std::cell::RefCell;
use std::collections::HashMap;

use warpui::elements::{
    ConstrainedBox, Container, CrossAxisAlignment, Element, Flex, MainAxisAlignment, MainAxisSize,
    MouseStateHandle, ParentElement, Shrinkable, Text,
};
use warpui::platform::Cursor;
use warpui::ui_components::button::ButtonVariant;
use warpui::ui_components::components::UiComponent;
use warpui::ui_components::switch::SwitchStateHandle;
use warpui::{AppContext, Entity, SingletonEntity, TypedActionView, View, ViewContext, ViewHandle};

use super::settings_page::{
    LocalOnlyIconState, MatchData, PageTitle, PageType, SettingsPageMeta, SettingsPageViewHandle,
    SettingsWidget, render_body_item,
};
use super::{SettingsSection, ToggleState};
use crate::appearance::Appearance;
use crate::remote_access::RemoteAccessService;
use crate::remote_access::ui::view_model::{
    device_rows, fingerprint_lines, now_unix, session_rows,
};
use crate::workspace::WorkspaceAction;

#[derive(Clone, Debug, PartialEq)]
pub enum RemoteAccessPageAction {
    ToggleEnabled,
    PairPhone,
    RevokeDevice(String),
    AskRotateCertificate,
    CancelRotateCertificate,
    ConfirmRotateCertificate,
    DisconnectAll,
}

pub struct RemoteAccessPageView {
    page: PageType<Self>,
    switch_state: SwitchStateHandle,
    pair_button: MouseStateHandle,
    rotate_button: MouseStateHandle,
    rotate_confirm_button: MouseStateHandle,
    rotate_cancel_button: MouseStateHandle,
    disconnect_all_button: MouseStateHandle,
    /// One revoke button state per device id (created on first render of that row).
    revoke_buttons: RefCell<HashMap<String, MouseStateHandle>>,
    confirming_rotate: bool,
}

impl RemoteAccessPageView {
    pub fn new(ctx: &mut ViewContext<Self>) -> Self {
        ctx.subscribe_to_model(&RemoteAccessService::handle(ctx), |_, _, _, ctx| {
            ctx.notify();
        });
        let widgets: Vec<Box<dyn SettingsWidget<View = Self>>> = vec![
            Box::new(EnableWidget),
            Box::new(StatusWidget),
            Box::new(PairWidget),
            Box::new(DevicesWidget),
            Box::new(SessionsWidget),
        ];
        Self {
            page: PageType::new_uncategorized(widgets, Some(PageTitle::new("Remote Access"))),
            switch_state: Default::default(),
            pair_button: Default::default(),
            rotate_button: Default::default(),
            rotate_confirm_button: Default::default(),
            rotate_cancel_button: Default::default(),
            disconnect_all_button: Default::default(),
            revoke_buttons: RefCell::new(HashMap::new()),
            confirming_rotate: false,
        }
    }
}

impl Entity for RemoteAccessPageView {
    type Event = ();
}

impl TypedActionView for RemoteAccessPageView {
    type Action = RemoteAccessPageAction;

    fn handle_action(&mut self, action: &Self::Action, ctx: &mut ViewContext<Self>) {
        let service = RemoteAccessService::handle(ctx);
        match action {
            RemoteAccessPageAction::ToggleEnabled => {
                service.update(ctx, |s, ctx| {
                    let enabled = s.is_enabled();
                    s.set_enabled(!enabled, ctx);
                });
            }
            RemoteAccessPageAction::PairPhone => {
                ctx.dispatch_typed_action(&WorkspaceAction::ShowRemoteAccessPairing);
            }
            RemoteAccessPageAction::RevokeDevice(id) => {
                service.update(ctx, |s, ctx| s.revoke_device(id, ctx));
                self.revoke_buttons.borrow_mut().remove(id);
            }
            RemoteAccessPageAction::AskRotateCertificate => self.confirming_rotate = true,
            RemoteAccessPageAction::CancelRotateCertificate => self.confirming_rotate = false,
            RemoteAccessPageAction::ConfirmRotateCertificate => {
                self.confirming_rotate = false;
                service.update(ctx, |s, ctx| s.rotate_certificate(ctx));
            }
            RemoteAccessPageAction::DisconnectAll => {
                service.update(ctx, |s, ctx| s.kill_all_sessions(ctx));
            }
        }
        ctx.notify();
    }
}

impl View for RemoteAccessPageView {
    fn ui_name() -> &'static str {
        "RemoteAccessSettingsPage"
    }

    fn render(&self, app: &AppContext) -> Box<dyn Element> {
        self.page.render(self, app)
    }
}

impl SettingsPageMeta for RemoteAccessPageView {
    fn section() -> SettingsSection {
        SettingsSection::RemoteAccess
    }

    /// Only meaningful for the AnonWarp build (offline stub-server mode): the upstream Warp
    /// channels do not ship phone remote access.
    fn should_render(&self, _ctx: &AppContext) -> bool {
        is_remote_access_available()
    }

    fn update_filter(&mut self, query: &str, ctx: &mut ViewContext<Self>) -> MatchData {
        self.page.update_filter(query, ctx)
    }

    fn scroll_to_widget(&mut self, widget_id: &'static str) {
        self.page.scroll_to_widget(widget_id)
    }

    fn clear_highlighted_widget(&mut self) {
        self.page.clear_highlighted_widget();
    }
}

impl From<ViewHandle<RemoteAccessPageView>> for SettingsPageViewHandle {
    fn from(view_handle: ViewHandle<RemoteAccessPageView>) -> Self {
        SettingsPageViewHandle::RemoteAccess(view_handle)
    }
}

/// Phone remote access exists only in the AnonWarp binary, which runs with the offline stub
/// server. The value is fixed for the process, so callers gate page construction on it.
pub fn is_remote_access_available() -> bool {
    cfg!(not(target_family = "wasm")) && warp_core::channel::stub_server_enabled()
}

fn text_line(appearance: &Appearance, text: String, dim: bool) -> Box<dyn Element> {
    let theme = appearance.theme();
    let color = if dim {
        theme.disabled_ui_text_color()
    } else {
        theme.active_ui_text_color()
    };
    Text::new(text, appearance.ui_font_family(), 13.)
        .with_color(color.into())
        .finish()
}

fn small_button(
    appearance: &Appearance,
    variant: ButtonVariant,
    mouse: &MouseStateHandle,
    label: &str,
    action: Option<RemoteAccessPageAction>,
) -> Box<dyn Element> {
    let builder = appearance
        .ui_builder()
        .button(variant, mouse.clone())
        .with_text_label(label.to_owned());
    match action {
        Some(action) => builder
            .build()
            .with_cursor(Cursor::PointingHand)
            .on_click(move |ctx, _, _| ctx.dispatch_typed_action(action.clone()))
            .finish(),
        None => builder.disabled().build().finish(),
    }
}

struct EnableWidget;

impl SettingsWidget for EnableWidget {
    type View = RemoteAccessPageView;

    fn search_terms(&self) -> &str {
        "remote access phone enable toggle lan tailscale control terminal mobile android"
    }

    fn render(
        &self,
        view: &Self::View,
        appearance: &Appearance,
        app: &AppContext,
    ) -> Box<dyn Element> {
        let enabled = RemoteAccessService::as_ref(app).is_enabled();
        render_body_item::<RemoteAccessPageAction>(
            "Allow paired phones to control this computer".into(),
            None,
            LocalOnlyIconState::Hidden,
            ToggleState::Enabled,
            appearance,
            appearance
                .ui_builder()
                .switch(view.switch_state.clone())
                .check(enabled)
                .build()
                .on_click(|ctx, _, _| {
                    ctx.dispatch_typed_action(RemoteAccessPageAction::ToggleEnabled);
                })
                .finish(),
            Some(
                "Starts a server that lets phones you have paired view and type into ALL of your \
                 terminal panes. It is reachable only from your local network (LAN) and Tailscale, \
                 never the internet. Off by default and turned off again when AnonWarp restarts."
                    .to_owned(),
            ),
        )
    }
}

struct StatusWidget;

impl SettingsWidget for StatusWidget {
    type View = RemoteAccessPageView;

    fn search_terms(&self) -> &str {
        "remote access listening addresses ip port certificate fingerprint tls"
    }

    fn should_render(&self, app: &AppContext) -> bool {
        RemoteAccessService::as_ref(app).is_enabled()
    }

    fn render(
        &self,
        _view: &Self::View,
        appearance: &Appearance,
        app: &AppContext,
    ) -> Box<dyn Element> {
        let service = RemoteAccessService::as_ref(app);
        let mut col = Flex::column().with_child(text_line(appearance, "Listening on".into(), true));
        let addrs = service.listen_addrs();
        if addrs.is_empty() {
            col.add_child(text_line(appearance, "No address yet".into(), false));
        }
        for addr in addrs {
            col.add_child(text_line(appearance, addr.to_string(), false));
        }
        col.add_child(
            Container::new(text_line(
                appearance,
                "Certificate fingerprint (SHA-256)".into(),
                true,
            ))
            .with_margin_top(8.)
            .finish(),
        );
        match service.fingerprint_display() {
            Some(fp) => {
                for line in fingerprint_lines(&fp, 16) {
                    col.add_child(text_line(appearance, line, false));
                }
            }
            None => col.add_child(text_line(appearance, "Not generated yet".into(), false)),
        }
        Container::new(col.finish())
            .with_margin_bottom(12.)
            .finish()
    }
}

struct PairWidget;

impl SettingsWidget for PairWidget {
    type View = RemoteAccessPageView;

    fn search_terms(&self) -> &str {
        "remote access pair a phone qr code scan pairing"
    }

    fn render(
        &self,
        view: &Self::View,
        appearance: &Appearance,
        app: &AppContext,
    ) -> Box<dyn Element> {
        let enabled = RemoteAccessService::as_ref(app).is_enabled();
        render_body_item::<RemoteAccessPageAction>(
            "Pair a phone".into(),
            None,
            LocalOnlyIconState::Hidden,
            ToggleState::Enabled,
            appearance,
            small_button(
                appearance,
                ButtonVariant::Secondary,
                &view.pair_button,
                "Pair a phone...",
                enabled.then_some(RemoteAccessPageAction::PairPhone),
            ),
            Some(if enabled {
                "Shows a QR code that is valid for two minutes and works once. You will be asked to approve the phone on this computer.".to_owned()
            } else {
                "Turn on remote access first.".to_owned()
            }),
        )
    }
}

struct DevicesWidget;

impl SettingsWidget for DevicesWidget {
    type View = RemoteAccessPageView;

    fn search_terms(&self) -> &str {
        "remote access paired devices phones revoke rotate certificate last seen"
    }

    fn render(
        &self,
        view: &Self::View,
        appearance: &Appearance,
        app: &AppContext,
    ) -> Box<dyn Element> {
        let service = RemoteAccessService::as_ref(app);
        let rows = device_rows(&service.devices(), now_unix());
        let mut col = Flex::column()
            .with_child(text_line(appearance, "Paired devices".into(), false));
        if rows.is_empty() {
            col.add_child(text_line(appearance, "No paired devices.".into(), true));
        }
        for row in &rows {
            let mouse = view
                .revoke_buttons
                .borrow_mut()
                .entry(row.id.clone())
                .or_default()
                .clone();
            let info = Flex::column()
                .with_child(text_line(
                    appearance,
                    format!("{} ({})", row.label, row.platform),
                    false,
                ))
                .with_child(text_line(
                    appearance,
                    format!("Last seen {} from {}", row.last_seen, row.last_ip),
                    true,
                ))
                .finish();
            col.add_child(
                Container::new(
                    Flex::row()
                        .with_main_axis_size(MainAxisSize::Max)
                        .with_main_axis_alignment(MainAxisAlignment::SpaceBetween)
                        .with_cross_axis_alignment(CrossAxisAlignment::Center)
                        .with_child(Shrinkable::new(1., info).finish())
                        .with_child(small_button(
                            appearance,
                            ButtonVariant::Warn,
                            &mouse,
                            "Revoke",
                            Some(RemoteAccessPageAction::RevokeDevice(row.id.clone())),
                        ))
                        .finish(),
                )
                .with_margin_top(8.)
                .finish(),
            );
        }

        let rotate: Box<dyn Element> = if view.confirming_rotate {
            Flex::column()
                .with_child(text_line(
                    appearance,
                    format!(
                        "Rotating the certificate revokes all {} paired device(s); every phone must pair again. Continue?",
                        rows.len()
                    ),
                    false,
                ))
                .with_child(
                    Container::new(
                        Flex::row()
                            .with_child(small_button(
                                appearance,
                                ButtonVariant::Warn,
                                &view.rotate_confirm_button,
                                "Rotate and revoke all",
                                Some(RemoteAccessPageAction::ConfirmRotateCertificate),
                            ))
                            .with_child(
                                Container::new(small_button(
                                    appearance,
                                    ButtonVariant::Secondary,
                                    &view.rotate_cancel_button,
                                    "Cancel",
                                    Some(RemoteAccessPageAction::CancelRotateCertificate),
                                ))
                                .with_margin_left(8.)
                                .finish(),
                            )
                            .finish(),
                    )
                    .with_margin_top(6.)
                    .finish(),
                )
                .finish()
        } else {
            small_button(
                appearance,
                ButtonVariant::Secondary,
                &view.rotate_button,
                "Rotate certificate (revokes all devices)",
                Some(RemoteAccessPageAction::AskRotateCertificate),
            )
        };
        col.add_child(Container::new(rotate).with_margin_top(12.).finish());
        Container::new(col.finish())
            .with_margin_bottom(12.)
            .finish()
    }
}

struct SessionsWidget;

impl SettingsWidget for SessionsWidget {
    type View = RemoteAccessPageView;

    fn search_terms(&self) -> &str {
        "remote access active sessions connected phones disconnect all kill switch stop"
    }

    fn should_render(&self, app: &AppContext) -> bool {
        RemoteAccessService::as_ref(app).is_enabled()
    }

    fn render(
        &self,
        view: &Self::View,
        appearance: &Appearance,
        app: &AppContext,
    ) -> Box<dyn Element> {
        let sessions = RemoteAccessService::as_ref(app).active_sessions();
        let rows = session_rows(&sessions, now_unix());
        let mut col = Flex::column()
            .with_child(text_line(appearance, "Active sessions".into(), false));
        if rows.is_empty() {
            col.add_child(text_line(appearance, "No phone is connected.".into(), true));
        }
        for row in &rows {
            col.add_child(text_line(
                appearance,
                format!("{} from {} for {}", row.label, row.ip, row.duration),
                true,
            ));
        }
        let button = ConstrainedBox::new(small_button(
            appearance,
            ButtonVariant::Error,
            &view.disconnect_all_button,
            "Disconnect all",
            (!rows.is_empty()).then_some(RemoteAccessPageAction::DisconnectAll),
        ))
        .with_min_width(160.)
        .finish();
        col.add_child(Container::new(button).with_margin_top(10.).finish());
        Container::new(col.finish())
            .with_margin_bottom(12.)
            .finish()
    }
}

#[cfg(test)]
#[path = "remote_access_page_tests.rs"]
mod tests;
