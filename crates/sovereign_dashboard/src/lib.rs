//! The Sovereign Agents dashboard (founder direction, 2026-08-25): one left
//! dock that tracks the agent economy — plugins, MCP servers mapped to Nostr
//! IDs, the agent wallet balance, and spending authorizations.
//!
//! THIS IS THE STUB LAYER. Every mutating control (add/remove plugin, add/
//! remove MCP mapping, fund wallet, new mandate) renders and dispatches a
//! visible "stubbed" notice instead of performing an effect. The wiring
//! targets already exist elsewhere — `command_center_ui` balances/mandate
//! components, `LedgerStore`, `MandateStore`, `settings_ui::mcp_servers_page`,
//! `omega_identity` — and land here in the Sovereign Agents program. Nothing
//! in this panel is authority-bearing yet: it must not look like custody it
//! does not have (the same honesty law as OMEGA-DELTA-0021's executor
//! disclosure).

use gpui::{
    App, AsyncWindowContext, Context, Entity, EventEmitter, FocusHandle, Focusable, IntoElement,
    ParentElement, Render, SharedString, Styled, Task, WeakEntity, Window, actions, px,
};
use ui::prelude::*;
use workspace::{
    Workspace,
    dock::{DockPosition, Panel, PanelEvent},
};

actions!(
    sovereign_dashboard,
    [
        /// Toggles focus on the Sovereign Agents dashboard panel.
        ToggleFocus,
    ]
);

const PANEL_KEY: &str = "sovereign-dashboard";

const STUB_NOTICE: &str =
    "Stubbed — wiring lands with the Sovereign Agents program (wallet, NIP-MKT offers, L-402 calls, HODLHODL escrow).";

const STUB_PLUGINS: &[(&str, &str)] = &[
    ("source-summarization", "registered"),
    ("om (Obsidian Mind)", "registered"),
];

const STUB_MCPS: &[(&str, &str)] = &[
    ("om", "unmapped"),
    ("source-summarization", "unmapped"),
];

pub struct SovereignDashboardPanel {
    focus_handle: FocusHandle,
    stub_notice: Option<&'static str>,
}

impl SovereignDashboardPanel {
    pub fn load(
        workspace: WeakEntity<Workspace>,
        cx: AsyncWindowContext,
    ) -> Task<anyhow::Result<Entity<Self>>> {
        cx.spawn(async move |cx| {
            workspace.update_in(cx, |_workspace, _window, cx| cx.new(|cx| Self::new(cx)))
        })
    }

    fn new(cx: &mut Context<Self>) -> Self {
        Self {
            focus_handle: cx.focus_handle(),
            stub_notice: None,
        }
    }

    fn stub(&mut self, notice: &'static str, cx: &mut Context<Self>) {
        self.stub_notice = Some(notice);
        cx.notify();
    }

    fn stub_row(
        &self,
        id: SharedString,
        primary: &str,
        secondary: &str,
        remove_notice: &'static str,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let name_for_label = primary.to_string();
        let remove_id = SharedString::from(format!("{id}-remove"));
        h_flex()
            .id(id)
            .w_full()
            .justify_between()
            .items_center()
            .px_2()
            .py_1()
            .rounded_sm()
            .hover(|style| style.bg(cx.theme().colors().element_hover))
            .child(
                v_flex()
                    .child(Label::new(primary.to_string()).size(LabelSize::Small))
                    .child(
                        Label::new(secondary.to_string())
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    ),
            )
            .child(
                IconButton::new(remove_id, IconName::Close)
                    .icon_size(IconSize::Small)
                    .style(ButtonStyle::Subtle)
                    .aria_label(format!("Remove {name_for_label} (stubbed)"))
                    .tooltip(ui::Tooltip::text("Remove (stubbed)"))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.stub(remove_notice, cx);
                    })),
            )
            .into_any_element()
    }

    fn section_header(&self, title: &'static str) -> AnyElement {
        Label::new(title)
            .size(LabelSize::Small)
            .color(Color::Muted)
            .into_any_element()
    }
}

impl EventEmitter<PanelEvent> for SovereignDashboardPanel {}
impl Focusable for SovereignDashboardPanel {
    fn focus_handle(&self, _: &gpui::App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for SovereignDashboardPanel {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let panel_background = cx.theme().colors().panel_background;
        let element_hover = cx.theme().colors().element_hover;

        // Rows are built first so the `cx.listener` borrows do not cross the
        // later builder calls.
        let plugin_rows: Vec<AnyElement> = STUB_PLUGINS
            .iter()
            .map(|(name, state)| {
                let id = SharedString::from(format!("plugin-{name}"));
                self.stub_row(
                    id,
                    name,
                    state,
                    "Plugin removal is stubbed.",
                    cx,
                )
            })
            .collect();
        let mcp_rows: Vec<AnyElement> = STUB_MCPS
            .iter()
            .map(|(server, nostr_id)| {
                let id = SharedString::from(format!("mcp-{server}"));
                let secondary = format!("nostr: {nostr_id}");
                self.stub_row(
                    id,
                    server,
                    &secondary,
                    "MCP mapping removal is stubbed.",
                    cx,
                )
            })
            .collect();

        v_flex()
            .id("sovereign-dashboard")
            .size_full()
            .key_context("SovereignDashboard")
            .bg(panel_background)
            .p_3()
            .gap_3()
            .overflow_y_scroll()
            .track_focus(&self.focus_handle)
            // Header
            .child(
                v_flex()
                    .child(Label::new("Sovereign Agents"))
                    .child(
                        Label::new("plugins · MCP · wallet · spending authorizations")
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    ),
            )
            // Agent Nostr identity
            .child(self.section_header("Agent Nostr ID"))
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .items_center()
                    .child(Label::new("npub… (not yet linked)").size(LabelSize::Small))
                    .child(
                        Button::new("link-nostr-id", "Link")
                            .style(ButtonStyle::Subtle)
                            .tooltip(ui::Tooltip::text("Link a Nostr identity (stubbed)"))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.stub("Nostr identity linking is stubbed.", cx);
                            })),
                    ),
            )
            // Wallet
            .child(self.section_header("Agent Wallet"))
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .items_center()
                    .child(
                        v_flex()
                            .child(Label::new("0 sats"))
                            .child(
                                Label::new("custody not yet wired")
                                    .size(LabelSize::Small)
                                    .color(Color::Muted),
                            ),
                    )
                    .child(
                        Button::new("fund-wallet", "Fund")
                            .style(ButtonStyle::Subtle)
                            .tooltip(ui::Tooltip::text("Fund the agent wallet (stubbed)"))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.stub("Wallet funding is stubbed.", cx);
                            })),
                    ),
            )
            // Plugins
            .child(self.section_header("Plugins"))
            .children(plugin_rows)
            .child(
                Button::new("add-plugin", "Add Plugin")
                    .style(ButtonStyle::Subtle)
                    .tooltip(ui::Tooltip::text("Add a plugin (stubbed)"))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.stub("Plugin creation is stubbed.", cx);
                    })),
            )
            // MCP servers mapped to Nostr IDs
            .child(self.section_header("MCP Servers → Nostr IDs"))
            .children(mcp_rows)
            .child(
                Button::new("add-mcp", "Add Mapping")
                    .style(ButtonStyle::Subtle)
                    .tooltip(ui::Tooltip::text(
                        "Map an MCP server to a Nostr ID (stubbed)",
                    ))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.stub("MCP-to-Nostr mapping is stubbed.", cx);
                    })),
            )
            // Spending authorizations
            .child(self.section_header("Spending Authorizations"))
            .child(
                Label::new("No active authorizations")
                    .size(LabelSize::Small)
                    .color(Color::Muted),
            )
            .child(
                Button::new("new-mandate", "New Authorization")
                    .style(ButtonStyle::Subtle)
                    .tooltip(ui::Tooltip::text(
                        "Create a spending authorization (stubbed)",
                    ))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.stub("Spending authorizations are stubbed.", cx);
                    })),
            )
            // Stub notice
            .children(self.stub_notice.map(|notice| {
                div()
                    .id("sovereign-dashboard-stub-notice")
                    .w_full()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .bg(element_hover)
                    .role(gpui::Role::Status)
                    .aria_label("Stubbed control")
                    .child(
                        Label::new(notice)
                            .size(LabelSize::Small)
                            .color(Color::Warning),
                    )
            }))
    }
}

impl Panel for SovereignDashboardPanel {
    fn persistent_name() -> &'static str {
        "SovereignDashboardPanel"
    }

    fn panel_key() -> &'static str {
        PANEL_KEY
    }

    fn position(&self, _: &Window, _: &App) -> DockPosition {
        DockPosition::Left
    }

    fn position_is_valid(&self, _: DockPosition) -> bool {
        true
    }

    fn set_position(&mut self, _: DockPosition, _: &mut Window, _: &mut Context<Self>) {}

    fn default_size(&self, _: &Window, _: &App) -> gpui::Pixels {
        px(340.)
    }

    fn icon(&self, _: &Window, _: &App) -> Option<IconName> {
        Some(IconName::BoltOutlined)
    }

    fn icon_tooltip(&self, _: &Window, _: &App) -> Option<&'static str> {
        Some("Sovereign Agents")
    }

    fn toggle_action(&self) -> Box<dyn gpui::Action> {
        Box::new(ToggleFocus)
    }

    fn activation_priority(&self) -> u32 {
        9
    }
}

pub fn init(cx: &mut App) {
    cx.observe_new(|workspace: &mut Workspace, _, _| {
        workspace.register_action(|workspace, _: &ToggleFocus, window, cx| {
            workspace.toggle_panel_focus::<SovereignDashboardPanel>(window, cx);
        });
    })
    .detach();
}
