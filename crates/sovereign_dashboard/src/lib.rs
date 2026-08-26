//! The Sovereign Agents dashboard (founder direction, 2026-08-25): one left
//! dock that tracks the agent economy — plugins, MCP servers mapped to Nostr
//! IDs, the agent wallet balance, and spending authorizations.
//!
//! WP-5 (OA-P2-WALLET-2026-08-26) wired the real surfaces behind
//! `OMEGA_SOVEREIGN_WALLET=1` (default OFF):
//! - Wallet: real read-only signet balance from the sidecar; operator-only
//!   Create/Unlock/Lock; a real Fund flow (BOLT11 + QR via `ui::QrCodeCanvas`,
//!   the existing deposit-UI pattern from `command_center_ui::transfer_flow`).
//! - Agent Nostr ID: the REAL derived npub from the sidecar `identity-status`,
//!   the identity ceremony (vault init + word challenge + unlock), and the
//!   one-time export-nostr-secret bridge (WP-4 seam, operator-only).
//! - Spending Authorizations: the REAL generalized MandateStore snapshot
//!   (venue-wide + pubkey-keyed mandates, design §6.3), rendered with the
//!   reused `command_center_ui` components.
//! - MCP Servers → Nostr IDs: REAL configured servers from
//!   `ProjectSettings::get_global(cx).context_servers`, mapped to the derived
//!   identity npub where an identity seam exists, labeled "unmapped" otherwise.
//!
//! HONESTY LAW (unchanged): every control that is not real-and-verified keeps
//! an explicit stubbed notice; nothing claims custody it does not have. The
//! stub-notice mechanism is the enforcement surface and is never removed.

use std::time::Duration;

use editor::Editor;
use gpui::{
    App, AsyncWindowContext, Context, Entity, EventEmitter, FocusHandle, Focusable, FontWeight,
    IntoElement, ParentElement, PromptLevel, Render, SharedString, Styled, Task, WeakEntity,
    Window, actions, px,
};
use project::project_settings::ProjectSettings;
use settings::Settings as _;
use sovereign_wallet::{
    BalanceResult, IdentityStatusResult, InvoiceResult, SharedSovereignWalletSupervisor,
    StatusResult,
};
use trading_mandate::{MandateSnapshot, MandateStore, TradingMandate, TradingNetwork};
use ui::prelude::*;
use ui::{CopyButton, MarketTokens, QrCodeCanvas};
use util::ResultExt as _;
use workspace::{
    Workspace,
    dock::{DockPosition, Panel, PanelEvent},
};

use command_center_ui::{
    MandateApprovalDialog, MandateEditorAction, MandateEditorValue, MandateStatusCard, MandateUsage,
};

actions!(
    sovereign_dashboard,
    [
        /// Toggles focus on the Sovereign Agents dashboard panel.
        ToggleFocus,
    ]
);

const PANEL_KEY: &str = "sovereign-dashboard";

const STUB_PLUGINS: &[(&str, &str)] = &[
    ("source-summarization", "registered"),
    ("om (Obsidian Mind)", "registered"),
];

/// The widening application is delta-bound this WP: OMEGA-DELTA-0245 restricts
/// the widening-door callers to the settings-UI files, and this WP cannot
/// extend that allowlist (crates/omega_deltas is out of scope). The dashboard
/// renders the bound proposal; the terminal application is OQ-WP5-2.
const WIDENING_DOOR_NOTICE: &str =
    "Proposal bound (digest + revision). Applying it requires the settings-UI approval path — \
     OMEGA-DELTA-0245 limits widening-door callers and this WP cannot extend the allowlist \
     (open question OQ-WP5-2).";

/// The dashboard's refresh cadence for sidecar reads (the supervisor health
/// cadence is 5s; the dashboard re-reads on this interval and after actions).
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Input ceremony (operator text entry; the panel renders one input row)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum InputRequest {
    WalletCreatePassword,
    WalletUnlockPassword,
    FundAmount,
    VaultPassphrase,
    ChallengeWord { label: SharedString },
    MandateAmount,
    MandateExpiryHours,
    /// WP-6: the MCP-server id for the Add Mapping control (design §6.4).
    McpServerId,
    /// WP-6: the Nostr pubkey (64-hex) for the mapping; empty = unset.
    McpPrincipalPubkey,
}

impl InputRequest {
    fn key(&self) -> &'static str {
        match self {
            Self::WalletCreatePassword => "input-wallet-create-password",
            Self::WalletUnlockPassword => "input-wallet-unlock-password",
            Self::FundAmount => "input-fund-amount",
            Self::VaultPassphrase => "input-vault-passphrase",
            Self::ChallengeWord { .. } => "input-challenge-word",
            Self::MandateAmount => "input-mandate-amount",
            Self::MandateExpiryHours => "input-mandate-expiry-hours",
            Self::McpServerId => "input-mcp-server-id",
            Self::McpPrincipalPubkey => "input-mcp-principal-pubkey",
        }
    }
}

#[derive(Clone, Debug)]
struct PendingInput {
    request: InputRequest,
    label: SharedString,
    detail: SharedString,
}

#[derive(Clone, Debug, Default)]
struct WalletView {
    status: Option<StatusResult>,
    balance: Option<BalanceResult>,
    balance_error: Option<SharedString>,
    invoice: Option<InvoiceResult>,
    invoice_error: Option<SharedString>,
    /// Show-once aezeed from a wallet create (operator ceremony).
    create_aezeed: Option<Vec<String>>,
    create_note: Option<SharedString>,
}

impl WalletView {
    fn ready(&self) -> bool {
        matches!(
            self.status.as_ref().map(|status| &status.wallet_state),
            Some(sovereign_wallet::WalletState::Ready)
        )
    }
}

#[derive(Clone, Debug, Default)]
struct IdentityView {
    status: Option<IdentityStatusResult>,
    identity_error: Option<SharedString>,
    /// The show-once mnemonic of a pending identity ceremony (never logged;
    /// cleared on commit, cancel, or lock).
    ceremony_mnemonic: Option<SharedString>,
    ceremony_labels: Vec<SharedString>,
    /// The passphrase entered during the ceremony (staged until the word
    /// challenge completes; then committed).
    ceremony_passphrase: Option<String>,
    /// Challenge answers accumulated across the ceremony's word inputs.
    ceremony_answers: Vec<(SharedString, String)>,
    /// The one-time exported nsec, shown once (cleared by the operator).
    exported_nsec: Option<SharedString>,
    export_error: Option<SharedString>,
}

#[derive(Clone, Debug, Default)]
struct MandatesView {
    snapshot: Option<MandateSnapshot>,
    store_error: Option<SharedString>,
    proposal: Option<MandateEditorValue>,
    proposal_notice: Option<SharedString>,
    /// The amount staged between the two New Authorization inputs.
    pending_amount: Option<u64>,
}

pub struct SovereignDashboardPanel {
    focus_handle: FocusHandle,
    stub_notice: Option<&'static str>,
    wallet: WalletView,
    identity: IdentityView,
    mandates: MandatesView,
    mandate_store: Option<MandateStore>,
    supervisor: Option<SharedSovereignWalletSupervisor>,
    pending_input: Option<PendingInput>,
    refreshed_at_ms: i64,
    refresh_task: Option<Task<()>>,
    /// Idempotency-key suffix (per-panel uniqueness is enough).
    id_counter: u64,
    /// WP-6: the L-402 gateway's MCP-server -> Nostr-identity attribution map
    /// (design §6.4 / §5.4), fetched from the sidecar on refresh. Public
    /// pubkeys only — never key material.
    mcp_identity_map: std::collections::HashMap<String, String>,
    /// WP-6: a mapping-write error surfaced next to the Add Mapping control.
    mapping_error: Option<SharedString>,
    /// WP-6: the staged MCP-server id between the two Add Mapping inputs.
    mapping_server_id: Option<String>,
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

    pub fn new(cx: &mut Context<Self>) -> Self {
        let supervisor = sovereign_wallet::shared_supervisor(cx).ok();
        let mandate_store = MandateStore::open_default()
            .map_err(|error| log::error!("sovereign dashboard: {error:#}"))
            .ok();
        let mut panel = Self {
            focus_handle: cx.focus_handle(),
            stub_notice: None,
            wallet: WalletView::default(),
            identity: IdentityView::default(),
            mandates: MandatesView::default(),
            mandate_store,
            supervisor,
            pending_input: None,
            refreshed_at_ms: 0,
            refresh_task: None,
            id_counter: 0,
            mcp_identity_map: std::collections::HashMap::new(),
            mapping_error: None,
            mapping_server_id: None,
        };
        panel.refresh(cx);
        panel
    }

    fn stub(&mut self, notice: &'static str, cx: &mut Context<Self>) {
        self.stub_notice = Some(notice);
        cx.notify();
    }

    fn next_idempotency_key(&mut self) -> String {
        self.id_counter = self.id_counter.wrapping_add(1);
        format!("sw-dashboard-{}-{}", command_center_ui::unix_now_ms(), self.id_counter)
    }

    /// Re-read the sidecar projections and the mandate snapshot. Runs on the
    /// foreground executor (the supervisor is UI-thread affine); the sidecar
    /// start is `ensure_started`-idempotent, so a failed start here surfaces
    /// as a named state, never a hang.
    fn refresh(&mut self, cx: &mut Context<Self>) {
        self.refreshed_at_ms = command_center_ui::unix_now_ms();
        let Some(supervisor) = self.supervisor.clone() else {
            return;
        };
        let store = self.mandate_store.clone();
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let mut guard = supervisor.lock().await;
            let started = guard.ensure_started().await;
            let (status, balance, balance_error, identity_status, identity_error) = match started {
                Ok(()) => {
                    let status = guard.status().await.ok();
                    let balance_result = guard.balance().await;
                    let identity_status = guard.identity_status().await.ok();
                    let balance_error = match &balance_result {
                        Ok(_) => None,
                        Err(error) => Some(SharedString::from(error.to_string())),
                    };
                    (
                        status,
                        balance_result.ok(),
                        balance_error,
                        identity_status.clone(),
                        identity_status
                            .map(|_| None)
                            .unwrap_or_else(|| Some("identity-status unavailable".into())),
                    )
                }
                Err(error) => {
                    log::error!("sovereign wallet sidecar failed to start: {error:#}");
                    (
                        None,
                        None,
                        Some(SharedString::from(format!("sidecar unavailable: {error}"))),
                        None,
                        Some(SharedString::from("identity unavailable (sidecar down)")),
                    )
                }
            };
            let snapshot = store.as_ref().and_then(|store| store.snapshot().ok());
            let store_error = store
                .as_ref()
                .and_then(|store| store.snapshot().err().map(|error| error.to_string()));
            // WP-6: the L-402 gateway's MCP-server -> Nostr-identity map
            // (design §6.4). Read-only projection; the Add Mapping control
            // writes it through `mcp_identity_map_set`.
            let mcp_identity_map = if status.is_some() {
                guard
                    .mcp_identity_map_get()
                    .await
                    .ok()
                    .and_then(|value| {
                        value
                            .get("entries")
                            .and_then(serde_json::Value::as_object)
                            .map(|entries| {
                                entries
                                    .iter()
                                    .filter_map(|(server, principal)| {
                                        principal.as_str().map(|pubkey| (server.clone(), pubkey.to_string()))
                                    })
                                    .collect::<std::collections::HashMap<String, String>>()
                            })
                    })
                    .unwrap_or_default()
            } else {
                std::collections::HashMap::new()
            };
            this.update(cx, |this, cx| {
                this.wallet.status = status;
                this.wallet.balance = balance;
                this.wallet.balance_error = balance_error;
                this.identity.status = identity_status;
                this.identity.identity_error = identity_error;
                this.mcp_identity_map = mcp_identity_map;
                if let Some(snapshot) = snapshot {
                    this.mandates.snapshot = Some(snapshot);
                }
                if let Some(error) = store_error {
                    this.mandates.store_error = Some(SharedString::from(error));
                }
                cx.notify();
            })
            .log_err();
        }));
    }

    // -----------------------------------------------------------------------
    // Wallet section
    // -----------------------------------------------------------------------

    fn create_wallet_flow(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let answer = window.prompt(
            PromptLevel::Warning,
            "Create the Wavelength wallet (signet)?",
            Some(
                "The wallet DB password you enter is shown nowhere after creation. If the vault \
                 is unlocked it is captured there; otherwise the aezeed shown next is your only \
                 paper backup. A LOST PASSPHRASE OR AEZEED IS UNRECOVERABLE without a recovery \
                 artifact (SEC-2026-052 consequence).",
            ),
            &["Create wallet", "Cancel"],
            cx,
        );
        let task = cx.spawn(async move |this, cx| {
            if answer.await != Ok(0) {
                return;
            }
            this.update(cx, |this, cx| {
                this.pending_input = Some(PendingInput {
                    request: InputRequest::WalletCreatePassword,
                    label: "Wallet DB password".into(),
                    detail: "Enter a password for the Wavelength wallet database (operator-only). \
                             The field is not masked; clear it after use."
                        .into(),
                });
                cx.notify();
            })
            .log_err();
        });
        self.refresh_task = Some(task);
        cx.notify();
    }

    fn unlock_wallet_flow(&mut self, cx: &mut Context<Self>) {
        self.pending_input = Some(PendingInput {
            request: InputRequest::WalletUnlockPassword,
            label: "Wallet DB password".into(),
            detail: "Unlock the Wavelength wallet (operator-only). The field is not masked; \
                     clear it after use."
                .into(),
        });
        cx.notify();
    }

    fn lock_wallet(&mut self, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            return;
        };
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let _ = supervisor.lock().await.lock().await;
            this.update(cx, |this, cx| {
                this.wallet.balance = None;
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    fn fund_flow(&mut self, cx: &mut Context<Self>) {
        if self.supervisor.is_none() {
            self.stub_notice = Some("Wallet unavailable — the sovereign wallet lane is off (OMEGA_SOVEREIGN_WALLET=1 not set).");
            cx.notify();
            return;
        }
        if !self.wallet.ready() {
            self.wallet.invoice_error =
                Some("the wallet must be ready to mint an invoice (operator: create + unlock)".into());
            cx.notify();
            return;
        }
        self.pending_input = Some(PendingInput {
            request: InputRequest::FundAmount,
            label: "Amount (sats)".into(),
            detail: "Mint a real signet receive invoice for this amount. Test coins only — \
                     never mainnet."
                .into(),
        });
        cx.notify();
    }

    // -----------------------------------------------------------------------
    // Identity section
    // -----------------------------------------------------------------------

    fn identity_ceremony_start(&mut self, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            self.stub_notice = Some("Identity unavailable — the sovereign wallet lane is off.");
            cx.notify();
            return;
        };
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let result = supervisor.lock().await.vault_init_prepare().await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(value) => {
                        let mnemonic = value
                            .get("mnemonic")
                            .and_then(serde_json::Value::as_str)
                            .map(SharedString::from);
                        let labels = value
                            .get("challengeLabels")
                            .and_then(serde_json::Value::as_array)
                            .map(|labels| {
                                labels
                                    .iter()
                                    .filter_map(serde_json::Value::as_u64)
                                    .map(|label| SharedString::from(label.to_string()))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        this.identity.ceremony_mnemonic = mnemonic;
                        this.identity.ceremony_labels = labels;
                        this.identity.ceremony_answers.clear();
                        // Step 1 of the ceremony: the vault passphrase.
                        this.pending_input = Some(PendingInput {
                            request: InputRequest::VaultPassphrase,
                            label: "Vault passphrase".into(),
                            detail: "At least 12 characters (SEC-2026-052). A LOST PASSPHRASE OR \
                                     MNEMONIC IS UNRECOVERABLE without a NIP-49 recovery artifact."
                                .into(),
                        });
                    }
                    Err(error) => {
                        this.identity.identity_error =
                            Some(SharedString::from(format!("ceremony prepare failed: {error}")));
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    /// Advance the identity ceremony: after the passphrase, the word-challenge
    /// inputs cycle through the ceremony positions; the final answer commits
    /// (in `confirm_input`).
    fn ceremony_advance(&mut self, cx: &mut Context<Self>) {
        let answered: Vec<SharedString> = self
            .identity
            .ceremony_answers
            .iter()
            .map(|(label, _)| label.clone())
            .collect();
        let next = self
            .identity
            .ceremony_labels
            .iter()
            .find(|label| !answered.contains(label))
            .cloned();
        if let Some(label) = next {
            self.pending_input = Some(PendingInput {
                request: InputRequest::ChallengeWord { label: label.clone() },
                label: format!("Word #{} of your recorded mnemonic", label).into(),
                detail: "Enter the word exactly as recorded (the ceremony proves you wrote it \
                         down)."
                    .into(),
            });
        }
        cx.notify();
    }

    fn identity_ceremony_commit(&mut self, passphrase: String, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            return;
        };
        // Guard: the ceremony must be prepared (show-once mnemonic pending).
        if self.identity.ceremony_mnemonic.is_none() {
            self.identity.identity_error =
                Some("the identity ceremony is not prepared; start it again".into());
            cx.notify();
            return;
        }
        if passphrase.len() < 12 {
            self.identity.identity_error = Some(
                "the vault passphrase must be at least 12 characters (SEC-2026-052)".into(),
            );
            cx.notify();
            return;
        }
        let answers = self.identity.ceremony_answers.clone();
        let answers_json = serde_json::Value::Object(
            answers
                .iter()
                .map(|(label, word)| (label.to_string(), serde_json::Value::String(word.clone())))
                .collect(),
        );
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let result = supervisor
                .lock()
                .await
                .vault_init(&passphrase, &answers_json)
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(value) => {
                        let npub = value
                            .get("npub")
                            .and_then(serde_json::Value::as_str)
                            .map(ToString::to_string);
                        let pubkey_hex = value
                            .get("pubkeyHex")
                            .and_then(serde_json::Value::as_str)
                            .map(ToString::to_string);
                        this.identity.ceremony_mnemonic = None;
                        this.identity.ceremony_labels.clear();
                        this.identity.ceremony_answers.clear();
                        this.identity.status = Some(IdentityStatusResult {
                            vault_state: "unlocked".into(),
                            derived_npub: npub,
                            derived_pubkey_hex: pubkey_hex,
                            recovery_artifact_state: "absent".into(),
                            note: String::new(),
                        });
                        this.identity.identity_error = None;
                        this.pending_input = None;
                    }
                    Err(error) => {
                        this.identity.ceremony_mnemonic = None;
                        this.identity.ceremony_labels.clear();
                        this.identity.ceremony_answers.clear();
                        this.identity.identity_error =
                            Some(SharedString::from(format!("ceremony failed: {error}")));
                        this.pending_input = None;
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    fn unlock_vault_flow(&mut self, cx: &mut Context<Self>) {
        self.pending_input = Some(PendingInput {
            request: InputRequest::VaultPassphrase,
            label: "Vault passphrase".into(),
            detail: "Unlock the identity vault. A lost passphrase is unrecoverable without a \
                     recovery artifact (SEC-2026-052)."
                .into(),
        });
        cx.notify();
    }

    fn export_secret_flow(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            return;
        };
        let answer = window.prompt(
            PromptLevel::Warning,
            "Export the Nostr secret once?",
            Some(
                "This hands the derived nsec to the Rust omega_identity import ceremony \
                 (design §4.6). It is ONE-TIME: the sidecar refuses a second export. \
                 The secret is shown once and never logged.",
            ),
            &["Export once", "Cancel"],
            cx,
        );
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            if answer.await != Ok(0) {
                return;
            }
            let result = supervisor.lock().await.export_nostr_secret().await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(exported) => {
                        this.identity.exported_nsec = Some(SharedString::from(exported.nsec));
                        this.identity.export_error = None;
                    }
                    Err(error) => {
                        this.identity.export_error =
                            Some(SharedString::from(format!("export refused: {error}")));
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    // -----------------------------------------------------------------------
    // Spending authorizations
    // -----------------------------------------------------------------------

    fn new_authorization_flow(&mut self, cx: &mut Context<Self>) {
        if self.mandate_store.is_none() {
            self.mandates.store_error = Some("the trading mandate store is not available".into());
            cx.notify();
            return;
        }
        let Some(identity) = self.identity.status.clone() else {
            self.mandates.proposal_notice =
                Some("no agent identity yet — run the identity ceremony first".into());
            cx.notify();
            return;
        };
        if identity.derived_pubkey_hex.is_none() {
            self.mandates.proposal_notice =
                Some("no derived identity pubkey yet — unlock the vault first".into());
            cx.notify();
            return;
        }
        self.pending_input = Some(PendingInput {
            request: InputRequest::MandateAmount,
            label: "Maximum payment (sats)".into(),
            detail: "Maximum PAYMENT SIZE in sats for the sovereign-wallet venue (signet test \
                     coins only). The authorization is keyed to this agent's Nostr pubkey \
                     (principal-only, SEC-2026-043)."
                .into(),
        });
        cx.notify();
    }

    fn propose_authorization(&mut self, amount_sat: u64, expiry_hours: u64) {
        let Some(store) = self.mandate_store.clone() else {
            return;
        };
        let Some(pubkey_hex) = self
            .identity
            .status
            .as_ref()
            .and_then(|identity| identity.derived_pubkey_hex.clone())
        else {
            self.mandates.proposal_notice =
                Some("no derived identity pubkey yet — unlock the vault first".into());
            return;
        };
        let now_ms = command_center_ui::unix_now_ms();
        let expiry_ms = now_ms.saturating_add(
            (expiry_hours.clamp(1, 24 * 365) * 3_600 * 1_000) as i64,
        );
        let candidate =
            sovereign_wallet::sovereign_wallet_mandate_candidate(&pubkey_hex, amount_sat, expiry_ms);
        match store.propose(candidate) {
            Ok(proposal) => {
                let current = self
                    .mandates
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| {
                        snapshot.mandate_for_principal(
                            trading_mandate::SOVEREIGN_WALLET_VENUE,
                            TradingNetwork::Signet,
                            Some(&pubkey_hex),
                        )
                    })
                    .cloned();
                self.mandates.proposal =
                    Some(MandateEditorValue::from_proposal(current.as_ref(), &proposal));
                self.mandates.proposal_notice = None;
            }
            Err(error) => {
                self.mandates.proposal_notice =
                    Some(SharedString::from(format!("proposal failed: {error}")));
            }
        }
    }

    /// The approve action of the bound proposal dialog. The widening
    /// application is delta-bound this WP (OQ-WP5-2): the proposal is bound
    /// and ready, but the terminal store call must live on the settings-UI
    /// approval path (OMEGA-DELTA-0245 caller allowlist). The dashboard
    /// reports that honestly instead of claiming applied authority.
    fn approve_proposal(&mut self) {
        self.mandates.proposal_notice = Some(WIDENING_DOOR_NOTICE.into());
    }

    fn reject_proposal(&mut self) {
        self.mandates.proposal = None;
        self.mandates.proposal_notice = None;
    }

    fn revoke_venue_wide(
        &mut self,
        venue: &str,
        network: TradingNetwork,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(store) = self.mandate_store.clone() else {
            return;
        };
        let venue = venue.to_string();
        let answer = window.prompt(
            PromptLevel::Warning,
            &format!(
                "Revoke the venue-wide mandate for {venue} ({})?",
                network_label(network)
            ),
            Some("Revocation needs no approval (Restriction/Revoke unchanged). This removes the venue-wide (None) mandate only; principal-keyed authorizations are untouched (OQ-WP5-3)."),
            &["Revoke", "Cancel"],
            cx,
        );
        let task = cx.spawn(async move |this, cx| {
            if answer.await != Ok(0) {
                return;
            }
            let result = store.revoke(&venue, network, command_center_ui::unix_now_ms());
            this.update(cx, |this, cx| {
                match result {
                    Ok(snapshot) => {
                        this.mandates.snapshot = Some(snapshot);
                        this.mandates.store_error = None;
                    }
                    Err(error) => {
                        this.mandates.store_error =
                            Some(SharedString::from(format!("revoke failed: {error}")));
                    }
                }
                cx.notify();
            })
            .log_err();
        });
        self.refresh_task = Some(task);
        cx.notify();
    }

    // -----------------------------------------------------------------------
    // Input dispatch (the single operator input row)
    // -----------------------------------------------------------------------

    fn confirm_input(&mut self, request: InputRequest, value: String, cx: &mut Context<Self>) {
        self.pending_input = None;
        match request {
            InputRequest::WalletCreatePassword => {
                let Some(supervisor) = self.supervisor.clone() else {
                    return;
                };
                let idempotency_key = self.next_idempotency_key();
                let task = cx.spawn(async move |this, cx| {
                    let result = supervisor
                        .lock()
                        .await
                        .create_wallet(&idempotency_key, &value)
                        .await;
                    this.update(cx, |this, cx| {
                        match result {
                            Ok(created) => {
                                this.wallet.create_aezeed = Some(created.mnemonic.clone());
                                this.wallet.create_note = Some(SharedString::from(created.note));
                                this.wallet.balance_error = None;
                                this.wallet.status = None;
                            }
                            Err(error) => {
                                this.wallet.balance_error =
                                    Some(SharedString::from(format!("create-wallet failed: {error}")));
                            }
                        }
                        cx.notify();
                    })
                    .log_err();
                });
                self.refresh_task = Some(task);
                cx.notify();
            }
            InputRequest::WalletUnlockPassword => {
                let Some(supervisor) = self.supervisor.clone() else {
                    return;
                };
                let idempotency_key = self.next_idempotency_key();
                let task = cx.spawn(async move |this, cx| {
                    let result = supervisor
                        .lock()
                        .await
                        .unlock(&idempotency_key, &value)
                        .await;
                    this.update(cx, |this, cx| {
                        if let Err(error) = result {
                            this.wallet.balance_error =
                                Some(SharedString::from(format!("unlock failed: {error}")));
                        }
                        cx.notify();
                    })
                    .log_err();
                });
                self.refresh_task = Some(task);
                cx.notify();
            }
            InputRequest::FundAmount => {
                let Some(supervisor) = self.supervisor.clone() else {
                    return;
                };
                let Ok(amount_sat) = value.trim().parse::<u64>() else {
                    self.wallet.invoice_error = Some("amount must be a positive integer (sats)".into());
                    cx.notify();
                    return;
                };
                if amount_sat == 0 {
                    self.wallet.invoice_error = Some("amount must be positive".into());
                    cx.notify();
                    return;
                }
                let idempotency_key = self.next_idempotency_key();
                let task = cx.spawn(async move |this, cx| {
                    let result = supervisor
                        .lock()
                        .await
                        .make_invoice(amount_sat, "sovereign wallet fund", &idempotency_key)
                        .await;
                    this.update(cx, |this, cx| {
                        match result {
                            Ok(invoice) => {
                                this.wallet.invoice = Some(invoice);
                                this.wallet.invoice_error = None;
                            }
                            Err(error) => {
                                this.wallet.invoice_error =
                                    Some(SharedString::from(format!("make-invoice failed: {error}")));
                            }
                        }
                        cx.notify();
                    })
                    .log_err();
                });
                self.refresh_task = Some(task);
                cx.notify();
            }
            InputRequest::VaultPassphrase => {
                if self.identity.ceremony_mnemonic.is_some() {
                    // Ceremony in progress: passphrase captured, next the challenge.
                    self.identity.ceremony_passphrase = Some(value);
                    self.ceremony_advance(cx);
                } else {
                    // Plain vault unlock.
                    self.unlock_vault_with_passphrase(value, cx);
                }
            }
            InputRequest::ChallengeWord { label } => {
                self.identity.ceremony_answers.push((label.clone(), value));
                let answered: Vec<SharedString> = self
                    .identity
                    .ceremony_answers
                    .iter()
                    .map(|(label, _)| label.clone())
                    .collect();
                if self
                    .identity
                    .ceremony_labels
                    .iter()
                    .all(|label| answered.contains(label))
                {
                    let passphrase = self.identity.ceremony_passphrase.take().unwrap_or_default();
                    self.identity_ceremony_commit(passphrase, cx);
                } else {
                    self.ceremony_advance(cx);
                }
            }
            InputRequest::MandateAmount => {
                let Ok(amount_sat) = value.trim().parse::<u64>() else {
                    self.mandates.proposal_notice =
                        Some("amount must be a positive integer (sats)".into());
                    cx.notify();
                    return;
                };
                if amount_sat == 0 {
                    self.mandates.proposal_notice = Some("amount must be positive".into());
                    cx.notify();
                    return;
                }
                self.mandates.pending_amount = Some(amount_sat);
                self.pending_input = Some(PendingInput {
                    request: InputRequest::MandateExpiryHours,
                    label: "Authorization expiry (hours)".into(),
                    detail: "Default 24 hours. After expiry, payments are refused until renewed."
                        .into(),
                });
                cx.notify();
            }
            InputRequest::MandateExpiryHours => {
                let Ok(expiry_hours) = value.trim().parse::<u64>() else {
                    self.mandates.proposal_notice =
                        Some("expiry must be a positive integer (hours)".into());
                    cx.notify();
                    return;
                };
                if let Some(amount) = self.mandates.pending_amount.take() {
                    self.propose_authorization(amount, expiry_hours.max(1));
                } else {
                    self.mandates.proposal_notice =
                        Some("authorization flow restarted; enter the amount again".into());
                }
                cx.notify();
            }
            InputRequest::McpServerId => {
                // WP-6: Add Mapping step 1 — the server id, then the pubkey.
                let server_id = value.trim().to_string();
                if server_id.is_empty() {
                    self.mapping_error = Some("the MCP server id must not be empty".into());
                    cx.notify();
                    return;
                }
                self.pending_input = Some(PendingInput {
                    request: InputRequest::McpPrincipalPubkey,
                    label: "Nostr pubkey (64-hex)".into(),
                    detail: "The pubkey-keyed identity this server's paid tool calls attribute to \
                             (design §5.4). Leave empty to UNSET an existing mapping. The field is \
                             not masked; clear it after use."
                        .into(),
                });
                self.mapping_server_id = Some(server_id);
                cx.notify();
            }
            InputRequest::McpPrincipalPubkey => {
                // WP-6: Add Mapping step 2 — commit the mapping (empty = unset).
                let server_id = self.mapping_server_id.take().unwrap_or_default();
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    self.commit_mapping(server_id, None, cx);
                } else if !is_valid_pubkey_hex(&trimmed) {
                    self.mapping_error =
                        Some("the Nostr pubkey must be 64-hex (a public key, never a secret)".into());
                    cx.notify();
                } else {
                    self.commit_mapping(server_id, Some(trimmed), cx);
                }
            }
        }
    }

    fn unlock_vault_with_passphrase(&mut self, passphrase: String, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            return;
        };
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let result = supervisor
                .lock()
                .await
                .vault_unlock(&passphrase)
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(value) => {
                        let npub = value
                            .get("derivedNpub")
                            .and_then(serde_json::Value::as_str)
                            .map(ToString::to_string);
                        let pubkey_hex = value
                            .get("derivedPubkeyHex")
                            .and_then(serde_json::Value::as_str)
                            .map(ToString::to_string);
                        this.identity.status = Some(IdentityStatusResult {
                            vault_state: "unlocked".into(),
                            derived_npub: npub,
                            derived_pubkey_hex: pubkey_hex,
                            recovery_artifact_state: "absent".into(),
                            note: String::new(),
                        });
                        this.identity.identity_error = None;
                    }
                    Err(error) => {
                        this.identity.identity_error =
                            Some(SharedString::from(format!("vault unlock failed: {error}")));
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    // -----------------------------------------------------------------------
    // Render helpers
    // -----------------------------------------------------------------------

    fn wallet_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let network_label = self
            .wallet
            .status
            .as_ref()
            .map(|status| status.network.as_str())
            .unwrap_or("signet");
        let body = if self.supervisor.is_none() {
            v_flex()
                .child(Label::new("Wallet unavailable").size(LabelSize::Small).color(Color::Error))
                .child(
                    Label::new("the sovereign wallet lane is off (OMEGA_SOVEREIGN_WALLET=1 not set)")
                        .size(LabelSize::Small)
                        .color(Color::Muted),
                )
        } else if let Some(error) = &self.wallet.balance_error {
            v_flex()
                .child(Label::new("Wallet unavailable").size(LabelSize::Small).color(Color::Error))
                .child(Label::new(error.clone()).size(LabelSize::Small).color(Color::Muted))
        } else if let Some(status) = &self.wallet.status {
            match status.wallet_state {
                sovereign_wallet::WalletState::Ready => {
                    let (primary, secondary) =
                        wallet_balance_label(self.wallet.balance.as_ref(), network_label);
                    v_flex()
                        .child(
                            Label::new(primary)
                                .size(LabelSize::Default)
                                .weight(FontWeight::SEMIBOLD),
                        )
                        .child(
                            Label::new(secondary)
                                .size(LabelSize::Small)
                                .color(Color::Muted),
                        )
                }
                sovereign_wallet::WalletState::None => v_flex()
                    .child(Label::new("No wallet yet").size(LabelSize::Small))
                    .child(
                        Label::new(format!("operator: create the wallet on {network_label}"))
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    ),
                sovereign_wallet::WalletState::Locked => v_flex()
                    .child(Label::new("Wallet locked").size(LabelSize::Small).color(Color::Warning))
                    .child(
                        Label::new(format!("operator: unlock on {network_label}"))
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    ),
                sovereign_wallet::WalletState::Syncing => v_flex()
                    .child(
                        Label::new("Wallet syncing…")
                            .size(LabelSize::Small)
                            .color(Color::Warning),
                    )
                    .child(
                        Label::new(format!("real state on {network_label} — never a fake zero"))
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    ),
                sovereign_wallet::WalletState::Error => v_flex()
                    .child(Label::new("Wallet error").size(LabelSize::Small).color(Color::Error))
                    .child(
                        Label::new("see the sidecar log (redacted)")
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    ),
            }
        } else {
            v_flex().child(
                Label::new("Reading wallet state…")
                    .size(LabelSize::Small)
                    .color(Color::Muted),
            )
        };

        let state = self
            .wallet
            .status
            .as_ref()
            .map(|status| status.wallet_state.clone());
        let controls = match state {
            Some(sovereign_wallet::WalletState::None) => v_flex()
                .child(
                    Button::new("sw-wallet-create", "Create")
                        .style(ButtonStyle::Subtle)
                        .tooltip(ui::Tooltip::text("Create the Wavelength wallet (operator-only)"))
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.create_wallet_flow(window, cx);
                        })),
                )
                .into_any_element(),
            Some(sovereign_wallet::WalletState::Locked) => v_flex()
                .child(
                    Button::new("sw-wallet-unlock", "Unlock")
                        .style(ButtonStyle::Subtle)
                        .tooltip(ui::Tooltip::text("Unlock the wallet (operator-only)"))
                        .on_click(cx.listener(|this, _, _, cx| this.unlock_wallet_flow(cx))),
                )
                .into_any_element(),
            Some(sovereign_wallet::WalletState::Ready) => h_flex()
                .gap_2()
                .child(
                    Button::new("sw-wallet-lock", "Lock")
                        .style(ButtonStyle::Subtle)
                        .tooltip(ui::Tooltip::text("Lock the wallet and the vault (operator-only)"))
                        .on_click(cx.listener(|this, _, _, cx| this.lock_wallet(cx))),
                )
                .child(
                    Button::new("fund-wallet", "Fund")
                        .style(ButtonStyle::Subtle)
                        .tooltip(ui::Tooltip::text("Mint a real signet receive invoice"))
                        .on_click(cx.listener(|this, _, _, cx| this.fund_flow(cx))),
                )
                .into_any_element(),
            _ => v_flex().into_any_element(),
        };

        let invoice = self.wallet.invoice.as_ref().map(|invoice| {
            let tokens = MarketTokens::from_theme(cx);
            let qr = QrCodeCanvas::encode(invoice.invoice.as_bytes())
                .ok()
                .map(|qr| qr.size(136.0).tokens(tokens));
            let qr_missing = qr.is_none();
            let invoice_text = SharedString::from(invoice.invoice.clone());
            h_flex()
                .w_full()
                .items_start()
                .gap_3()
                .child(
                    div()
                        .size(px(136.0))
                        .when_some(qr, |this, qr| this.child(qr))
                        .when(qr_missing, |this| {
                            this.flex()
                                .items_center()
                                .justify_center()
                                .border_1()
                                .border_color(tokens.grid)
                                .child(
                                    Label::new("QR unavailable")
                                        .size(LabelSize::XSmall)
                                        .color(Color::Muted),
                                )
                        }),
                )
                .child(
                    v_flex()
                        .flex_1()
                        .gap_2()
                        .child(
                            Label::new(format!(
                                "{} sats · {} · {}",
                                invoice.amount_sat,
                                invoice.hrp,
                                if network_label == "regtest" {
                                    "regtest — local test coins only"
                                } else {
                                    "signet test coins — never mainnet"
                                }
                            ))
                            .size(LabelSize::XSmall)
                            .color(Color::Muted),
                        )
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    div()
                                        .flex_1()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .font_family("monospace")
                                        .text_size(px(11.0))
                                        .child(invoice_text.clone()),
                                )
                                .child(
                                    CopyButton::new("sw-invoice-copy", invoice_text)
                                        .icon_size(IconSize::XSmall),
                                ),
                        ),
                )
                .into_any_element()
        });

        let create_aezeed = self.wallet.create_aezeed.as_ref().map(|aezeed| {
            let phrase = aezeed.join(" ");
            let phrase_shared = SharedString::from(phrase.clone());
            v_flex()
                .w_full()
                .gap_1()
                .child(
                    Label::new("Show-once aezeed backup phrase (record it now):")
                        .size(LabelSize::XSmall)
                        .color(Color::Warning),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            div()
                                .flex_1()
                                .font_family("monospace")
                                .text_size(px(11.0))
                                .child(Label::new(phrase).size(LabelSize::XSmall)),
                        )
                        .child(
                            CopyButton::new("sw-aezeed-copy", phrase_shared)
                                .icon_size(IconSize::XSmall),
                        ),
                )
                .child(
                    Button::new("sw-aezeed-ack", "I recorded the phrase")
                        .style(ButtonStyle::Subtle)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.wallet.create_aezeed = None;
                            cx.notify();
                        })),
                )
                .into_any_element()
        });

        v_flex()
            .w_full()
            .gap_2()
            .child(body)
            .child(controls)
            .children(self.wallet.create_note.clone().map(|note| {
                Label::new(note)
                    .size(LabelSize::XSmall)
                    .color(Color::Muted)
                    .into_any_element()
            }))
            .children(create_aezeed)
            .children(invoice)
            .children(self.wallet.invoice_error.clone().map(|error| {
                Label::new(error)
                    .size(LabelSize::XSmall)
                    .color(Color::Error)
                    .into_any_element()
            }))
            .into_any_element()
    }

    fn identity_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let body = if let Some(identity) = &self.identity.status {
            match identity.vault_state.as_str() {
                "unlocked" => {
                    let npub = identity
                        .derived_npub
                        .clone()
                        .unwrap_or_else(|| "npub unavailable".into());
                    let npub_shared = SharedString::from(npub.clone());
                    v_flex()
                        .child(
                            Label::new("Agent identity (derived, read-only)")
                                .size(LabelSize::Small),
                        )
                        .child(
                            h_flex()
                                .gap_2()
                                .child(
                                    div()
                                        .flex_1()
                                        .overflow_hidden()
                                        .text_ellipsis()
                                        .font_family("monospace")
                                        .text_size(px(11.0))
                                        .child(Label::new(npub).size(LabelSize::XSmall)),
                                )
                                .child(
                                    CopyButton::new("sw-npub-copy", npub_shared)
                                        .icon_size(IconSize::XSmall),
                                ),
                        )
                        .child(
                            Label::new(
                                "vault unlocked · derived from the BIP-39/NIP-06 root (OMEGA-DELTA-0284)",
                            )
                            .size(LabelSize::XSmall)
                            .color(Color::Muted),
                        )
                }
                "locked" => v_flex()
                    .child(Label::new("Vault locked").size(LabelSize::Small).color(Color::Warning))
                    .child(
                        Label::new("unlock the vault to read the derived identity")
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    ),
                _ => v_flex()
                    .child(Label::new("No identity yet").size(LabelSize::Small))
                    .child(
                        Label::new("the identity ceremony creates the vault (operator-only)")
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    ),
            }
        } else if let Some(error) = &self.identity.identity_error {
            v_flex()
                .child(Label::new("Identity unavailable").size(LabelSize::Small).color(Color::Error))
                .child(Label::new(error.clone()).size(LabelSize::Small).color(Color::Muted))
        } else {
            v_flex().child(
                Label::new("Reading identity…")
                    .size(LabelSize::Small)
                    .color(Color::Muted),
            )
        };

        let vault_state = self
            .identity
            .status
            .as_ref()
            .map(|identity| identity.vault_state.clone());
        let controls = match vault_state.as_deref() {
            Some("none") | None => v_flex()
                .gap_2()
                .child(
                    Button::new("sw-identity-init", "Initialize Identity")
                        .style(ButtonStyle::Subtle)
                        .tooltip(ui::Tooltip::text(
                            "Identity ceremony: mnemonic show-once + word challenge (operator-only)",
                        ))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.identity_ceremony_start(cx);
                        })),
                )
                .into_any_element(),
            Some("locked") => v_flex()
                .gap_2()
                .child(
                    Button::new("sw-vault-unlock", "Unlock Vault")
                        .style(ButtonStyle::Subtle)
                        .on_click(cx.listener(|this, _, _, cx| this.unlock_vault_flow(cx))),
                )
                .into_any_element(),
            Some("unlocked") => h_flex()
                .gap_2()
                .child(
                    Button::new("sw-export-nsec", "Export Nostr secret (one-time)")
                        .style(ButtonStyle::Subtle)
                        .tooltip(ui::Tooltip::text(
                            "One-time operator bridge to the Rust omega_identity import ceremony",
                        ))
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.export_secret_flow(window, cx);
                        })),
                )
                .child(
                    Button::new("sw-vault-lock", "Lock Vault")
                        .style(ButtonStyle::Subtle)
                        .on_click(cx.listener(|this, _, _, cx| this.lock_wallet(cx))),
                )
                .into_any_element(),
            _ => v_flex().into_any_element(),
        };

        // The pending ceremony (show-once mnemonic).
        let ceremony = self.identity.ceremony_mnemonic.as_ref().map(|mnemonic| {
            let mnemonic_shared = mnemonic.clone();
            let labels = self
                .identity
                .ceremony_labels
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            v_flex()
                .w_full()
                .gap_2()
                .child(
                    Label::new("Record these 12 words — shown once, never again:")
                        .size(LabelSize::XSmall)
                        .color(Color::Warning),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            div()
                                .flex_1()
                                .font_family("monospace")
                                .text_size(px(11.0))
                                .child(Label::new(mnemonic.clone()).size(LabelSize::XSmall)),
                        )
                        .child(
                            CopyButton::new("sw-mnemonic-copy", mnemonic_shared)
                                .icon_size(IconSize::XSmall),
                        ),
                )
                .child(
                    Label::new(format!(
                        "Challenge: you will be asked for the words at positions {labels}."
                    ))
                    .size(LabelSize::XSmall)
                    .color(Color::Muted),
                )
                .into_any_element()
        });

        // The one-time exported nsec (show-once, cleared by the operator).
        let export = self.identity.exported_nsec.as_ref().map(|nsec| {
            let nsec_shared = nsec.clone();
            v_flex()
                .w_full()
                .gap_2()
                .child(
                    Label::new("Nostr secret — shown once (bridge to omega_identity import):")
                        .size(LabelSize::XSmall)
                        .color(Color::Warning),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            div()
                                .flex_1()
                                .font_family("monospace")
                                .text_size(px(11.0))
                                .child(Label::new(nsec.clone()).size(LabelSize::XSmall)),
                        )
                        .child(CopyButton::new("sw-nsec-copy", nsec_shared).icon_size(IconSize::XSmall)),
                )
                .child(
                    Button::new("sw-nsec-clear", "Clear from screen")
                        .style(ButtonStyle::Subtle)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.identity.exported_nsec = None;
                            cx.notify();
                        })),
                )
                .into_any_element()
        });

        let link = h_flex()
            .w_full()
            .justify_between()
            .items_center()
            .child(
                Label::new(
                    "Cross-machine linking is out of scope this phase (the identity derives from this vault root).",
                )
                .size(LabelSize::XSmall)
                .color(Color::Muted),
            )
            .child(
                Button::new("link-nostr-id", "Link")
                    .style(ButtonStyle::Subtle)
                    .tooltip(ui::Tooltip::text("Link a Nostr identity (stubbed)"))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.stub(
                            "Cross-machine Nostr identity linking is stubbed (out of scope this phase).",
                            cx,
                        );
                    })),
            )
            .into_any_element();

        v_flex()
            .w_full()
            .gap_2()
            .child(body)
            .child(controls)
            .children(ceremony)
            .children(export)
            .children(self.identity.export_error.clone().map(|error| {
                Label::new(error)
                    .size(LabelSize::XSmall)
                    .color(Color::Error)
                    .into_any_element()
            }))
            .child(link)
            .into_any_element()
    }

    fn plugins_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let plugin_rows: Vec<AnyElement> = STUB_PLUGINS
            .iter()
            .map(|(name, state)| {
                let id = SharedString::from(format!("plugin-{name}"));
                self.stub_row(id, name, state, "Plugin removal is stubbed.", cx)
            })
            .collect();
        v_flex()
            .w_full()
            .gap_2()
            .children(plugin_rows)
            .child(
                Button::new("add-plugin", "Add Plugin")
                    .style(ButtonStyle::Subtle)
                    .tooltip(ui::Tooltip::text("Add a plugin (stubbed)"))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.stub("Plugin creation is stubbed.", cx);
                    })),
            )
            .into_any_element()
    }

    fn mcp_section(&self, cx: &mut Context<Self>) -> AnyElement {
        // REAL configured MCP servers from the settings store (design §6.4).
        let context_servers = ProjectSettings::get_global(cx).context_servers.clone();
        let identity_npub = self
            .identity
            .status
            .as_ref()
            .and_then(|identity| identity.derived_npub.clone());
        // WP-6: the REAL persisted mapping from the L-402 gateway store
        // (server -> Nostr identity, design §6.4/§5.4).
        let rows = mcp_mapping_rows(
            context_servers.keys().map(|id| id.as_ref()),
            identity_npub.as_deref(),
            &self.mcp_identity_map,
        );
        // WP-6: the L-402 gateway state surfaced honestly (real value from the
        // sidecar `status` — ready/locked/absent, never a claim without a
        // gateway behind it).
        let gateway_state = self
            .wallet
            .status
            .as_ref()
            .map(|status| status.l402_gateway_state.clone())
            .unwrap_or_else(|| "absent".into());
        let gateway_line = format!("L-402 gateway: {gateway_state} — signet/testnet only (D4)");
        let mapping_error = self.mapping_error.clone();
        let rows_elements: Vec<AnyElement> = rows
            .iter()
            .map(|(server, mapped)| {
                let id = SharedString::from(format!("mcp-{server}"));
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
                            .child(Label::new(server.clone()).size(LabelSize::Small))
                            .child(
                                Label::new(mapped.clone())
                                    .size(LabelSize::Small)
                                    .color(Color::Muted),
                            ),
                    )
                    .into_any_element()
            })
            .collect();
        v_flex()
            .w_full()
            .gap_2()
            .when(rows_elements.is_empty(), |this| {
                this.child(
                    Label::new("No MCP servers configured")
                        .size(LabelSize::Small)
                        .color(Color::Muted),
                )
            })
            .children(rows_elements)
            .child(
                Label::new(gateway_line)
                    .size(LabelSize::XSmall)
                    .color(Color::Muted),
            )
            .when(mapping_error.is_some(), |this| {
                this.child(
                    Label::new(mapping_error.unwrap_or_default())
                        .size(LabelSize::XSmall)
                        .color(Color::Error),
                )
            })
            .child(
                Button::new("add-mcp", "Add Mapping")
                    .style(ButtonStyle::Subtle)
                    .tooltip(ui::Tooltip::text(
                        "Map a configured MCP server to a Nostr pubkey (the L-402 entitlement attribution, design §6.4)",
                    ))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.add_mapping_flow(cx);
                    })),
            )
            .into_any_element()
    }

    /// WP-6: the Add Mapping control — REAL, wired to the L-402 gateway store
    /// through the sidecar's `mcp-identity-map-set` (design §6.4). Two-step
    /// input: the MCP server id, then the 64-hex Nostr pubkey (empty = unset).
    fn add_mapping_flow(&mut self, cx: &mut Context<Self>) {
        if self.supervisor.is_none() {
            self.stub_notice =
                Some("MCP mapping unavailable — the sovereign wallet lane is off (OMEGA_SOVEREIGN_WALLET=1 not set).");
            cx.notify();
            return;
        }
        self.pending_input = Some(PendingInput {
            request: InputRequest::McpServerId,
            label: "MCP server id".into(),
            detail: "The id of a configured MCP server (e.g. \"om\"). The mapping is persisted in \
                     the L-402 gateway store and attributes paid tool calls to this identity (design §5.4)."
                .into(),
        });
        cx.notify();
    }

    fn commit_mapping(&mut self, server_id: String, principal_pubkey: Option<String>, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            return;
        };
        let task = cx.spawn(async move |this, cx| {
            let result = supervisor
                .lock()
                .await
                .mcp_identity_map_set(&server_id, principal_pubkey.as_deref())
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(_) => {
                        this.mapping_error = None;
                        // Re-read the mapping so the rows reflect the stored state.
                        this.refresh(cx);
                    }
                    Err(error) => {
                        this.mapping_error = Some(SharedString::from(format!("mapping failed: {error}")));
                        cx.notify();
                    }
                }
            })
            .log_err();
        });
        self.refresh_task = Some(task);
        cx.notify();
    }

    fn authorizations_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let body = if let Some(snapshot) = &self.mandates.snapshot {
            let rows: Vec<AnyElement> = snapshot
                .mandates
                .iter()
                .map(|mandate| {
                    let usage = MandateUsage::default();
                    let card = MandateStatusCard::new(
                        mandate,
                        &usage,
                        snapshot.revision,
                        command_center_ui::unix_now_ms(),
                    );
                    let scope = mandate_scope_label(mandate);
                    let revoke = if mandate.principal_pubkey.is_none() {
                        let venue = mandate.venue.clone();
                        let network = mandate.network;
                        Some(
                            Button::new(
                                SharedString::from(format!(
                                    "revoke-{}-{:?}",
                                    mandate.venue, mandate.network
                                )),
                                "Revoke",
                            )
                            .style(ButtonStyle::Subtle)
                            .tooltip(ui::Tooltip::text(
                                "Revoke the venue-wide mandate (no approval needed)",
                            ))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.revoke_venue_wide(&venue, network, window, cx);
                            })),
                        )
                    } else {
                        None
                    };
                    v_flex()
                        .w_full()
                        .gap_1()
                        .child(
                            Label::new(scope)
                                .size(LabelSize::XSmall)
                                .color(Color::Muted),
                        )
                        .child(card)
                        .children(revoke.map(|button| {
                            h_flex().w_full().justify_end().child(button).into_any_element()
                        }))
                        .into_any_element()
                })
                .collect();
            v_flex()
                .w_full()
                .gap_2()
                .when(rows.is_empty(), |this| {
                    this.child(
                        Label::new("No active authorizations")
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    )
                })
                .children(rows)
                .into_any_element()
        } else if let Some(error) = &self.mandates.store_error {
            v_flex()
                .child(
                    Label::new("Authorizations unavailable")
                        .size(LabelSize::Small)
                        .color(Color::Error),
                )
                .child(Label::new(error.clone()).size(LabelSize::Small).color(Color::Muted))
                .into_any_element()
        } else {
            v_flex()
                .child(
                    Label::new("Reading authorizations…")
                        .size(LabelSize::Small)
                        .color(Color::Muted),
                )
                .into_any_element()
        };

        let new_authorization = Button::new("new-mandate", "New Authorization")
            .style(ButtonStyle::Subtle)
            .tooltip(ui::Tooltip::text(
                "Create a pubkey-keyed spending authorization for the sovereign-wallet venue",
            ))
            .on_click(cx.listener(|this, _, _, cx| this.new_authorization_flow(cx)));

        // The bound approval dialog (reused command_center_ui component).
        // The on_action handler receives the action BY VALUE (the dialog's
        // `MandateActionHandler` shape), so the entity handle is captured
        // instead of a `cx.listener`.
        let dialog = self.mandates.proposal.as_ref().map(|value| {
            let value = value.clone();
            let this = cx.entity();
            MandateApprovalDialog::new(value)
                .on_action(move |action, _window, cx| match action {
                    MandateEditorAction::Approve { .. } => {
                        this.update(cx, |this, cx| {
                            this.approve_proposal();
                            cx.notify();
                        });
                    }
                    _ => {
                        this.update(cx, |this, cx| {
                            this.reject_proposal();
                            cx.notify();
                        });
                    }
                })
                .into_any_element()
        });

        v_flex()
            .w_full()
            .gap_2()
            .child(body)
            .child(new_authorization)
            .children(dialog)
            .children(self.mandates.proposal_notice.clone().map(|notice| {
                Label::new(notice)
                    .size(LabelSize::XSmall)
                    .color(Color::Warning)
                    .into_any_element()
            }))
            .into_any_element()
    }

    /// The single operator input row (rendered when a flow needs text entry).
    fn input_row(&self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let Some(pending) = self.pending_input.clone() else {
            return div().into_any_element();
        };
        let editor = window.use_keyed_state(
            SharedString::from(format!("{}-editor", pending.request.key())),
            cx,
            |window, cx| {
                let mut editor = Editor::single_line(window, cx);
                editor.set_placeholder_text("…", window, cx);
                editor
            },
        );
        let editor_for_confirm = editor.clone();
        v_flex()
            .w_full()
            .gap_2()
            .p_2()
            .rounded_md()
            .border_1()
            .border_color(cx.theme().colors().border)
            .bg(cx.theme().colors().editor_background)
            .child(Label::new(pending.label.clone()).size(LabelSize::Small))
            .child(
                Label::new(pending.detail.clone())
                    .size(LabelSize::XSmall)
                    .color(Color::Muted),
            )
            .child(editor)
            .child(
                h_flex()
                    .w_full()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("sw-input-cancel", "Cancel")
                            .style(ButtonStyle::Subtle)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.pending_input = None;
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("sw-input-confirm", "Confirm")
                            .style(ButtonStyle::Filled)
                            .on_click(cx.listener(move |this, _, _window, cx| {
                                let value = editor_for_confirm
                                    .read_with(cx, |editor, cx| editor.text(cx));
                                this.confirm_input(pending.request.clone(), value, cx);
                            })),
                    ),
            )
            .into_any_element()
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
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Auto-refresh on the interval (and after every action via refresh()).
        if command_center_ui::unix_now_ms() - self.refreshed_at_ms
            > REFRESH_INTERVAL.as_millis() as i64
        {
            self.refresh(cx);
        }

        let panel_background = cx.theme().colors().panel_background;
        let element_hover = cx.theme().colors().element_hover;

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
            // Agent Nostr identity (real)
            .child(self.section_header("Agent Nostr ID"))
            .child(self.identity_section(cx))
            // Wallet (real)
            .child(self.section_header("Agent Wallet"))
            .child(self.wallet_section(cx))
            // Operator input row (ceremony entry)
            .child(self.input_row(window, cx))
            // Plugins (stubbed)
            .child(self.section_header("Plugins"))
            .child(self.plugins_section(cx))
            // MCP servers mapped to Nostr IDs (real mapping)
            .child(self.section_header("MCP Servers → Nostr IDs"))
            .child(self.mcp_section(cx))
            // Spending authorizations (real generalized store)
            .child(self.section_header("Spending Authorizations"))
            .child(self.authorizations_section(cx))
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

// ---------------------------------------------------------------------------
// Pure helpers (tested)
// ---------------------------------------------------------------------------

/// The wallet balance line: real confirmed sats with the honest network label.
fn wallet_balance_label(balance: Option<&BalanceResult>, network: &str) -> (String, String) {
    let Some(balance) = balance else {
        return (
            "Balance unavailable".into(),
            format!("read-only balance on {network} (sidecar)"),
        );
    };
    let confirmed = balance.confirmed_sat.parse::<u64>().unwrap_or(0);
    let pending_in = balance.pending_in_sat.parse::<u64>().unwrap_or(0);
    let pending_out = balance.pending_out_sat.parse::<u64>().unwrap_or(0);
    let network_note = if network == "regtest" {
        "regtest — local test coins only"
    } else {
        "signet test coins — never mainnet"
    };
    if pending_in == 0 && pending_out == 0 {
        (
            format!("{confirmed} sats"),
            format!("read-only · {network_note}"),
        )
    } else {
        (
            format!("{confirmed} sats"),
            format!("read-only · +{pending_in} in / -{pending_out} out · {network_note}"),
        )
    }
}

/// The mandate scope line: venue-wide vs principal-keyed (pubkey prefix).
fn mandate_scope_label(mandate: &TradingMandate) -> String {
    match &mandate.principal_pubkey {
        Some(principal) => format!(
            "pubkey-keyed · {} · principal {}…",
            mandate.venue,
            &principal[..principal.len().min(8)]
        ),
        None => format!("venue-wide · {}", mandate.venue),
    }
}

fn network_label(network: TradingNetwork) -> &'static str {
    match network {
        TradingNetwork::Signet => "signet",
        TradingNetwork::Testnet => "testnet",
        TradingNetwork::Mainnet => "mainnet",
    }
}

/// A public Nostr pubkey is exactly 64 hex chars (never key material).
fn is_valid_pubkey_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Map configured MCP server ids to a persisted Nostr identity where the
/// operator mapped one (design §6.4 — the L-402 entitlement attribution), to
/// the derived identity npub where the identity seam exists, or to an honest
/// "unmapped" label otherwise.
fn mcp_mapping_rows<'a>(
    server_ids: impl Iterator<Item = &'a str>,
    identity_npub: Option<&str>,
    persisted_map: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut servers = server_ids.map(ToString::to_string).collect::<Vec<_>>();
    servers.sort();
    servers
        .into_iter()
        .map(|server| {
            let short = |npub: &str| {
                if npub.len() > 16 {
                    format!("{}…{}", &npub[..8], &npub[npub.len() - 4..])
                } else {
                    npub.to_string()
                }
            };
            let mapped = if let Some(principal) = persisted_map.get(&server) {
                format!("nostr: {} (mapped)", short(principal))
            } else if let Some(npub) = identity_npub {
                format!("nostr: {} (agent identity)", short(npub))
            } else {
                "unmapped — no agent identity yet".to_string()
            };
            (server, mapped)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn wallet_balance_label_shows_real_sats_and_the_honest_network() {
        let balance = BalanceResult {
            confirmed_sat: "12345".into(),
            pending_in_sat: "0".into(),
            pending_out_sat: "0".into(),
            credit_available_sat: "0".into(),
            credit_reserved_sat: "0".into(),
        };
        let (primary, secondary) = wallet_balance_label(Some(&balance), "signet");
        assert_eq!(primary, "12345 sats");
        assert!(secondary.contains("read-only"), "{secondary}");
        assert!(secondary.contains("signet"), "{secondary}");
        assert!(secondary.contains("never mainnet"), "{secondary}");
        let (primary, secondary) = wallet_balance_label(None, "signet");
        assert_eq!(primary, "Balance unavailable");
        assert!(secondary.contains("read-only"), "{secondary}");
    }

    #[test]
    fn wallet_balance_label_shows_inflight_sats_when_present() {
        let balance = BalanceResult {
            confirmed_sat: "100".into(),
            pending_in_sat: "50".into(),
            pending_out_sat: "20".into(),
            credit_available_sat: "0".into(),
            credit_reserved_sat: "0".into(),
        };
        let (_, secondary) = wallet_balance_label(Some(&balance), "regtest");
        assert!(secondary.contains("+50 in"), "{secondary}");
        assert!(secondary.contains("-20 out"), "{secondary}");
    }

    #[test]
    fn mandate_scope_label_distinguishes_venue_wide_from_principal_keyed() {
        let mut venue_wide = sovereign_wallet::sovereign_wallet_mandate_candidate(
            "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
            1_000,
            1,
        );
        venue_wide.principal_pubkey = None;
        assert!(mandate_scope_label(&venue_wide).contains("venue-wide"));
        let principal_keyed = sovereign_wallet::sovereign_wallet_mandate_candidate(
            "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
            1_000,
            1,
        );
        let label = mandate_scope_label(&principal_keyed);
        assert!(label.contains("pubkey-keyed"), "{label}");
        assert!(label.contains("a1b2c3d4…"), "{label}");
    }

    #[test]
    fn mcp_mapping_uses_the_identity_seam_and_labels_unmapped_honestly() {
        use settings::ContextServerCommand;
        let mut servers = HashMap::new();
        let stdio = |path: &str| project::project_settings::ContextServerSettings::Stdio {
            enabled: true,
            remote: false,
            command: ContextServerCommand {
                path: path.into(),
                args: vec![],
                env: None,
                timeout: None,
            },
        };
        servers.insert(std::sync::Arc::<str>::from("om"), stdio("om"));
        servers.insert(
            std::sync::Arc::<str>::from("source-summarization"),
            stdio("node"),
        );
        let empty_map = std::collections::HashMap::new();
        let rows = mcp_mapping_rows(
            servers.keys().map(|id| id.as_ref()),
            Some("npub1az708q3kd9zy6z6f44zav5ygvdwelkzspf6mtusttx47lft2z38sghk0w7"),
            &empty_map,
        );
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter().all(|(_, mapped)| mapped.contains("nostr:")),
            "{rows:?}"
        );
        let unmapped = mcp_mapping_rows(servers.keys().map(|id| id.as_ref()), None, &empty_map);
        assert!(
            unmapped.iter().all(|(_, mapped)| mapped.contains("unmapped")),
            "{unmapped:?}"
        );
    }

    #[test]
    fn mcp_mapping_prefers_the_persisted_l402_map_and_labels_mapped_rows() {
        // WP-6 (design §6.4): a persisted server -> Nostr-identity mapping
        // from the L-402 gateway store is the L-402 entitlement attribution;
        // the row must show it as "mapped", distinct from the derived-identity
        // fallback.
        let mut persisted = std::collections::HashMap::new();
        persisted.insert(
            "om".to_string(),
            "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0".to_string(),
        );
        let rows = mcp_mapping_rows(
            ["om", "other"].into_iter(),
            Some("npub1az708q3kd9zy6z6f44zav5ygvdwelkzspf6mtusttx47lft2z38sghk0w7"),
            &persisted,
        );
        let om = rows.iter().find(|(server, _)| server == "om").expect("om row");
        assert!(om.1.contains("(mapped)"), "{}", om.1);
        assert!(om.1.contains("a1b2c3d4…"), "{}", om.1);
        let other = rows.iter().find(|(server, _)| server == "other").expect("other row");
        assert!(other.1.contains("(agent identity)"), "{}", other.1);
    }
}