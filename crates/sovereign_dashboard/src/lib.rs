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
//! WP-10 (OA-P2-WALLET-2026-08-26 close-out; founder direction: zero stubbed
//! surfaces) wired the last two explicitly-stubbed controls to REAL machinery:
//! - Plugins: the REAL installed-extension registry (`ExtensionStore`, the
//!   `extension_host` crate — the extension/plugin system behind "plugins the
//!   agent runs"). Rows render real installed extensions (id/name/version/dev),
//!   Remove performs a real `uninstall_extension`, Add Plugin performs the
//!   real `install_latest_extension` registry flow, and in-flight
//!   install/remove/upgrade operations render from
//!   `outstanding_operations()`. The section copy labels the mapping honestly
//!   ("the extension host's installed set — this is the real plugin registry").
//! - Link (cross-machine): a REAL NIP-46 remote-signer pairing ceremony
//!   through the `omega_identity::nip46` pairing state machine and the
//!   `omega_signer_broker` relay coordinator (`SignerRoute::RemoteNip46` — the
//!   real machinery for linking this machine's agent to a remote signer on
//!   another machine). The ceremony drives the real states
//!   (AwaitingApproval → AwaitingAcknowledgement → AwaitingUserPublicKey →
//!   AwaitingFinalApproval → AwaitingSignedChallenge → AwaitingRegistration →
//!   Active), persists pairing state on disk through `Nip46Service`, and the
//!   section surfaces a real status from `AccountRegistryService` (registered
//!   remote accounts, signer availability, last use) with a real Disconnect.
//!
//! HONESTY LAW (unchanged): every control that is not real-and-verified keeps
//! an explicit stubbed notice; nothing claims custody it does not have. The
//! stub-notice mechanism is the enforcement surface and is never removed.

use std::time::Duration;

use credentials_provider::CredentialsProvider;
use editor::Editor;
use gpui::{
    App, AsyncApp, AsyncWindowContext, Context, Entity, EventEmitter, FocusHandle, Focusable,
    FontWeight, IntoElement, ParentElement, PromptLevel, Render, SharedString, Styled, Task,
    WeakEntity, Window, actions, px,
};
use lnmarkets_client::{CREDENTIAL_STORAGE_URL, Network as LnMarketsNetwork, StoredCredentials};
use nautilus_sidecar::{
    ENABLE_ENVIRONMENT_VARIABLE as NAUTILUS_ENABLE_ENVIRONMENT_VARIABLE,
    NETWORK_ENVIRONMENT_VARIABLE as NAUTILUS_NETWORK_ENVIRONMENT_VARIABLE,
    Network as NautilusNetwork, credential_key as nautilus_credential_key,
};
use project::project_settings::ProjectSettings;
use settings::Settings as _;
use sovereign_wallet::{
    BalanceResult, DAILY_CEILING_SATS, IdentityStatusResult, InvoiceResult,
    SharedSovereignWalletSupervisor, SpendPolicySnapshot, StatusResult, SURFACE_WALLET_L402,
    SurfaceSpendSnapshot,
};
use trading_ledger::LedgerStore;
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

// WP-10 real machinery: the installed-extension registry (Plugins) and the
// NIP-46 remote-signer pairing state machine + relay coordinator (Link).
use omega_identity::{
    AccountRegistryService, Nip46ConnectionInput, Nip46InboundEvent, Nip46PairingFence,
    Nip46PairingState, Nip46PermissionPreview, Nip46Service, SignerKind,
};
use omega_signer_broker::Nip46RelayCoordinator;

actions!(
    sovereign_dashboard,
    [
        /// Toggles focus on the Sovereign Agents dashboard panel.
        ToggleFocus,
    ]
);

const PANEL_KEY: &str = "sovereign-dashboard";

/// WP-10: the Link ceremony's relay for the nostrconnect path (the same relay
/// the account_ui pairing ceremony uses — `wss://relay.openagents.com`).
const LINK_PAIRING_RELAY: &str = "wss://relay.openagents.com";
/// WP-10: first-wave NIP-46 pairing lifetime (7 days, account_ui precedent).
const LINK_FIRST_WAVE_LIFETIME_SECONDS: u64 = 60 * 60 * 24 * 7;
/// WP-10: per-step relay exchange timeout (account_ui `NIP46_EXCHANGE_TIMEOUT_SECONDS`).
const LINK_EXCHANGE_TIMEOUT_SECONDS: u64 = 30;

/// WP-7: the NIP-AC projection flag name (per the WP-11 flag plan, design
/// note §11). WP-12 implements the projection; until then this surface
/// displays the flag's absence honestly — it is a display of real flag
/// state, never a claim of a feature.
const NIPAC_PROJECTION_ENVIRONMENT_VARIABLE: &str = "OMEGA_NIPAC_PROJECTION";

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
    /// WP-10: the extension id for the real Add Plugin install flow.
    PluginId,
    /// WP-10: the `bunker://` NIP-46 URI from the remote machine's signer.
    LinkBunkerUri,
    /// WP-7: the per-surface daily ceiling input (sats) for the enforced
    /// `wallet-l402` surface (the spend-policy choke point surface).
    SpendCeilingSats,
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
            Self::PluginId => "input-plugin-id",
            Self::LinkBunkerUri => "input-link-bunker-uri",
            Self::SpendCeilingSats => "input-spend-ceiling-sats",
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

/// WP-10: the real Plugins view — the installed-extension registry
/// (`ExtensionStore::installed_extensions()`), the in-flight operations, and
/// the honest "registry unavailable" state when the extension host is not
/// registered (e.g. in tests). No fake rows: everything renders real state.
#[derive(Clone, Debug, Default)]
struct PluginsView {
    /// Real installed extensions: (id, display name, version, dev flag).
    installed: Vec<PluginRow>,
    /// Real in-flight operations: (id, label) from `outstanding_operations()`.
    operations: Vec<(String, String)>,
    /// Honest named state when the extension host is absent.
    unavailable: Option<SharedString>,
    /// A real install/remove message surfaced next to the control.
    message: Option<SharedString>,
    /// An install/remove error surfaced next to the control.
    error: Option<SharedString>,
}

/// WP-10: one real installed-extension row (mirrors `ExtensionIndexEntry`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct PluginRow {
    id: String,
    name: String,
    version: String,
    dev: bool,
}

/// WP-10: the real Link view — the NIP-46 remote-signer pairing ceremony and
/// the account-registry status. Every state is a real state-machine state.
#[derive(Clone, Debug, Default)]
struct LinkView {
    /// The account-registry projection (registered remote accounts, active
    /// selection) — the real status surface.
    status: Option<omega_identity::AccountDashboardProjection>,
    status_error: Option<SharedString>,
    /// The in-flight ceremony's real pairing state + capability ref.
    ceremony: Option<LinkCeremony>,
    /// The nostrconnect pairing URI to share with the other machine (shown
    /// once, copyable).
    pairing_uri: Option<SharedString>,
    /// The reported remote signer awaiting the operator's final approval.
    reported_signer: Option<LinkReportedSigner>,
    /// A message surfaced next to the section (real ceremony outcomes).
    message: Option<SharedString>,
    /// The connect envelope handed between ceremony steps (bunker path).
    connect_envelope: Option<omega_identity::Nip46RequestEnvelope>,
    /// The get-public-key envelope handed between ceremony steps.
    get_public_key_envelope: Option<omega_identity::Nip46RequestEnvelope>,
}

/// WP-10: the ceremony progress — the REAL `Nip46PairingState` from the
/// `omega_identity::nip46` state machine, persisted by `Nip46Service`.
#[derive(Clone, Debug)]
struct LinkCeremony {
    capability_ref: String,
    state: Nip46PairingState,
    registry_generation: u64,
}

/// WP-10: the remote signer the ceremony reported, awaiting the operator's
/// final approval (the `AwaitingFinalApproval` step).
#[derive(Clone, Debug)]
struct LinkReportedSigner {
    capability_ref: String,
    remote_signer_public_key: String,
    user_public_key: String,
    registry_generation: u64,
    relays: Vec<String>,
    expires_at: u64,
}

/// WP-7: the credential-slot presence state — a REAL read of the platform
/// credential stores (presence only; never secret material). `Unreadable`
/// carries the honest reason a presence check could not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
enum CredentialSlotState {
    Present,
    Absent,
    Unreadable(String),
}

/// WP-7: the operator view for the mainnet transition — the spend-policy
/// snapshot (kill + budgets) and the per-network credential-slot presence.
/// Every rendered value is real state (the policy store, the platform
/// credential stores, the process env); nothing self-enables and no
/// authority is claimed without backing (C7 honesty law).
#[derive(Clone, Debug, Default)]
struct OperatorView {
    /// The read-only spend-policy projection (kill sources + per-surface
    /// counters + ceilings). `None` while the wallet lane is off — the
    /// policy store exists only with the supervisor.
    spend: Option<SpendPolicySnapshot>,
    /// A real outcome of the last operator control (set/clear/ceiling).
    control_message: Option<SharedString>,
    /// A real refusal of the last operator control (the honest message the
    /// policy produced — env kill / loss-rule C3 route / invalid input).
    control_error: Option<SharedString>,
    /// Hyperliquid mainnet agent-wallet slot presence.
    nautilus_mainnet_wallet: Option<CredentialSlotState>,
    /// LN Markets mainnet Trade-key slot presence (the stored record's
    /// network field — the single stored LN Markets record carries it).
    lnmarkets_mainnet_key: Option<CredentialSlotState>,
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
    /// WP-10: the real Plugins view (installed-extension registry).
    plugins: PluginsView,
    /// WP-10: the real Link view (NIP-46 pairing ceremony + registry status).
    link: LinkView,
    /// WP-5b: the persisted escrow sessions (HTLC 2-of-3 limbo, digest-only
    /// state) loaded from the escrow store on refresh.
    escrow_sessions: Vec<market_ui::EscrowSession>,
    /// WP-5b: the observed signet tip for the timeout countdown (fail-closed
    /// when the probe is unavailable — never wall-clock).
    escrow_height: Option<u32>,
    /// WP-5b: an escrow action error surfaced next to the section.
    escrow_error: Option<SharedString>,
    /// WP-5b: the ledger of record for escrow entries (same store the
    /// trading surfaces use — no second ledger).
    ledger_store: Option<LedgerStore>,
    /// WP-7: the mainnet-transition operator view (spend policy + credential
    /// slots) — real state only.
    operator: OperatorView,
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
            plugins: PluginsView::default(),
            link: LinkView::default(),
            escrow_sessions: Vec::new(),
            escrow_height: None,
            escrow_error: None,
            ledger_store: LedgerStore::open_default()
                .map_err(|error| log::error!("sovereign dashboard: {error:#}"))
                .ok(),
            operator: OperatorView::default(),
        };
        panel.refresh(cx);
        panel
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
            // WP-7: the credential-slot reads do not need the wallet lane —
            // run them so the operator surface renders real state even with
            // the lane off. The spend policy has no state without the
            // supervisor (the honest `None` is rendered as "lane off").
            let zed_provider = zed_credentials_provider::global(cx);
            let agent_wallet_provider = zed_credentials_provider::agent_wallet_credentials(cx);
            self.refresh_task = Some(cx.spawn(async move |this, cx| {
                let nautilus_mainnet_wallet =
                    read_nautilus_mainnet_wallet_presence(&agent_wallet_provider, cx).await;
                let lnmarkets_mainnet_key =
                    read_lnmarkets_mainnet_key_slot(&zed_provider, cx).await;
                this.update(cx, |this, cx| {
                    this.operator.nautilus_mainnet_wallet = Some(nautilus_mainnet_wallet);
                    this.operator.lnmarkets_mainnet_key = Some(lnmarkets_mainnet_key);
                    this.operator.spend = None;
                    cx.notify();
                })
                .log_err();
            }));
            return;
        };
        let store = self.mandate_store.clone();
        // WP-7: the credential stores for the per-network slot presence reads
        // (the global provider holds the LN Markets credentials; the platform
        // agent-wallet store holds the Nautilus agent wallets).
        let zed_provider = zed_credentials_provider::global(cx);
        let agent_wallet_provider = zed_credentials_provider::agent_wallet_credentials(cx);
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
            // WP-5b: the observed signet tip for the escrow timeout countdown.
            // Fail-closed: when the probe fails the countdown shows the
            // unavailable state and never substitutes wall-clock.
            let escrow_height = if status.is_some() {
                guard.wallet_height().await.ok().map(|result| result.block_height)
            } else {
                None
            };
            // WP-7: the REAL spend-policy state (kill + budgets) — read
            // directly from the supervisor's policy store; the projection
            // normalizes stale-day counters to zero spent.
            let spend_snapshot = guard.spend_policy_snapshot(unix_now_seconds() as i64);
            // WP-7: the per-network credential-slot presence (REAL reads of
            // the platform credential stores; presence only — the Nautilus
            // record is never decoded on this surface, and the LN Markets
            // record is opened only for its public `network` field).
            let nautilus_mainnet_wallet =
                read_nautilus_mainnet_wallet_presence(&agent_wallet_provider, cx).await;
            let lnmarkets_mainnet_key =
                read_lnmarkets_mainnet_key_slot(&zed_provider, cx).await;
            this.update(cx, |this, cx| {
                this.wallet.status = status;
                this.wallet.balance = balance;
                this.wallet.balance_error = balance_error;
                this.identity.status = identity_status;
                this.identity.identity_error = identity_error;
                this.mcp_identity_map = mcp_identity_map;
                this.escrow_height = escrow_height;
                this.operator.spend = Some(spend_snapshot);
                this.operator.nautilus_mainnet_wallet = Some(nautilus_mainnet_wallet);
                this.operator.lnmarkets_mainnet_key = Some(lnmarkets_mainnet_key);
                // WP-5b: reload the persisted escrow sessions (digest-only).
                this.escrow_sessions = load_escrow_sessions();
                if let Some(snapshot) = snapshot {
                    this.mandates.snapshot = Some(snapshot);
                }
                if let Some(error) = store_error {
                    this.mandates.store_error = Some(SharedString::from(error));
                }
                // WP-10: the REAL Plugins view — the installed-extension
                // registry (the extension host's installed set) plus the
                // in-flight operations. `try_global` is used so the dashboard
                // renders an honest "registry unavailable" state in builds or
                // tests where the extension host is not registered.
                this.plugins = plugins_view(cx);
                // WP-10: the REAL Link status — the account registry's
                // registered accounts (remote NIP-46 signers, lifecycle,
                // availability, last use) and the active selection.
                match AccountRegistryService::system(*app_identity::CHANNEL).inspect() {
                    Ok(projection) => {
                        this.link.status = Some(projection);
                        this.link.status_error = None;
                    }
                    Err(error) => {
                        this.link.status_error =
                            Some(SharedString::from(format!("account registry unavailable: {error}")));
                    }
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
        // WP-7: the network wording follows the REAL configured network (the
        // 0286 grammar makes mainnet a real configured state) — never a
        // hardcoded claim.
        let network = self
            .wallet
            .status
            .as_ref()
            .map(|status| status.network.clone())
            .unwrap_or_else(|| "signet".to_string());
        self.pending_input = Some(PendingInput {
            request: InputRequest::FundAmount,
            label: "Amount (sats)".into(),
            detail: format!(
                "Mint a real {network} receive invoice for this amount. {}",
                wallet_network_note(&network)
            )
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
    // Plugins (WP-10: REAL — the installed-extension registry)
    // -----------------------------------------------------------------------

    fn add_plugin_flow(&mut self, cx: &mut Context<Self>) {
        self.pending_input = Some(PendingInput {
            request: InputRequest::PluginId,
            label: "Extension id".into(),
            detail: "Install from the REAL extension registry (ExtensionStore::install_latest_extension — \
                     the same flow the extension host uses). Enter the extension id, e.g. \"om\". \
                     The registry must be reachable for the download."
                .into(),
        });
        cx.notify();
    }

    fn install_plugin(&mut self, extension_id: String, cx: &mut Context<Self>) {
        let Some(store) = extension_host::ExtensionStore::try_global(cx) else {
            self.plugins.error = Some(
                "the extension host is not registered in this build; install is unavailable".into(),
            );
            cx.notify();
            return;
        };
        let extension_id: std::sync::Arc<str> = extension_id.trim().into();
        if extension_id.is_empty() {
            self.plugins.error = Some("the extension id must not be empty".into());
            cx.notify();
            return;
        }
        self.plugins.error = None;
        // The REAL install flow (downloads from the extension registry, reloads,
        // emits ExtensionInstalled). In-flight state renders from
        // `outstanding_operations()` on the next refresh. `install_latest_extension`
        // returns () — it spawns and detaches its own task.
        store.update(cx, |store, cx| store.install_latest_extension(extension_id.clone(), cx));
        self.plugins.message = Some(SharedString::from(format!(
            "installing {extension_id} from the extension registry (real flow)…"
        )));
        self.refresh(cx);
        cx.notify();
    }

    fn remove_plugin(&mut self, extension_id: String, cx: &mut Context<Self>) {
        let Some(store) = extension_host::ExtensionStore::try_global(cx) else {
            self.plugins.error = Some(
                "the extension host is not registered in this build; removal is unavailable".into(),
            );
            cx.notify();
            return;
        };
        let extension_id: std::sync::Arc<str> = extension_id.into();
        self.plugins.error = None;
        // The REAL uninstall flow (removes the installed dir, reloads the
        // index, emits ExtensionUninstalled — the same call the settings UI
        // uses for extension-provided MCP servers).
        store
            .update(cx, |store, cx| store.uninstall_extension(extension_id, cx))
            .detach_and_log_err(cx);
        self.refresh(cx);
        cx.notify();
    }

    // -----------------------------------------------------------------------
    // Link (WP-10: REAL — NIP-46 remote-signer pairing, design §4.6 seam +
    // omega_signer_broker SignerRoute::RemoteNip46)
    // -----------------------------------------------------------------------

    /// Start a link ceremony from a `bunker://` URI pasted from the signer on
    /// the other machine. Real state-machine states are persisted by
    /// `Nip46Service` and rendered at each step.
    fn link_bunker_flow(&mut self, cx: &mut Context<Self>) {
        if self.link.ceremony.is_some() || self.link.reported_signer.is_some() {
            self.link.message =
                Some("a pairing ceremony is already in progress; finish or cancel it first".into());
            cx.notify();
            return;
        }
        self.pending_input = Some(PendingInput {
            request: InputRequest::LinkBunkerUri,
            label: "bunker:// URI".into(),
            detail: "Paste the NIP-46 bunker URI from the signer on the other machine \
                     (bunker://<pubkey>?relay=<wss…>&secret=…). This starts a REAL \
                     remote-signer pairing (NIP-46, omega_identity::nip46)."
                .into(),
        });
        cx.notify();
    }

    /// Start the nostrconnect path: create a REAL pairing link to open on the
    /// other machine's signer app, then wait for its acknowledgement over the
    /// relay (the `create_nostrconnect_pairing` flow).
    fn create_link_pairing(&mut self, cx: &mut Context<Self>) {
        if self.link.ceremony.is_some() || self.link.reported_signer.is_some() {
            self.link.message =
                Some("a pairing ceremony is already in progress; finish or cancel it first".into());
            cx.notify();
            return;
        }
        let service = Nip46Service::system(*app_identity::CHANNEL);
        let generation = match link_registry_generation() {
            Ok(generation) => generation,
            Err(error) => {
                self.link.message = Some(SharedString::from(error));
                cx.notify();
                return;
            }
        };
        let now = unix_now_seconds();
        let preview = match Nip46PermissionPreview::omega_first_profile(
            None,
            vec![LINK_PAIRING_RELAY.to_string()],
            now,
            now.saturating_add(LINK_FIRST_WAVE_LIFETIME_SECONDS),
        ) {
            Ok(preview) => preview,
            Err(error) => {
                self.link.message = Some(SharedString::from(format!("pairing preview failed: {error}")));
                cx.notify();
                return;
            }
        };
        let fence = match Nip46PairingFence::new(generation) {
            Ok(fence) => fence,
            Err(error) => {
                self.link.message = Some(SharedString::from(format!("registry fence failed: {error}")));
                cx.notify();
                return;
            }
        };
        match service.create_nostrconnect_pairing(preview, fence, "Omega") {
            Ok((session, uri)) => {
                let capability_ref = session.capability_ref().to_string();
                // Persisted state: AwaitingAcknowledgement (the URI carries the
                // pairing secret the remote signer must echo back).
                self.link.ceremony = Some(LinkCeremony {
                    capability_ref,
                    state: session.state(),
                    registry_generation: generation,
                });
                self.link.pairing_uri = Some(SharedString::from(uri.expose().to_string()));
                self.link.message = Some(
                    "pairing link created — open it on the other machine's signer, then wait for \
                     its acknowledgement"
                        .into(),
                );
                self.drive_link_nostrconnect_acknowledgement(cx);
            }
            Err(error) => {
                self.link.message =
                    Some(SharedString::from(format!("pairing link creation failed: {error}")));
            }
        }
        cx.notify();
    }

    /// Begin the bunker ceremony: parse the URI, build the first-wave preview
    /// and the registry fence, and start the persisted pairing session.
    fn begin_link_bunker_ceremony(&mut self, uri: String, cx: &mut Context<Self>) {
        let input = match Nip46ConnectionInput::parse(uri.trim()) {
            Ok(input) => input,
            Err(error) => {
                self.link.message = Some(SharedString::from(format!("invalid bunker URI: {error}")));
                cx.notify();
                return;
            }
        };
        let generation = match link_registry_generation() {
            Ok(generation) => generation,
            Err(error) => {
                self.link.message = Some(SharedString::from(error));
                cx.notify();
                return;
            }
        };
        let now = unix_now_seconds();
        let preview = match Nip46PermissionPreview::omega_first_profile(
            Some(input.public_key().clone()),
            input.relays().to_vec(),
            now,
            now.saturating_add(LINK_FIRST_WAVE_LIFETIME_SECONDS),
        ) {
            Ok(preview) => preview,
            Err(error) => {
                self.link.message = Some(SharedString::from(format!("pairing preview failed: {error}")));
                cx.notify();
                return;
            }
        };
        let fence = match Nip46PairingFence::new(generation) {
            Ok(fence) => fence,
            Err(error) => {
                self.link.message = Some(SharedString::from(format!("registry fence failed: {error}")));
                cx.notify();
                return;
            }
        };
        let service = Nip46Service::system(*app_identity::CHANNEL);
        match service.begin_bunker_pairing(input, preview, fence) {
            Ok(session) => {
                let capability_ref = session.capability_ref().to_string();
                // Persisted state: AwaitingApproval.
                self.link.ceremony = Some(LinkCeremony {
                    capability_ref,
                    state: session.state(),
                    registry_generation: generation,
                });
                self.link.message =
                    Some("pairing started — awaiting the remote signer's approval".into());
                self.drive_link_approval(cx);
            }
            Err(error) => {
                self.link.message =
                    Some(SharedString::from(format!("pairing could not start: {error}")));
            }
        }
        cx.notify();
    }

    /// Step 1 (bunker): resume the persisted session, `approve()`, and render
    /// the persisted `AwaitingAcknowledgement` state. The connect envelope is
    /// handed to the acknowledgement exchange.
    fn drive_link_approval(&mut self, cx: &mut Context<Self>) {
        let Some(ceremony) = self.link.ceremony.clone() else {
            return;
        };
        let service = Nip46Service::system(*app_identity::CHANNEL);
        self.link.message = Some("awaiting the remote signer's acknowledgement…".into());
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let mut session = service
                        .resume(&ceremony.capability_ref)
                        .map_err(|error| error.to_string())?;
                    let connect = session
                        .approve(unix_now_seconds(), LINK_EXCHANGE_TIMEOUT_SECONDS)
                        .map_err(|error| error.to_string())?;
                    Ok::<_, String>((session.state(), connect))
                })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok((state, connect)) => {
                        if let Some(ceremony) = this.link.ceremony.as_mut() {
                            ceremony.state = state;
                        }
                        this.link.connect_envelope = Some(connect);
                        this.drive_link_acknowledgement(cx);
                    }
                    Err(error) => {
                        this.link.ceremony = None;
                        this.link.message =
                            Some(SharedString::from(format!("pairing approval failed: {error}")));
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    /// Step 2 (bunker): exchange the connect request over the relay and wait
    /// for the signer's acknowledgement (the `AwaitingAcknowledgement` state).
    fn drive_link_acknowledgement(&mut self, cx: &mut Context<Self>) {
        let Some(ceremony) = self.link.ceremony.clone() else {
            return;
        };
        let Some(connect) = self.link.connect_envelope.take() else {
            return;
        };
        let service = Nip46Service::system(*app_identity::CHANNEL);
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let mut session = service
                        .resume(&ceremony.capability_ref)
                        .map_err(|error| error.to_string())?;
                    let expected_signer = session.remote_signer_public_key().cloned();
                    let client_public_key = session.client_public_key().clone();
                    let coordinator = Nip46RelayCoordinator::default();
                    let get_public_key = coordinator
                        .exchange(
                            &connect,
                            expected_signer.as_ref(),
                            &client_public_key,
                            |relay_url, event_json, received_at| {
                                session
                                    .receive_acknowledgement(
                                        ceremony.registry_generation,
                                        Nip46InboundEvent {
                                            relay_url,
                                            event_json,
                                            received_at,
                                        },
                                        LINK_EXCHANGE_TIMEOUT_SECONDS,
                                    )
                                    .map(Some)
                            },
                        )
                        .await
                        .map_err(|error| link_relay_error_message(&error))?;
                    Ok::<_, String>((session.state(), get_public_key))
                })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok((state, get_public_key)) => {
                        if let Some(ceremony) = this.link.ceremony.as_mut() {
                            ceremony.state = state;
                        }
                        this.link.get_public_key_envelope = Some(get_public_key);
                        this.drive_link_user_public_key(cx);
                    }
                    Err(error) => {
                        this.link.ceremony = None;
                        this.link.message = Some(SharedString::from(error));
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    /// Step 1' (nostrconnect): listen on the relay for the remote signer's
    /// acknowledgement of the pairing link (no publication — the signer
    /// initiates), then request its public key.
    fn drive_link_nostrconnect_acknowledgement(&mut self, cx: &mut Context<Self>) {
        let Some(ceremony) = self.link.ceremony.clone() else {
            return;
        };
        let service = Nip46Service::system(*app_identity::CHANNEL);
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let mut session = service
                        .resume(&ceremony.capability_ref)
                        .map_err(|error| error.to_string())?;
                    let client_public_key = session.client_public_key().clone();
                    let relay_urls = session.preview().relays.clone();
                    let coordinator = Nip46RelayCoordinator::default();
                    let get_public_key = coordinator
                        .listen(
                            &relay_urls,
                            &ceremony.capability_ref,
                            None,
                            &client_public_key,
                            |relay_url, event_json, received_at| {
                                session
                                    .receive_nostrconnect_acknowledgement(
                                        ceremony.registry_generation,
                                        Nip46InboundEvent {
                                            relay_url,
                                            event_json,
                                            received_at,
                                        },
                                        LINK_EXCHANGE_TIMEOUT_SECONDS,
                                    )
                                    .map(Some)
                            },
                        )
                        .await
                        .map_err(|error| link_relay_error_message(&error))?;
                    Ok::<_, String>((session.state(), get_public_key))
                })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok((state, get_public_key)) => {
                        if let Some(ceremony) = this.link.ceremony.as_mut() {
                            ceremony.state = state;
                        }
                        this.link.get_public_key_envelope = Some(get_public_key);
                        this.drive_link_user_public_key(cx);
                    }
                    Err(error) => {
                        this.link.ceremony = None;
                        this.link.pairing_uri = None;
                        this.link.message = Some(SharedString::from(error));
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    /// Step 3 (both paths): exchange the get-public-key request; the reported
    /// signer lands in `AwaitingFinalApproval` for the operator's explicit
    /// approval.
    fn drive_link_user_public_key(&mut self, cx: &mut Context<Self>) {
        let Some(ceremony) = self.link.ceremony.clone() else {
            return;
        };
        let Some(get_public_key) = self.link.get_public_key_envelope.take() else {
            return;
        };
        let capability_ref = ceremony.capability_ref.clone();
        let registry_generation = ceremony.registry_generation;
        let capability_ref_for_ui = capability_ref.clone();
        let service = Nip46Service::system(*app_identity::CHANNEL);
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let mut session = service
                        .resume(&capability_ref)
                        .map_err(|error| error.to_string())?;
                    let expected_signer = session.remote_signer_public_key().cloned();
                    let client_public_key = session.client_public_key().clone();
                    let coordinator = Nip46RelayCoordinator::default();
                    let reported = coordinator
                        .exchange(
                            &get_public_key,
                            expected_signer.as_ref(),
                            &client_public_key,
                            |relay_url, event_json, received_at| {
                                session
                                    .receive_user_public_key(
                                        registry_generation,
                                        Nip46InboundEvent {
                                            relay_url,
                                            event_json,
                                            received_at,
                                        },
                                        LINK_EXCHANGE_TIMEOUT_SECONDS,
                                    )
                                    .map(Some)
                            },
                        )
                        .await
                        .map_err(|error| link_relay_error_message(&error))?;
                    Ok::<_, String>((session.state(), reported))
                })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok((state, reported)) => {
                        if let Some(ceremony) = this.link.ceremony.as_mut() {
                            ceremony.state = state;
                        }
                        let user_public_key = reported.user_identity.public_key_hex().as_str().to_string();
                        let remote_signer_public_key =
                            reported.remote_signer_public_key.as_str().to_string();
                        this.link.reported_signer = Some(LinkReportedSigner {
                            capability_ref: capability_ref_for_ui.clone(),
                            remote_signer_public_key,
                            user_public_key,
                            registry_generation,
                            relays: reported.preview.relays.clone(),
                            expires_at: reported.preview.expires_at,
                        });
                        this.link.pairing_uri = None;
                        this.link.message = Some(
                            "the remote signer reported its identity — review and approve to \
                             complete the link"
                                .into(),
                        );
                    }
                    Err(error) => {
                        this.link.ceremony = None;
                        this.link.message = Some(SharedString::from(error));
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    /// The operator's final approval: `approve_reported_signer`, the
    /// signed-challenge exchange (`AwaitingSignedChallenge` →
    /// `AwaitingRegistration`), then the real registry registration
    /// (`register_remote_account` → Active).
    fn approve_reported_link_signer(&mut self, cx: &mut Context<Self>) {
        let Some(approval) = self.link.reported_signer.clone() else {
            return;
        };
        let service = Nip46Service::system(*app_identity::CHANNEL);
        let registry = AccountRegistryService::system(*app_identity::CHANNEL);
        self.link.reported_signer = None;
        self.link.message = Some("finalizing the link: signed-challenge proof + registration…".into());
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let mut session = service
                        .resume(&approval.capability_ref)
                        .map_err(|error| error.to_string())?;
                    let challenge = session
                        .approve_reported_signer(unix_now_seconds(), LINK_EXCHANGE_TIMEOUT_SECONDS)
                        .map_err(|error| error.to_string())?;
                    let expected_signer = session.remote_signer_public_key().cloned();
                    let client_public_key = session.client_public_key().clone();
                    Nip46RelayCoordinator::default()
                        .exchange(
                            &challenge,
                            expected_signer.as_ref(),
                            &client_public_key,
                            |relay_url, event_json, received_at| {
                                session
                                    .receive_signed_challenge(
                                        approval.registry_generation,
                                        Nip46InboundEvent {
                                            relay_url,
                                            event_json,
                                            received_at,
                                        },
                                    )
                                    .map(Some)
                            },
                        )
                        .await
                        .map_err(|error| link_relay_error_message(&error))?;
                    // The terminal registration: the capability is in
                    // `AwaitingRegistration`; this binds the remote account as
                    // the ACTIVE account (SignerKind::RemoteNip46).
                    registry
                        .register_remote_account(
                            &approval.capability_ref,
                            approval.registry_generation,
                        )
                        .map_err(|error| error.to_string())?;
                    Ok::<_, String>(())
                })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(()) => {
                        this.link.ceremony = None;
                        this.link.message =
                            Some("remote signer linked and active (NIP-46 pairing complete)".into());
                        this.refresh(cx);
                    }
                    Err(error) => {
                        this.link.ceremony = None;
                        this.link.message =
                            Some(SharedString::from(format!("link finalization failed: {error}")));
                    }
                }
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    /// Reject the reported signer (deletes the pairing key material, state →
    /// Rejected) or cancel an in-flight ceremony.
    fn reject_link_ceremony(&mut self, cx: &mut Context<Self>) {
        let capability_ref = self
            .link
            .reported_signer
            .as_ref()
            .map(|approval| approval.capability_ref.clone())
            .or_else(|| self.link.ceremony.as_ref().map(|ceremony| ceremony.capability_ref.clone()));
        self.link.ceremony = None;
        self.link.reported_signer = None;
        self.link.pairing_uri = None;
        self.link.connect_envelope = None;
        self.link.get_public_key_envelope = None;
        if let Some(capability_ref) = capability_ref {
            let service = Nip46Service::system(*app_identity::CHANNEL);
            match service
                .resume(&capability_ref)
                .and_then(|mut session| session.reject())
            {
                Ok(()) => {
                    self.link.message = Some("remote signer connection rejected.".into());
                }
                Err(error) => {
                    self.link.message = Some(SharedString::from(format!(
                        "the connection could not be rejected cleanly: {error}"
                    )));
                }
            }
        }
        cx.notify();
    }

    /// Disconnect a linked remote signer: the REAL registry revoke + SignedOut
    /// (`AccountRegistryService::disconnect_remote_signer`).
    fn disconnect_link(
        &mut self,
        account_ref: String,
        expected_generation: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let answer = window.prompt(
            PromptLevel::Warning,
            "Disconnect this remote signer?",
            Some("Revokes the NIP-46 capability and marks the account signed out in the identity registry (real revocation)."),
            &["Disconnect", "Cancel"],
            cx,
        );
        let parsed = omega_identity::AccountRef::new(account_ref);
        let registry = AccountRegistryService::system(*app_identity::CHANNEL);
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            if answer.await != Ok(0) {
                return;
            }
            let result = match &parsed {
                Ok(account_ref) => registry
                    .disconnect_remote_signer(account_ref, expected_generation)
                    .map_err(|error| error.to_string()),
                Err(error) => Err(format!("invalid account ref: {error}")),
            };
            this.update(cx, |this, cx| {
                match result {
                    Ok(_projection) => {
                        this.link.message = Some("remote signer disconnected (revoked).".into());
                        this.refresh(cx);
                    }
                    Err(error) => {
                        this.link.message =
                            Some(SharedString::from(format!("disconnect failed: {error}")));
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
        // OMEGA-DELTA-0286: the mandate builder is network-aware; the
        // dashboard's New Authorization flow keeps creating signet mandates
        // (unchanged behavior — the network-aware operator surface is WP-7's
        // scope; mainnet mandates are constructed by the escrow/L-402 lanes).
        let candidate = sovereign_wallet::sovereign_wallet_mandate_candidate(
            TradingNetwork::Signet,
            &pubkey_hex,
            amount_sat,
            expiry_ms,
        );
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
            InputRequest::PluginId => {
                // WP-10: real Add Plugin — install from the extension registry.
                self.install_plugin(value, cx);
            }
            InputRequest::LinkBunkerUri => {
                // WP-10: real Link — begin the NIP-46 bunker pairing ceremony.
                self.begin_link_bunker_ceremony(value, cx);
            }
            InputRequest::SpendCeilingSats => {
                // WP-7: apply the operator ceiling for the enforced surface.
                let Ok(ceiling_sats) = value.trim().parse::<u64>() else {
                    self.operator.control_error =
                        Some("the ceiling must be a positive integer (sats)".into());
                    cx.notify();
                    return;
                };
                let Some(supervisor) = self.supervisor.clone() else {
                    self.stub_notice = Some("Spend controls unavailable — the sovereign wallet lane is off (OMEGA_SOVEREIGN_WALLET=1 not set).");
                    cx.notify();
                    return;
                };
                let task = cx.spawn(async move |this, cx| {
                    let mut guard = supervisor.lock().await;
                    let result = guard.set_surface_ceiling(SURFACE_WALLET_L402, ceiling_sats);
                    this.update(cx, |this, cx| {
                        match result {
                            Ok(()) => {
                                this.operator.control_error = None;
                                this.operator.control_message = Some(SharedString::from(
                                    format!(
                                        "daily ceiling for {SURFACE_WALLET_L402} set to \
                                         {ceiling_sats} sats (override; event logged)"
                                    ),
                                ));
                                this.refresh(cx);
                            }
                            Err(error) => {
                                this.operator.control_error =
                                    Some(SharedString::from(format!("set refused: {error:#}")));
                            }
                        }
                        cx.notify();
                    })
                    .log_err();
                });
                self.refresh_task = Some(task);
                cx.notify();
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

        let link = self.link_section(cx);

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

    /// WP-10: the REAL Link section — the NIP-46 remote-signer pairing
    /// ceremony (omega_identity::nip46 + omega_signer_broker relay
    /// coordinator; the `SignerRoute::RemoteNip46` machinery) plus the real
    /// account-registry status. Every rendered state is a real state-machine
    /// state; the pairing state persists through `Nip46Service`.
    fn link_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let ceremony = self.link.ceremony.as_ref().map(|ceremony| {
            let state_label = pairing_state_label(&ceremony.state);
            v_flex()
                .w_full()
                .gap_1()
                .p_2()
                .rounded_md()
                .border_1()
                .border_color(cx.theme().colors().border)
                .child(
                    Label::new(format!("Pairing in progress — {state_label}"))
                        .size(LabelSize::Small)
                        .color(Color::Warning),
                )
                .child(
                    Label::new(
                        "the ceremony runs the REAL NIP-46 state machine; pairing state is \
                         persisted on disk (Nip46Service)",
                    )
                    .size(LabelSize::XSmall)
                    .color(Color::Muted),
                )
                .child(
                    Button::new("sw-link-cancel", "Cancel pairing")
                        .style(ButtonStyle::Subtle)
                        .on_click(cx.listener(|this, _, _, cx| this.reject_link_ceremony(cx))),
                )
                .into_any_element()
        });

        let pairing_uri = self.link.pairing_uri.as_ref().map(|uri| {
            let uri_shared = uri.clone();
            v_flex()
                .w_full()
                .gap_1()
                .child(
                    Label::new("Open this pairing link on the other machine's signer:")
                        .size(LabelSize::XSmall)
                        .color(Color::Warning),
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
                                .child(Label::new(uri.clone()).size(LabelSize::XSmall)),
                        )
                        .child(CopyButton::new("sw-link-uri-copy", uri_shared).icon_size(IconSize::XSmall)),
                )
                .into_any_element()
        });

        let reported = self.link.reported_signer.as_ref().map(|reported| {
            let remote_short = short_pubkey(&reported.remote_signer_public_key);
            let user_short = short_pubkey(&reported.user_public_key);
            let relays = reported.relays.join(", ");
            let expiry = reported.expires_at;
            v_flex()
                .w_full()
                .gap_1()
                .p_2()
                .rounded_md()
                .border_1()
                .border_color(cx.theme().colors().border_variant)
                .child(
                    Label::new("Remote signer reported its identity — approve to complete the link:")
                        .size(LabelSize::Small)
                        .color(Color::Warning),
                )
                .child(
                    Label::new(format!("remote signer: {remote_short}"))
                        .size(LabelSize::XSmall)
                        .color(Color::Muted),
                )
                .child(
                    Label::new(format!("user identity: {user_short}"))
                        .size(LabelSize::XSmall)
                        .color(Color::Muted),
                )
                .child(
                    Label::new(format!("relays: {relays} · expires: {expiry}"))
                        .size(LabelSize::XSmall)
                        .color(Color::Muted),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new("sw-link-approve", "Approve")
                                .style(ButtonStyle::Filled)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.approve_reported_link_signer(cx);
                                })),
                        )
                        .child(
                            Button::new("sw-link-reject", "Reject")
                                .style(ButtonStyle::Subtle)
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.reject_link_ceremony(cx);
                                })),
                        ),
                )
                .into_any_element()
        });

        // The real status: registered remote accounts from the identity
        // registry (SignerKind::RemoteNip46), with lifecycle/availability and
        // a real Disconnect (revocation).
        let status_rows: Vec<AnyElement> = self
            .link
            .status
            .as_ref()
            .map(|projection| link_status_rows(projection))
            .unwrap_or_default()
            .into_iter()
            .map(|row| {
                let account_ref = row.account_ref.clone();
                let generation = row.generation;
                let remove_id = SharedString::from(format!("sw-link-disconnect-{account_ref}"));
                h_flex()
                    .id(remove_id.clone())
                    .w_full()
                    .justify_between()
                    .items_center()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .hover(|style| style.bg(cx.theme().colors().element_hover))
                    .child(
                        v_flex()
                            .child(Label::new(row.title).size(LabelSize::Small))
                            .child(
                                Label::new(row.detail)
                                    .size(LabelSize::Small)
                                    .color(Color::Muted),
                            ),
                    )
                    .child(
                        Button::new(remove_id, "Disconnect")
                            .style(ButtonStyle::Subtle)
                            .tooltip(ui::Tooltip::text(
                                "Revoke the NIP-46 capability and sign the account out (real)",
                            ))
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.disconnect_link(account_ref.clone(), generation, window, cx);
                            })),
                    )
                    .into_any_element()
            })
            .collect();

        let status_body = if let Some(error) = &self.link.status_error {
            v_flex()
                .child(
                    Label::new("Link status unavailable")
                        .size(LabelSize::Small)
                        .color(Color::Error),
                )
                .child(Label::new(error.clone()).size(LabelSize::Small).color(Color::Muted))
        } else if status_rows.is_empty() {
            v_flex().child(
                Label::new("No remote signer linked")
                    .size(LabelSize::Small)
                    .color(Color::Muted),
            )
        } else {
            v_flex().w_full().gap_2().children(status_rows)
        };

        v_flex()
            .w_full()
            .gap_2()
            .child(
                Label::new(
                    "Cross-machine link = NIP-46 remote-signer pairing (real; the signer on \
                     another machine holds the identity).",
                )
                .size(LabelSize::XSmall)
                .color(Color::Muted),
            )
            .children(ceremony)
            .children(pairing_uri)
            .children(reported)
            .child(status_body)
            .children(self.link.message.clone().map(|message| {
                Label::new(message)
                    .size(LabelSize::XSmall)
                    .color(Color::Muted)
                    .into_any_element()
            }))
            .child(
                h_flex()
                    .w_full()
                    .gap_2()
                    .child(
                        Button::new("link-nostr-id", "Link via bunker URI")
                            .style(ButtonStyle::Subtle)
                            .tooltip(ui::Tooltip::text(
                                "Start a REAL NIP-46 pairing from a bunker URI (remote signer on another machine)",
                            ))
                            .on_click(cx.listener(|this, _, _, cx| this.link_bunker_flow(cx))),
                    )
                    .child(
                        Button::new("link-nostrconnect", "Create pairing link")
                            .style(ButtonStyle::Subtle)
                            .tooltip(ui::Tooltip::text(
                                "Create a REAL nostrconnect pairing URI to open on the other machine",
                            ))
                            .on_click(cx.listener(|this, _, _, cx| this.create_link_pairing(cx))),
                    ),
            )
            .into_any_element()
    }

    /// WP-10: the REAL Plugins section — the installed-extension registry.
    /// Rows render real installed extensions (id/name/version/dev); Remove
    /// performs the real `uninstall_extension`; Add Plugin performs the real
    /// `install_latest_extension` flow; in-flight operations render from
    /// `outstanding_operations()`. The copy labels the mapping honestly: the
    /// extension host's installed set IS the plugin registry in this codebase.
    fn plugins_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let registry_note = Label::new(
            "real state — the extension host's installed set (the plugin registry in this build)",
        )
        .size(LabelSize::XSmall)
        .color(Color::Muted);

        let rows: Vec<AnyElement> = self
            .plugins
            .installed
            .iter()
            .map(|plugin| {
                let id = SharedString::from(format!("plugin-{}", plugin.id));
                let name = plugin.name.clone();
                let version = plugin.version.clone();
                let dev = plugin.dev;
                let secondary = if dev {
                    format!("v{version} · dev")
                } else {
                    format!("v{version}")
                };
                let remove_id = SharedString::from(format!("{id}-remove"));
                let plugin_id_for_remove = plugin.id.clone();
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
                            .child(Label::new(name).size(LabelSize::Small))
                            .child(
                                Label::new(secondary)
                                    .size(LabelSize::Small)
                                    .color(Color::Muted),
                            ),
                    )
                    .child(
                        IconButton::new(remove_id, IconName::Close)
                            .icon_size(IconSize::Small)
                            .style(ButtonStyle::Subtle)
                            .aria_label(format!(
                                "Remove {plugin_id_for_remove} (real extension uninstall)"
                            ))
                            .tooltip(ui::Tooltip::text(
                                "Remove (real extension uninstall through the extension host)",
                            ))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.remove_plugin(plugin_id_for_remove.clone(), cx);
                            })),
                    )
                    .into_any_element()
            })
            .collect();

        // Real in-flight operations from the extension store.
        let operations: Vec<AnyElement> = self
            .plugins
            .operations
            .iter()
            .map(|(id, label)| {
                h_flex()
                    .id(SharedString::from(format!("plugin-op-{id}")))
                    .w_full()
                    .justify_between()
                    .items_center()
                    .px_2()
                    .py_1()
                    .rounded_sm()
                    .child(
                        v_flex()
                            .child(Label::new(id.clone()).size(LabelSize::Small))
                            .child(
                                Label::new(label.clone())
                                    .size(LabelSize::Small)
                                    .color(Color::Muted),
                            ),
                    )
                    .into_any_element()
            })
            .collect();

        let body = if let Some(unavailable) = &self.plugins.unavailable {
            v_flex()
                .child(
                    Label::new("Plugin registry unavailable")
                        .size(LabelSize::Small)
                        .color(Color::Error),
                )
                .child(
                    Label::new(unavailable.clone())
                        .size(LabelSize::Small)
                        .color(Color::Muted),
                )
        } else {
            v_flex()
                .w_full()
                .gap_2()
                .when(rows.is_empty() && operations.is_empty(), |this| {
                    this.child(
                        Label::new("No extensions installed")
                            .size(LabelSize::Small)
                            .color(Color::Muted),
                    )
                })
                .children(rows)
                .children(operations)
        };

        v_flex()
            .w_full()
            .gap_2()
            .child(registry_note)
            .child(body)
            .child(
                Button::new("add-plugin", "Add Plugin")
                    .style(ButtonStyle::Subtle)
                    .tooltip(ui::Tooltip::text(
                        "Install an extension from the registry (real flow)",
                    ))
                    .on_click(cx.listener(|this, _, _, cx| this.add_plugin_flow(cx))),
            )
            .children(self.plugins.message.clone().map(|message| {
                Label::new(message)
                    .size(LabelSize::XSmall)
                    .color(Color::Muted)
                    .into_any_element()
            }))
            .children(self.plugins.error.clone().map(|error| {
                Label::new(error)
                    .size(LabelSize::XSmall)
                    .color(Color::Error)
                    .into_any_element()
            }))
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

    // -----------------------------------------------------------------------
    // Escrow section (WP-5b — real persisted sessions, honest limbo labels)
    // -----------------------------------------------------------------------

    fn escrow_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let body = if !self.escrow_sessions.is_empty() {
            let rows: Vec<AnyElement> = self
                .escrow_sessions
                .iter()
                .map(|session| self.escrow_row(session, cx))
                .collect();
            v_flex().w_full().gap_2().children(rows).into_any_element()
        } else if let Some(error) = &self.escrow_error {
            v_flex()
                .child(
                    Label::new("Escrow unavailable")
                        .size(LabelSize::Small)
                        .color(Color::Error),
                )
                .child(Label::new(error.clone()).size(LabelSize::Small).color(Color::Muted))
                .into_any_element()
        } else {
            v_flex()
                .child(
                    Label::new("No active escrows")
                        .size(LabelSize::Small)
                        .color(Color::Muted),
                )
                .child(
                    Label::new(
                        "Escrows open through the market session flow (agent service delivery); \
                         sessions appear here once persisted.",
                    )
                    .size(LabelSize::XSmall)
                    .color(Color::Muted),
                )
                .into_any_element()
        };

        v_flex()
            .w_full()
            .gap_2()
            .child(body)
            // Honesty label (amendment 02b §3): the demo HTLC is external and
            // simulated — the dashboard never claims on-chain settlement.
            // OMEGA-DELTA-0294: the label is network-aware — it names the
            // wallet's configured network (the same reported == configured
            // network the escrow lane inherits; the "signet" fallback is the
            // wallet section's existing honest-default posture).
            .child(
                Label::new(escrow_honesty_footer(
                    self.wallet
                        .status
                        .as_ref()
                        .map(|status| status.network.as_str())
                        .unwrap_or("signet"),
                ))
                .size(LabelSize::XSmall)
                .color(Color::Muted),
            )
            .into_any_element()
    }

    fn escrow_row(&self, session: &market_ui::EscrowSession, cx: &mut Context<Self>) -> AnyElement {
        let (state_label, state_color) = escrow_state_label(session.state);
        let id_short: SharedString = format!(
            "{}…{}",
            &session.escrow_id[..session.escrow_id.len().min(8)],
            &session.escrow_id[session.escrow_id.len().saturating_sub(4)..]
        )
        .into();

        // Timeout countdown from the same observed tip the gate uses —
        // fail-closed: no probe, no fabricated countdown.
        let timeout_line: SharedString = match self.escrow_height {
            Some(height) => {
                let created_height = session.timeout_at_height.saturating_sub(session.timeout_blocks as u64);
                let elapsed = height.saturating_sub(created_height as u32);
                let remaining = session
                    .timeout_at_height
                    .saturating_sub(height as u64);
                let fraction = if session.timeout_blocks == 0 {
                    1.0
                } else {
                    elapsed as f64 / session.timeout_blocks as f64
                };
                let tone = if fraction >= 0.95 {
                    "RED"
                } else if fraction >= 0.75 {
                    "amber"
                } else {
                    "ok"
                };
                format!(
                    "HTLC window: {} blocks total · {} remaining (tip {}) [{tone}] · expires at height {}",
                    session.timeout_blocks, remaining, height, session.timeout_at_height
                )
                .into()
            }
            None => format!(
                "HTLC window: {} blocks · tip unavailable (countdown fail-closed) · expires at height {}",
                session.timeout_blocks, session.timeout_at_height
            )
            .into(),
        };

        let receipt_line: SharedString = match (&session.state, &session.receipt_digest) {
            (market_ui::EscrowState::ReceiptSubmitted, Some(digest))
            | (market_ui::EscrowState::VerifiedFail, Some(digest)) => {
                format!("receipt claim {}…{} (re-derivation pending/failed)", &digest[..8], &digest[digest.len() - 4..]).into()
            }
            (market_ui::EscrowState::VerifiedPass, Some(digest)) => {
                format!("receipt verified {}…{}", &digest[..8], &digest[digest.len() - 4..]).into()
            }
            _ => "no receipt submitted".into(),
        };

        // Pay-first escalation (SEC-2026-085): reachable only from limbo
        // states with an attempted delivery; the button carries the fee.
        let escalation = matches!(
            session.state,
            market_ui::EscrowState::AwaitingDelivery | market_ui::EscrowState::VerifiedFail
        );
        let escalate_button = escalation.then(|| {
            let escrow_id = session.escrow_id.clone();
            Button::new(
                SharedString::from(format!("escrow-escalate-{escrow_id}")),
                format!(
                    "Request Human Arbitration (pay {} sats first)",
                    session.arbitration_fee_flat_sats
                ),
            )
            .style(ButtonStyle::Subtle)
            .tooltip(ui::Tooltip::text(
                "Pays the flat arbitration fee in advance (pay-first), then admits the human queue",
            ))
            .on_click(cx.listener(move |this, _, window, cx| {
                this.request_arbitration(&escrow_id, window, cx);
            }))
        });

        v_flex()
            .w_full()
            .gap_1()
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .child(
                        Label::new(format!("escrow {id_short} · {} sats", session.amount_sats))
                            .size(LabelSize::Small),
                    )
                    .child(
                        Label::new(state_label)
                            .size(LabelSize::XSmall)
                            .color(state_color),
                    ),
            )
            .child(Label::new(timeout_line).size(LabelSize::XSmall).color(Color::Muted))
            .child(Label::new(receipt_line).size(LabelSize::XSmall).color(Color::Muted))
            .children(escalate_button.map(|button| {
                h_flex().w_full().justify_end().child(button).into_any_element()
            }))
            .into_any_element()
    }

    /// WP-5b: the pay-first escalation. Gated exactly like the flow it calls:
    /// without the demo opt-in the honest gate message surfaces and nothing
    /// touches the sidecar; with the opt-in the flow mandate-gates the fee on
    /// the sovereign-wallet venue, pays, appends the Fee + ArbitrationRequested
    /// entries hash-chained (Fee first), and the session state advances.
    fn request_arbitration(&mut self, escrow_id: &str, window: &mut Window, cx: &mut Context<Self>) {
        let Some(session_index) = self
            .escrow_sessions
            .iter()
            .position(|session| session.escrow_id == escrow_id)
        else {
            return;
        };
        let session = self.escrow_sessions[session_index].clone();
        let Some(supervisor) = self.supervisor.clone() else {
            self.escrow_error = Some("sidecar unavailable — the fee cannot be paid (fail closed)".into());
            cx.notify();
            return;
        };
        let Some(ledger) = self.ledger_store.clone() else {
            self.escrow_error = Some("ledger of record unavailable — refusing to move escrow state".into());
            cx.notify();
            return;
        };
        let Some(mandates) = self.mandate_store.clone() else {
            self.escrow_error = Some("mandate store unavailable — refusing to move escrow state".into());
            cx.notify();
            return;
        };
        let allow_live_mint = market_ui::arbitration_live_fees_enabled();
        let escalator = session.principal_pubkey.clone();
        let idempotency_key = self.next_idempotency_key();
        let now_ms = command_center_ui::unix_now_ms();
        let answer = window.prompt(
            PromptLevel::Warning,
            &format!(
                "Request human arbitration for escrow {}… (fee {} sats, paid first)?",
                &escrow_id[..escrow_id.len().min(8)],
                session.arbitration_fee_flat_sats
            ),
            Some(
                "The fee is paid in advance by the escalator and rerouted to the platform \
                 arbitrator on the decision (SEC-2026-085). Automated receipts resolve free.",
            ),
            &["Pay fee & request arbitration", "Cancel"],
            cx,
        );
        let escrow_id = escrow_id.to_string();
        let task = cx.spawn(async move |this, cx| {
            if answer.await != Ok(0) {
                return;
            }
            let mut guard = supervisor.lock().await;
            let started = guard.ensure_started().await;
            let result = match started {
                Ok(()) => {
                    let mut session = session.clone();
                    market_ui::pay_arbitration_fee_and_request_arbitration(
                        &mut guard,
                        &ledger,
                        &mandates,
                        &mut session,
                        &escalator,
                        &idempotency_key,
                        allow_live_mint,
                        now_ms,
                    )
                    .await
                    .map(|_| session)
                }
                Err(error) => Err(anyhow::anyhow!("sidecar unavailable: {error}")),
            };
            drop(guard);
            this.update(cx, |this, cx| {
                match result {
                    Ok(updated) => {
                        let directory = paths::data_dir().join(market_ui::ESCROW_STORE_DIRECTORY);
                        match updated.persist(&directory) {
                            Ok(_) => {
                                if let Some(slot) = this
                                    .escrow_sessions
                                    .iter_mut()
                                    .find(|session| session.escrow_id == escrow_id)
                                {
                                    *slot = updated;
                                }
                                this.escrow_error = None;
                            }
                            Err(error) => {
                                this.escrow_error =
                                    Some(SharedString::from(format!("escrow persist failed: {error:#}")));
                            }
                        }
                    }
                    Err(error) => {
                        this.escrow_error = Some(SharedString::from(error.to_string()));
                    }
                }
                this.refresh(cx);
                cx.notify();
            })
            .log_err();
        });
        task.detach();
    }

    /// WP-7: the mainnet-transition operator surface — network gates, the
    /// spend policy (kill + budgets), the per-network credential slots, and
    /// the NIP-AC projection flag state. Every rendered value is REAL state:
    /// the supervisor's policy store, the platform credential stores (presence
    /// only), and the process env. Nothing self-enables; no authority claim
    /// without backing (C7 honesty law).
    fn operator_section(&self, cx: &mut Context<Self>) -> AnyElement {
        let configured_network = std::env::var(sovereign_wallet::NETWORK_ENVIRONMENT_VARIABLE)
            .unwrap_or_else(|_| "signet".to_string());
        let reported_network = self
            .wallet
            .status
            .as_ref()
            .map(|status| status.network.clone());
        let allow_mainnet = std::env::var(sovereign_wallet::ALLOW_MAINNET_ENVIRONMENT_VARIABLE)
            .as_deref()
            == Ok("1");
        let wallet_line = wallet_network_gate_line(
            self.supervisor
                .is_some()
                .then_some(configured_network.as_str()),
            reported_network.as_deref(),
            allow_mainnet,
        );
        let nautilus_line = nautilus_gate_line(
            std::env::var(NAUTILUS_ENABLE_ENVIRONMENT_VARIABLE).as_deref() == Ok("1"),
            std::env::var(NAUTILUS_NETWORK_ENVIRONMENT_VARIABLE).ok().as_deref(),
        );
        let lnmarkets_line = lnmarkets_admission_line(
            std::env::var("OMEGA_LNMARKETS_MAINNET").ok().as_deref(),
        );
        let nipac_line = nipac_projection_line(
            std::env::var(NIPAC_PROJECTION_ENVIRONMENT_VARIABLE)
                .ok()
                .as_deref(),
        );

        let network_labels: Vec<AnyElement> = vec![
            Label::new(wallet_line).size(LabelSize::XSmall).color(Color::Muted).into_any_element(),
            Label::new(nautilus_line).size(LabelSize::XSmall).color(Color::Muted).into_any_element(),
            Label::new(lnmarkets_line).size(LabelSize::XSmall).color(Color::Muted).into_any_element(),
            Label::new(nipac_line).size(LabelSize::XSmall).color(Color::Muted).into_any_element(),
        ];

        // The spend-policy block (real snapshot or the honest lane-off state).
        let spend_block: AnyElement = match &self.operator.spend {
            Some(snapshot) => {
                let killed = snapshot.env_killed || snapshot.persisted_killed;
                let (kill_line, kill_color) = (
                    spend_kill_state_line(snapshot),
                    if killed { Color::Error } else { Color::Muted },
                );
                let budget_rows: Vec<AnyElement> = snapshot
                    .surfaces
                    .iter()
                    .map(|row| {
                        Label::new(surface_budget_line(row))
                            .size(LabelSize::XSmall)
                            .color(Color::Muted)
                            .into_any_element()
                    })
                    .collect();
                let budget_empty = snapshot.surfaces.is_empty();
                let ceiling_override_present = snapshot
                    .surfaces
                    .iter()
                    .any(|row| row.ceiling_is_override);
                let halt_labels: Vec<AnyElement> = if killed {
                    vec![
                        // The C3 halted-state rule: the exact named halted
                        // state the funded flows produce, plus the route.
                        Label::new(snapshot.halt_message.clone())
                            .size(LabelSize::XSmall)
                            .color(Color::Error)
                            .into_any_element(),
                        Label::new(
                            "route: Debug & Incident before anything resumes; only the \
                             founder re-enables (Decision 4 / OMEGA-DELTA-0300)",
                        )
                        .size(LabelSize::XSmall)
                        .color(Color::Warning)
                        .into_any_element(),
                    ]
                } else {
                    Vec::new()
                };
                v_flex()
                    .w_full()
                    .gap_1()
                    .child(
                        Label::new(kill_line)
                            .size(LabelSize::XSmall)
                            .color(kill_color),
                    )
                    .children(halt_labels)
                    .when(budget_rows.is_empty() && budget_empty, |this| {
                        this.child(
                            Label::new(
                                "no spend recorded today (counters reset on the UTC day \
                                 rollover)",
                            )
                            .size(LabelSize::XSmall)
                            .color(Color::Muted),
                        )
                    })
                    .children(budget_rows)
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                Button::new("sw-kill-set", "Set kill")
                                    .style(ButtonStyle::Subtle)
                                    .tooltip(ui::Tooltip::text(
                                        "Persist the spend kill (all-value-touching; logged)",
                                    ))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.set_spend_kill_flow(window, cx);
                                    })),
                            )
                            .child(
                                Button::new("sw-kill-clear", "Clear kill")
                                    .style(ButtonStyle::Subtle)
                                    .tooltip(ui::Tooltip::text(
                                        "Clear an operator-set kill (loss-rule kills follow the C3 route)",
                                    ))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.clear_spend_kill_flow(window, cx);
                                    })),
                            )
                            .child(
                                Button::new("sw-ceiling-set", "Set daily ceiling (wallet-l402)")
                                    .style(ButtonStyle::Subtle)
                                    .tooltip(ui::Tooltip::text(
                                        "Configure the enforced surface's daily ceiling (logged)",
                                    ))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.set_ceiling_flow(cx);
                                    })),
                            )
                            .when(ceiling_override_present, |this| {
                                this.child(
                                    Button::new("sw-ceiling-clear", "Reset ceiling to default")
                                        .style(ButtonStyle::Subtle)
                                        .tooltip(ui::Tooltip::text(
                                            "Remove the operator ceiling override (logged)",
                                        ))
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.clear_ceiling_flow(window, cx);
                                        })),
                                )
                            }),
                    )
                    .into_any_element()
            }
            None => v_flex()
                .w_full()
                .gap_1()
                .child(
                    Label::new(
                        "spend policy unavailable — the sovereign wallet lane is off \
                         (OMEGA_SOVEREIGN_WALLET=1 not set)",
                    )
                    .size(LabelSize::XSmall)
                    .color(Color::Muted),
                )
                .into_any_element(),
        };

        // The per-network credential slots (presence only, never secret
        // material; provisioning is founder-held).
        let slot_labels: Vec<AnyElement> = vec![
            Label::new(credential_slot_line(
                "Hyperliquid mainnet agent wallet",
                "slot omega://nautilus/hyperliquid/mainnet/agent-wallet-v1 (platform \
                 agent-wallet store); provisioning is founder-held; the WP-5 graduation \
                 gate consumes it",
                self.operator.nautilus_mainnet_wallet.as_ref(),
            ))
            .size(LabelSize::XSmall)
            .color(Color::Muted)
            .into_any_element(),
            Label::new(credential_slot_line(
                "LN Markets mainnet Trade key",
                "slot https://lnmarkets.com/api/v3 (the stored record's network field); \
                 provisioning is founder-held; the WP-6 admission consumes it",
                self.operator.lnmarkets_mainnet_key.as_ref(),
            ))
            .size(LabelSize::XSmall)
            .color(Color::Muted)
            .into_any_element(),
        ];

        v_flex()
            .w_full()
            .gap_2()
            .children(network_labels)
            .child(spend_block)
            .children(slot_labels)
            .children(self.operator.control_message.clone().map(|message| {
                Label::new(message)
                    .size(LabelSize::XSmall)
                    .color(Color::Created)
                    .into_any_element()
            }))
            .children(self.operator.control_error.clone().map(|error| {
                Label::new(error)
                    .size(LabelSize::XSmall)
                    .color(Color::Error)
                    .into_any_element()
            }))
            .into_any_element()
    }

    // -----------------------------------------------------------------------
    // Mainnet transition operator controls (WP-7) — the kill switch, the
    // per-surface ceiling, and the credential-slot display. Operator-gated:
    // every mutation passes an explicit warning confirmation (the panel's
    // operator-gate pattern), runs through the supervisor's policy seam (the
    // loopback-token sidecar channel's owner — the policy store is the
    // single Rust writer), and every set/clear event is logged (redacted)
    // by the policy store itself.
    // -----------------------------------------------------------------------

    fn set_spend_kill_flow(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            self.stub_notice = Some("Spend controls unavailable — the sovereign wallet lane is off (OMEGA_SOVEREIGN_WALLET=1 not set).");
            cx.notify();
            return;
        };
        let answer = window.prompt(
            PromptLevel::Warning,
            "SET the spend kill (halt every funded flow)?",
            Some(
                "All-value-touching (OMEGA-DELTA-0300): mint AND pay are refused at the \
                 choke point until the kill is cleared, and the kill persists across \
                 restarts. The set event is logged. The clear control works only for an \
                 operator-set kill; a loss-rule auto-kill needs the Debug & Incident \
                 route first (C3).",
            ),
            &["Set kill", "Cancel"],
            cx,
        );
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let mut message = None;
            let mut error = None;
            if answer.await == Ok(0) {
                let mut guard = supervisor.lock().await;
                match guard.set_operator_kill("set from the operator surface (WP-7)") {
                    Ok(()) => {
                        message =
                            Some("spend kill SET (persisted; every funded flow refuses; event logged)".to_string())
                    }
                    Err(set_error) => error = Some(format!("set refused: {set_error:#}")),
                }
            }
            this.update(cx, |this, cx| {
                this.operator.control_message = message.map(SharedString::from);
                this.operator.control_error = error.map(SharedString::from);
                this.refresh(cx);
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    fn clear_spend_kill_flow(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            self.stub_notice = Some("Spend controls unavailable — the sovereign wallet lane is off (OMEGA_SOVEREIGN_WALLET=1 not set).");
            cx.notify();
            return;
        };
        let answer = window.prompt(
            PromptLevel::Warning,
            "CLEAR the persisted spend kill?",
            Some(
                "This clears only an OPERATOR-set kill (founder re-enable, OMEGA-DELTA-0300). \
                 A loss-rule auto-kill is refused here: the C3 halted-state rule applies — \
                 run the Debug & Incident route before anything resumes. The environment \
                 kill (OMEGA_SPEND_KILL=1) is separate: it is cleared only by unsetting the \
                 env and restarting. The clear event is logged.",
            ),
            &["Clear kill", "Cancel"],
            cx,
        );
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let mut message = None;
            let mut error = None;
            if answer.await == Ok(0) {
                let mut guard = supervisor.lock().await;
                match guard.clear_operator_kill() {
                    Ok(()) => {
                        message =
                            Some("spend kill CLEARED (the persisted operator kill was removed; event logged)".to_string())
                    }
                    Err(clear_error) => error = Some(clear_error),
                }
            }
            this.update(cx, |this, cx| {
                this.operator.control_message = message.map(SharedString::from);
                this.operator.control_error = error.map(SharedString::from);
                this.refresh(cx);
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
    }

    fn set_ceiling_flow(&mut self, cx: &mut Context<Self>) {
        if self.supervisor.is_none() {
            self.stub_notice = Some("Spend controls unavailable — the sovereign wallet lane is off (OMEGA_SOVEREIGN_WALLET=1 not set).");
            cx.notify();
            return;
        }
        let current = self
            .operator
            .spend
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .surfaces
                    .iter()
                    .find(|row| row.surface == SURFACE_WALLET_L402)
                    .map(|row| row.ceiling_sats)
                    .unwrap_or(snapshot.default_ceiling_sats)
            })
            .unwrap_or(DAILY_CEILING_SATS);
        self.pending_input = Some(PendingInput {
            request: InputRequest::SpendCeilingSats,
            label: format!("Daily ceiling for {SURFACE_WALLET_L402} (sats)").into(),
            detail: format!(
                "The per-surface daily spend ceiling (configuration, OMEGA-DELTA-0300; \
                 first-phase default {DAILY_CEILING_SATS} sats — a labeled reversible \
                 assumption). Current effective ceiling: {current} sats. The event is \
                 logged. wallet-l402 is the surface enforced at the supervisor choke \
                 point; zero is refused (the kill switch blocks all spend)."
            )
            .into(),
        });
        cx.notify();
    }

    fn clear_ceiling_flow(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(supervisor) = self.supervisor.clone() else {
            return;
        };
        let answer = window.prompt(
            PromptLevel::Warning,
            "Reset the wallet-l402 daily ceiling to the default?",
            Some("Removes the operator override; the surface falls back to the first-phase default ceiling. The event is logged."),
            &["Reset to default", "Cancel"],
            cx,
        );
        self.refresh_task = Some(cx.spawn(async move |this, cx| {
            let mut message = None;
            let mut error = None;
            if answer.await == Ok(0) {
                let mut guard = supervisor.lock().await;
                match guard.clear_surface_ceiling(SURFACE_WALLET_L402) {
                    Ok(()) => {
                        message =
                            Some(format!("ceiling override removed for {SURFACE_WALLET_L402} (default applies; event logged)"))
                    }
                    Err(clear_error) => error = Some(format!("reset refused: {clear_error:#}")),
                }
            }
            this.update(cx, |this, cx| {
                this.operator.control_message = message.map(SharedString::from);
                this.operator.control_error = error.map(SharedString::from);
                this.refresh(cx);
                cx.notify();
            })
            .log_err();
        }));
        cx.notify();
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
                        Label::new(
                            "plugins · MCP · wallet · spending authorizations · escrow · \
                             mainnet transition",
                        )
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
            // Plugins (real — the installed-extension registry, WP-10)
            .child(self.section_header("Plugins"))
            .child(self.plugins_section(cx))
            // MCP servers mapped to Nostr IDs (real mapping)
            .child(self.section_header("MCP Servers → Nostr IDs"))
            .child(self.mcp_section(cx))
            // Spending authorizations (real generalized store)
            .child(self.section_header("Spending Authorizations"))
            .child(self.authorizations_section(cx))
            // Escrow (WP-5b — real persisted sessions, honest limbo labels)
            .child(self.section_header("Escrow"))
            .child(self.escrow_section(cx))
            // Mainnet transition operator surface (WP-7 — network gates,
            // spend policy, credential slots, projection state; real state
            // only, C7 honesty law)
            .child(self.section_header("Mainnet Transition"))
            .child(self.operator_section(cx))
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

/// WP-5b: load the persisted escrow sessions (digest-only state) from the
/// escrow store beside the market sessions. Unreadable files are skipped
/// with a log line — the section surfaces what it can read, never a fake row.
fn load_escrow_sessions() -> Vec<market_ui::EscrowSession> {
    let directory = paths::data_dir().join(market_ui::ESCROW_STORE_DIRECTORY);
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut sessions = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
        if !name.starts_with("escrow-") || !name.ends_with(".json") {
            continue;
        }
        match market_ui::EscrowSession::load(&path) {
            Ok(session) => sessions.push(session),
            Err(error) => log::error!("sovereign dashboard: skipping escrow store {name}: {error:#}"),
        }
    }
    sessions.sort_by(|a, b| a.escrow_id.cmp(&b.escrow_id));
    sessions
}

/// WP-5b: the honest escrow state-pill label. The HTLC is always labeled as
/// the external LN HTLC — the demo simulates the limbo and never
/// claims on-chain settlement (amendment 02b §3 honesty rule; OMEGA-DELTA-
/// 0294 makes the section footer name the configured network).
fn escrow_state_label(state: market_ui::EscrowState) -> (&'static str, Color) {
    use market_ui::EscrowState as S;
    match state {
        S::Created => ("created — HTLC lock external (limbo)", Color::Muted),
        S::AwaitingDelivery => ("awaiting delivery — limbo", Color::Muted),
        S::ReceiptSubmitted => ("receipt submitted — limbo", Color::Muted),
        S::VerifiedPass => ("verified pass — sign-off ready", Color::Created),
        S::VerifiedFail => ("verified fail — limbo held", Color::Warning),
        S::ArbitrationRequested => ("human arbitration requested", Color::Warning),
        S::Released => ("released to agent", Color::Created),
        S::Refunded => ("refunded to customer", Color::Created),
        S::Closed => ("closed", Color::Muted),
    }
}

/// A public Nostr pubkey is exactly 64 hex chars (never key material).
fn is_valid_pubkey_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// OMEGA-DELTA-0294: the escrow section's honesty footer is network-aware —
/// "external {network} LN HTLC — simulated limbo in demo; settlement
/// authority stays with Bitcoin/Lightning". The simulated-limbo wording is
/// kept (Decision 3 step 1: no on-chain broadcast this step).
fn escrow_honesty_footer(network: &str) -> String {
    format!(
        "external {network} LN HTLC — simulated limbo in demo; settlement authority \
         stays with Bitcoin/Lightning"
    )
}

// ---------------------------------------------------------------------------
// WP-7 operator-surface helpers (mainnet transition): the network-gate lines,
// the spend-policy lines, the credential-slot presence projection, and the
// NIP-AC projection flag line. Every line renders REAL state only (C7
// honesty law): the process env, the supervisor's policy store, and the
// platform credential stores (presence only — never secret material). No
// line claims an authority, gate, or feature that does not exist in this
// build; surfaces whose owning WP has not landed on this branch say so.
// ---------------------------------------------------------------------------

/// WP-7: the honest network note for the Fund flow's detail line — the REAL
/// configured network's caution. Signet/regtest keep the long-standing
/// "test coins only" wording; a mainnet-configured wallet (reachable only
/// through the 0286 gate: explicit network env AND the allow-mainnet opt-in)
/// is labeled as the real-funds network it is.
fn wallet_network_note(network: &str) -> String {
    if network == "mainnet" {
        "Mainnet is a real-funds network: this invoice moves real sats \
         (OMEGA-DELTA-0286 gate: explicit network + allow-mainnet opt-in)."
            .to_string()
    } else {
        "Test coins only — never mainnet.".to_string()
    }
}

/// WP-7: the sovereign wallet's network line — the REAL 0286 gate state.
/// `configured` is `Some` only while the wallet lane is on (the supervisor
/// exists; its sidecar refused to start without the network env), `reported`
/// is the sidecar's probed network (the SEC-2026-050 revised assertion
/// compares it against the configuration), and `allow_mainnet` is the
/// `OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET` opt-in's actual state. Mainnet is
/// never rendered as selectable without the opt-in — the line names the
/// gate exactly as the sidecar enforces it.
fn wallet_network_gate_line(
    configured: Option<&str>,
    reported: Option<&str>,
    allow_mainnet: bool,
) -> String {
    let Some(configured) = configured else {
        return "wallet network: lane off (OMEGA_SOVEREIGN_WALLET_NETWORK unset; the \
                sidecar refuses to start unconfigured) · mainnet requires the \
                explicit network env AND the allow-mainnet opt-in (0286)"
            .to_string();
    };
    let opt_in = if allow_mainnet {
        "opt-in present"
    } else {
        "opt-in absent (mainnet refused)"
    };
    match reported {
        Some(reported) => format!(
            "wallet network: configured {configured} · reported {reported} · \
             allow-mainnet {opt_in}"
        ),
        None => format!(
            "wallet network: configured {configured} · sidecar not reporting yet · \
             allow-mainnet {opt_in}"
        ),
    }
}

/// WP-7: the Nautilus gate-status line. The WP-5 mainnet graduation gate is
/// NOT landed on this branch's base — the current build hard-refuses Nautilus
/// mainnet (the pre-0295 posture) — so the line renders that lock honestly
/// and names the sequencing; it never claims a graduation gate that does not
/// exist here. An explicitly configured mainnet env is rendered as what it
/// really is in this build: refused.
fn nautilus_gate_line(enabled: bool, network: Option<&str>) -> String {
    let lane = if enabled {
        "enabled".to_string()
    } else {
        "off (OMEGA_NAUTILUS_SIDECAR unset)".to_string()
    };
    let network = match network {
        // The sidecar's documented default when the env is unset.
        None => "testnet (OMEGA_NAUTILUS_NETWORK unset)".to_string(),
        Some(network) => network.to_string(),
    };
    if network == "mainnet" {
        format!(
            "Nautilus: {lane} · network mainnet configured — REFUSED by the current \
             build (the WP-5 mainnet graduation gate is not landed on this branch; \
             sequencing recorded)"
        )
    } else {
        format!(
            "Nautilus: {lane} · network {network} · mainnet locked (the WP-5 \
             graduation gate is not landed on this branch; sequencing recorded)"
        )
    }
}

/// WP-7: the LN Markets admission display line — DISPLAY-ONLY, rendering the
/// CURRENT posture honestly: the executors are signet-only in this build
/// (OMEGA-DELTA-0249/0250/0255/0256) and the WP-6 admission is not landed on
/// this branch, so mainnet is not admitted. If the WP-6 env happens to be
/// set, the line says honestly that nothing consumes it yet.
fn lnmarkets_admission_line(env: Option<&str>) -> String {
    match env {
        Some(value) => format!(
            "LN Markets admission: signet-only in the current build · \
             OMEGA_LNMARKETS_MAINNET={value} is set but nothing consumes it yet (the \
             WP-6 admission is not landed on this branch; display-only)"
        ),
        None => format!(
            "LN Markets admission: signet-only in the current build · \
             OMEGA_LNMARKETS_MAINNET unset (the WP-6 admission is not landed on this \
             branch; display-only)"
        ),
    }
}

/// WP-7: the NIP-AC projection status line — a display of the REAL flag
/// state, never a feature claim. WP-12 implements the projection; while the
/// flag is unset the line reads "projection disabled" (the honest absence).
/// Even an enabled flag is rendered honestly: nothing in this build emits a
/// projection, so the line says exactly that.
fn nipac_projection_line(flag: Option<&str>) -> String {
    match flag {
        Some("1") => format!(
            "NIP-AC projection: OMEGA_NIPAC_PROJECTION=1 is set, but the projection \
             is NOT implemented in the current build (WP-12 is not landed on this \
             branch) — nothing emits; displayed honestly"
        ),
        Some(value) => format!(
            "NIP-AC projection: disabled — OMEGA_NIPAC_PROJECTION={value} is not the \
             enabled value, and the projection is not implemented (WP-12 is not \
             landed on this branch)"
        ),
        None => format!(
            "NIP-AC projection: disabled — OMEGA_NIPAC_PROJECTION unset (WP-12 is not \
             landed on this branch; this line displays the flag's absence, not a \
             feature)"
        ),
    }
}

/// WP-7: the kill-state line rendered from the REAL policy snapshot. The two
/// kill sources are named separately because they have separate clear
/// semantics (the env kill clears only by unsetting the env and restarting;
/// the persisted kill clears only per the operator/loss-rule rules). Reasons
/// are policy-store text (redacted at write time; no secret material).
fn spend_kill_state_line(snapshot: &SpendPolicySnapshot) -> String {
    let env = if snapshot.env_killed {
        "SET (OMEGA_SPEND_KILL=1)"
    } else {
        "not set"
    };
    let persisted = if snapshot.persisted_killed {
        match &snapshot.kill_reason {
            Some(reason) => format!("SET ({reason})"),
            None => "SET".to_string(),
        }
    } else {
        "not set".to_string()
    };
    format!(
        "spend kill: env {env} · persisted {persisted} · founder-only re-enable \
         (OMEGA-DELTA-0300)"
    )
}

/// WP-7: one per-surface budget row — the REAL counter for the surface's
/// persisted UTC day and the effective ceiling, stating whether the ceiling
/// is the operator override or the first-phase default (the labeled
/// reversible assumption).
fn surface_budget_line(row: &SurfaceSpendSnapshot) -> String {
    let ceiling_source = if row.ceiling_is_override {
        "operator override"
    } else {
        "first-phase default"
    };
    format!(
        "surface {}: spent {} sats on {} of {} sats ceiling ({})",
        row.surface, row.spent_sats, row.utc_day, row.ceiling_sats, ceiling_source
    )
}

/// WP-7: one credential-slot line — presence/absence ONLY. The state is a
/// REAL read outcome of the platform credential store; the helper never
/// receives and never renders secret material (C7 + secret hygiene).
/// Provisioning is founder-held; the line says so via the slot detail.
fn credential_slot_line(
    name: &str,
    slot_detail: &str,
    state: Option<&CredentialSlotState>,
) -> String {
    let presence = match state {
        Some(CredentialSlotState::Present) => "PROVISIONED (credential present)",
        Some(CredentialSlotState::Absent) => "empty (no credential)",
        Some(CredentialSlotState::Unreadable(reason)) => {
            return format!("{name}: UNREADABLE — {reason} · {slot_detail}");
        }
        None => "not read yet",
    };
    format!("{name}: {presence} · {slot_detail}")
}

/// WP-7 (pure, tested): map the LN Markets stored record's network to the
/// mainnet-slot state. `Some(Ok(..))` is a decoded record's network field
/// (the ONLY field this surface opens), `None` is no stored record, and
/// `Some(Err(..))` is a record that could not be decoded.
fn lnmarkets_mainnet_slot_state(network: Option<Result<LnMarketsNetwork, String>>) -> CredentialSlotState {
    match network {
        Some(Ok(LnMarketsNetwork::Mainnet)) => CredentialSlotState::Present,
        Some(Ok(_)) => CredentialSlotState::Absent,
        Some(Err(error)) => CredentialSlotState::Unreadable(format!(
            "the stored LN Markets credential record could not be read: {error}"
        )),
        None => CredentialSlotState::Absent,
    }
}

/// WP-7: a REAL presence read of the Nautilus mainnet agent-wallet slot
/// (`omega://nautilus/hyperliquid/mainnet/agent-wallet-v1`, the platform
/// agent-wallet store). Presence only: the record is NEVER decoded on this
/// surface and no byte of it is rendered or logged (C7 + secret hygiene).
async fn read_nautilus_mainnet_wallet_presence(
    provider: &std::sync::Arc<dyn CredentialsProvider>,
    cx: &AsyncApp,
) -> CredentialSlotState {
    let slot = nautilus_credential_key(NautilusNetwork::Mainnet);
    match provider.read_credentials(slot, cx).await {
        Ok(Some(_)) => CredentialSlotState::Present,
        Ok(None) => CredentialSlotState::Absent,
        Err(error) => CredentialSlotState::Unreadable(format!(
            "the platform agent-wallet store could not be read: {error:#}"
        )),
    }
}

/// WP-7: a REAL presence read of the LN Markets mainnet Trade-key slot. The
/// stored record lives at [`lnmarkets_client::CREDENTIAL_STORAGE_URL`]; it is
/// opened ONLY for its public `network` field (never rendered, never logged)
/// — a record whose network is Mainnet means the mainnet slot is provisioned.
/// No secret material is decoded into any display (C7 + secret hygiene; the
/// decoded record zeroizes on drop).
async fn read_lnmarkets_mainnet_key_slot(
    provider: &std::sync::Arc<dyn CredentialsProvider>,
    cx: &AsyncApp,
) -> CredentialSlotState {
    match provider.read_credentials(CREDENTIAL_STORAGE_URL, cx).await {
        Ok(Some((_username, encoded))) => {
            let network = StoredCredentials::decode(&encoded)
                .map(|stored| stored.network)
                .map_err(|error| format!("{error:#}"));
            lnmarkets_mainnet_slot_state(Some(network))
        }
        Ok(None) => lnmarkets_mainnet_slot_state(None),
        Err(error) => CredentialSlotState::Unreadable(format!(
            "the platform credential store could not be read: {error:#}"
        )),
    }
}

// ---------------------------------------------------------------------------
// WP-10 pure helpers (tested): Plugins (real extension registry) and Link
// (real NIP-46 status projection + pairing-state labels)
// ---------------------------------------------------------------------------

/// The real Plugins view snapshot: the installed-extension registry and the
/// in-flight operations. `try_global` renders an honest "unavailable" state
/// when the extension host is not registered (tests, unusual builds) — never
/// a fake row.
fn plugins_view(cx: &App) -> PluginsView {
    let Some(store) = extension_host::ExtensionStore::try_global(cx) else {
        return PluginsView {
            installed: Vec::new(),
            operations: Vec::new(),
            unavailable: Some(
                "the extension host is not registered in this build (no ExtensionStore global)"
                    .into(),
            ),
            message: None,
            error: None,
        };
    };
    let store = store.read(cx);
    let (installed, operations) =
        plugin_rows(store.installed_extensions(), store.outstanding_operations());
    PluginsView {
        installed,
        operations,
        unavailable: None,
        message: None,
        error: None,
    }
}

/// Pure: map the REAL extension index + outstanding operations to rows.
fn plugin_rows(
    installed: &std::collections::BTreeMap<std::sync::Arc<str>, extension_host::ExtensionIndexEntry>,
    outstanding: &std::collections::BTreeMap<std::sync::Arc<str>, extension_host::ExtensionOperation>,
) -> (Vec<PluginRow>, Vec<(String, String)>) {
    let mut rows = installed
        .iter()
        .map(|(id, entry)| PluginRow {
            id: id.to_string(),
            name: entry.manifest.name.clone(),
            version: entry.manifest.version.to_string(),
            dev: entry.dev,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    let operations = outstanding
        .iter()
        .map(|(id, operation)| (id.to_string(), plugin_operation_label(*operation)))
        .collect::<Vec<_>>();
    (rows, operations)
}

/// Honest label for an in-flight extension operation.
fn plugin_operation_label(operation: extension_host::ExtensionOperation) -> String {
    match operation {
        extension_host::ExtensionOperation::Upgrade => "upgrading…".to_string(),
        extension_host::ExtensionOperation::Install => "installing…".to_string(),
        extension_host::ExtensionOperation::Remove => "removing…".to_string(),
    }
}

/// One real linked-remote-signer status row (from the account registry).
#[derive(Clone, Debug, PartialEq, Eq)]
struct LinkStatusRow {
    title: String,
    detail: String,
    account_ref: String,
    generation: u64,
}

/// Pure: map the REAL account-registry projection to link-status rows. Only
/// remote NIP-46 signer accounts are "links"; every other account kind is
/// honestly excluded (it is not a cross-machine link).
fn link_status_rows(projection: &omega_identity::AccountDashboardProjection) -> Vec<LinkStatusRow> {
    let mut rows = projection
        .accounts
        .iter()
        .filter(|entry| entry.signer.kind == SignerKind::RemoteNip46)
        .map(|entry| {
            let is_active = entry.is_active;
            let lifecycle = format!("{:?}", entry.lifecycle).to_lowercase();
            let availability = format!("{:?}", entry.signer.availability).to_lowercase();
            let last_use = entry
                .signer
                .last_successful_use
                .map(|used_at| format!("last use {used_at}"))
                .unwrap_or_else(|| "never used".to_string());
            LinkStatusRow {
                title: if is_active {
                    format!("remote signer · {} (active)", entry.identity.public_key_hex().as_str())
                } else {
                    format!("remote signer · {}", entry.identity.public_key_hex().as_str())
                },
                detail: format!("{lifecycle} · {availability} · {last_use}"),
                account_ref: entry.account_ref.as_str().to_string(),
                generation: projection.active.generation,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a.account_ref.cmp(&b.account_ref));
    rows
}

/// Honest label for every REAL NIP-46 pairing state.
fn pairing_state_label(state: &Nip46PairingState) -> &'static str {
    match state {
        Nip46PairingState::AwaitingApproval => "AwaitingApproval",
        Nip46PairingState::AwaitingAcknowledgement => "AwaitingAcknowledgement",
        Nip46PairingState::AwaitingUserPublicKey => "AwaitingUserPublicKey",
        Nip46PairingState::AwaitingFinalApproval => "AwaitingFinalApproval",
        Nip46PairingState::AwaitingSignedChallenge => "AwaitingSignedChallenge",
        Nip46PairingState::AwaitingRegistration => "AwaitingRegistration",
        Nip46PairingState::Active => "Active",
        Nip46PairingState::Rejected => "Rejected",
        Nip46PairingState::Revoked => "Revoked",
    }
}

/// The account registry's current generation (the NIP-46 fence).
fn link_registry_generation() -> Result<u64, String> {
    AccountRegistryService::system(*app_identity::CHANNEL)
        .inspect()
        .map(|projection| projection.active.generation)
        .map_err(|error| format!("account registry unavailable: {error}"))
}

fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Honest failure copy for the relay-exchange errors (mirrors the account_ui
/// ceremony's failure classification).
fn link_relay_error_message(error: &omega_signer_broker::Nip46RelayError) -> String {
    match error {
        omega_signer_broker::Nip46RelayError::Offline
        | omega_signer_broker::Nip46RelayError::Silence => {
            "the remote signer is offline or did not respond; start the connection again when it \
             is available"
                .to_string()
        }
        omega_signer_broker::Nip46RelayError::Timeout => {
            "the remote signer did not finish in time; start the connection again to retry"
                .to_string()
        }
        omega_signer_broker::Nip46RelayError::Protocol(omega_identity::Nip46Error::Rejected) => {
            "the remote signer rejected this connection".to_string()
        }
        omega_signer_broker::Nip46RelayError::Protocol(omega_identity::Nip46Error::Revoked) => {
            "this remote signer capability was revoked".to_string()
        }
        omega_signer_broker::Nip46RelayError::Protocol(error) => {
            format!("the remote signer response could not be verified: {error}")
        }
        omega_signer_broker::Nip46RelayError::NoRelay => {
            "the pairing declares no reachable relay".to_string()
        }
        omega_signer_broker::Nip46RelayError::InvalidTimeout
        | omega_signer_broker::Nip46RelayError::MalformedFrame => {
            "the NIP-46 relay exchange failed (protocol error)".to_string()
        }
    }
}

/// Compact display of a public key (never key material).
fn short_pubkey(pubkey: &str) -> String {
    if pubkey.len() > 12 {
        format!("{}…{}", &pubkey[..8], &pubkey[pubkey.len() - 4..])
    } else {
        pubkey.to_string()
    }
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
    use nostr::{
        EventBuilder, JsonUtil as _, Keys, Kind, PublicKey, Timestamp,
        nips::nip46::NostrConnectMessage,
    };
    use omega_identity::{Nip46CapabilityState, SignerKind};
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
        // OMEGA-DELTA-0286: the candidate builder gained the network
        // parameter; the label assertions are unchanged (signet candidate).
        let mut venue_wide = sovereign_wallet::sovereign_wallet_mandate_candidate(
            TradingNetwork::Signet,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
            1_000,
            1,
        );
        venue_wide.principal_pubkey = None;
        assert!(mandate_scope_label(&venue_wide).contains("venue-wide"));
        let principal_keyed = sovereign_wallet::sovereign_wallet_mandate_candidate(
            TradingNetwork::Signet,
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

    // -----------------------------------------------------------------------
    // WP-10: Plugins — the REAL installed-extension registry mapping
    // -----------------------------------------------------------------------

    #[test]
    fn plugin_rows_map_the_real_extension_registry_and_in_flight_operations() {
        // The mapping the dashboard renders is exactly the extension host's
        // installed set + outstanding operations — no fabricated rows.
        let manifest = |id: &str, name: &str, version: &str| {
            let value = serde_json::json!({
                "id": id,
                "name": name,
                "version": version,
                "schema_version": 1,
            });
            serde_json::from_value::<extension_host::ExtensionManifest>(value).expect("manifest")
        };
        let mut installed = std::collections::BTreeMap::new();
        installed.insert(
            std::sync::Arc::<str>::from("om"),
            extension_host::ExtensionIndexEntry {
                manifest: std::sync::Arc::new(manifest("om", "om (Obsidian Mind)", "0.2.0")),
                dev: false,
            },
        );
        installed.insert(
            std::sync::Arc::<str>::from("source-summarization"),
            extension_host::ExtensionIndexEntry {
                manifest: std::sync::Arc::new(manifest(
                    "source-summarization",
                    "source-summarization",
                    "1.4.1",
                )),
                dev: true,
            },
        );
        let mut outstanding = std::collections::BTreeMap::new();
        outstanding.insert(
            std::sync::Arc::<str>::from("theme-dev"),
            extension_host::ExtensionOperation::Install,
        );
        outstanding.insert(
            std::sync::Arc::<str>::from("om"),
            extension_host::ExtensionOperation::Remove,
        );
        let (rows, operations) = plugin_rows(&installed, &outstanding);
        assert_eq!(rows.len(), 2);
        let om = rows.iter().find(|row| row.id == "om").expect("om row");
        assert_eq!(om.name, "om (Obsidian Mind)");
        assert_eq!(om.version, "0.2.0");
        assert!(!om.dev);
        let summarization = rows
            .iter()
            .find(|row| row.id == "source-summarization")
            .expect("summarization row");
        assert_eq!(summarization.version, "1.4.1");
        assert!(summarization.dev);
        // The in-flight operations are rendered as real states.
        assert!(operations.iter().any(|(id, label)| id == "theme-dev" && label == "installing…"));
        assert!(operations.iter().any(|(id, label)| id == "om" && label == "removing…"));
    }

    #[test]
    fn plugin_operation_labels_are_honest() {
        assert_eq!(
            plugin_operation_label(extension_host::ExtensionOperation::Install),
            "installing…"
        );
        assert_eq!(
            plugin_operation_label(extension_host::ExtensionOperation::Remove),
            "removing…"
        );
        assert_eq!(
            plugin_operation_label(extension_host::ExtensionOperation::Upgrade),
            "upgrading…"
        );
    }

    // -----------------------------------------------------------------------
    // WP-10: Link — REAL NIP-46 pairing state labels + registry status
    // -----------------------------------------------------------------------

    #[test]
    fn pairing_state_labels_cover_every_real_state_machine_state() {
        // Every state the omega_identity::nip46 state machine can reach has an
        // honest label; a future state-machine addition must add one here.
        use omega_identity::Nip46PairingState as State;
        for state in [
            State::AwaitingApproval,
            State::AwaitingAcknowledgement,
            State::AwaitingUserPublicKey,
            State::AwaitingFinalApproval,
            State::AwaitingSignedChallenge,
            State::AwaitingRegistration,
            State::Active,
            State::Rejected,
            State::Revoked,
        ] {
            let label = pairing_state_label(&state);
            assert!(!label.is_empty(), "no label for {state:?}");
            assert!(
                label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "label {label} is not a clean identifier"
            );
        }
    }

    #[test]
    fn link_status_rows_include_only_real_remote_nip46_accounts() {
        // No remote accounts on a fresh registry: no rows (never fabricated).
        let dir = tempfile::tempdir().expect("temp data root");
        let registry =
            AccountRegistryService::for_channel_data_root(app_identity::AppChannel::Dev, dir.path().to_path_buf());
        let projection = registry.inspect().expect("registry projection");
        assert!(link_status_rows(&projection).is_empty());
        // The filter is exactly SignerKind::RemoteNip46 — a local (non-remote)
        // account kind must never appear as a "link". The full positive case
        // (a registered remote account renders as one row, then disconnects
        // honestly) is covered by the bunker ceremony test.
        let _ = SignerKind::LocalNative;
    }

    #[test]
    fn bunker_link_ceremony_walks_the_real_state_machine_to_active() {
        use omega_identity::{
            AccountLifecycleState, SignerAvailability,
        };

        // The NIP-46 login-challenge kind (omega_identity/src/nip46.rs
        // NIP46_LOGIN_CHALLENGE_KIND — a private const; the literal is the
        // protocol value).
        const NIP46_LOGIN_CHALLENGE_KIND: u16 = 24246;
        const RELAY: &str = "wss://relay.example/";
        const NOW: u64 = 2_000_000_000;

        let dir = tempfile::tempdir().expect("temp data root");
        let registry = AccountRegistryService::for_channel_data_root(
            app_identity::AppChannel::Dev,
            dir.path().to_path_buf(),
        );
        let service = Nip46Service::for_data_root(dir.path().to_path_buf());
        let signer = Keys::generate();
        let generation = registry.inspect().expect("registry").active.generation;
        assert!(generation >= 1, "a fresh registry starts at generation 1");

        // The ceremony start (the dashboard's begin path): parse the bunker
        // URI, build the first-wave preview + fence, begin the pairing.
        let uri = format!(
            "bunker://{}?relay={RELAY}&secret=pairing-secret",
            signer.public_key().to_hex()
        );
        let input = Nip46ConnectionInput::parse(&uri).expect("parse bunker URI");
        let preview = Nip46PermissionPreview::omega_first_profile(
            Some(input.public_key().clone()),
            input.relays().to_vec(),
            NOW,
            NOW + 3_600,
        )
        .expect("preview");
        let fence = Nip46PairingFence::new(generation).expect("fence");
        let mut session = service
            .begin_bunker_pairing(input, preview, fence)
            .expect("begin bunker pairing");
        assert_eq!(session.state(), Nip46PairingState::AwaitingApproval);

        // Step 1: approve -> the persisted state advances.
        let connect = session
            .approve(NOW, 30)
            .expect("approve connect request");
        assert_eq!(session.state(), Nip46PairingState::AwaitingAcknowledgement);

        // Step 2: the signer acknowledges (result "ack").
        let ack = connect_response(
            &signer,
            PublicKey::from_hex(session.client_public_key().as_str()).expect("client pubkey"),
            &connect.request_id,
            Some("ack".to_string()),
            None,
            NOW + 1,
        );
        let get_public_key = session
            .receive_acknowledgement(
                generation,
                Nip46InboundEvent {
                    relay_url: RELAY,
                    event_json: &ack,
                    received_at: NOW + 1,
                },
                30,
            )
            .expect("acknowledgement");
        assert_eq!(session.state(), Nip46PairingState::AwaitingUserPublicKey);

        // Step 3: the signer reports its public key.
        let public_key_response = connect_response(
            &signer,
            PublicKey::from_hex(session.client_public_key().as_str()).expect("client pubkey"),
            &get_public_key.request_id,
            Some(signer.public_key().to_hex()),
            None,
            NOW + 2,
        );
        let reported = session
            .receive_user_public_key(
                generation,
                Nip46InboundEvent {
                    relay_url: RELAY,
                    event_json: &public_key_response,
                    received_at: NOW + 2,
                },
                30,
            )
            .expect("reported signer");
        assert_eq!(session.state(), Nip46PairingState::AwaitingFinalApproval);
        assert_eq!(
            reported.remote_signer_public_key.as_str(),
            signer.public_key().to_hex()
        );
        assert_eq!(
            reported.user_identity.public_key_hex().as_str(),
            signer.public_key().to_hex()
        );

        // Step 4: the operator's final approval -> the signer signs the login
        // challenge. The challenge content is the deterministic ceremony
        // string (the private `challenge_content` in nip46.rs); reconstruct it
        // from the public session values.
        let challenge_request = session
            .approve_reported_signer(NOW + 3, 30)
            .expect("approve reported signer");
        assert_eq!(session.state(), Nip46PairingState::AwaitingSignedChallenge);
        let challenge_content = format!(
            "omega:nip46-login:{}:{}:{}:{}",
            session.capability_ref(),
            generation,
            session.client_public_key().as_str(),
            signer.public_key().to_hex()
        );
        let signed_challenge = EventBuilder::new(Kind::Custom(NIP46_LOGIN_CHALLENGE_KIND), challenge_content)
            .custom_created_at(Timestamp::from_secs(NOW + 3))
            .sign_with_keys(&signer)
            .expect("sign challenge");
        let challenge_response = connect_response(
            &signer,
            PublicKey::from_hex(session.client_public_key().as_str()).expect("client pubkey"),
            &challenge_request.request_id,
            Some(signed_challenge.try_as_json().expect("challenge json")),
            None,
            NOW + 4,
        );
        let capability = session
            .receive_signed_challenge(
                generation,
                Nip46InboundEvent {
                    relay_url: RELAY,
                    event_json: &challenge_response,
                    received_at: NOW + 4,
                },
            )
            .expect("signed challenge");
        assert_eq!(session.state(), Nip46PairingState::AwaitingRegistration);
        assert_eq!(capability.state, Nip46CapabilityState::AwaitingRegistration);

        // Step 5: the terminal registration -> the remote account is ACTIVE.
        let projection = registry
            .register_remote_account(&capability.capability_ref, generation)
            .expect("register remote account");
        let remote = projection
            .accounts
            .iter()
            .find(|entry| entry.signer.kind == SignerKind::RemoteNip46)
            .expect("remote account registered");
        assert_eq!(remote.lifecycle, AccountLifecycleState::Active);
        assert_eq!(remote.signer.availability, SignerAvailability::Ready);
        assert!(remote.is_active, "the linked remote signer becomes the active account");

        // The dashboard's status surface renders the real linked signer.
        let rows = link_status_rows(&projection);
        assert_eq!(rows.len(), 1, "exactly one linked remote signer: {rows:?}");
        assert!(rows[0].title.contains("remote signer"), "{}", rows[0].title);
        assert!(rows[0].title.contains("(active)"), "{}", rows[0].title);
        assert!(rows[0].detail.contains("ready"), "{}", rows[0].detail);

        // The real Disconnect revokes and signs the account out.
        let after_disconnect = registry
            .disconnect_remote_signer(&remote.account_ref, projection.active.generation)
            .expect("disconnect remote signer");
        assert!(after_disconnect.active.account_ref.is_none());
        let rows = link_status_rows(&after_disconnect);
        assert_eq!(rows.len(), 1, "the recorded account stays visible, honestly revoked");
        assert!(rows[0].detail.contains("signedout"), "{}", rows[0].detail);
        assert!(rows[0].detail.contains("revoked"), "{}", rows[0].detail);
    }

    #[test]
    fn nostrconnect_link_ceremony_walks_to_final_approval() {
        use omega_identity::Nip46PermissionPreview;

        const RELAY: &str = "wss://relay.example/";
        const NOW: u64 = 2_000_000_000;

        let dir = tempfile::tempdir().expect("temp data root");
        let service = Nip46Service::for_data_root(dir.path().to_path_buf());
        let registry = AccountRegistryService::for_channel_data_root(
            app_identity::AppChannel::Dev,
            dir.path().to_path_buf(),
        );
        let signer = Keys::generate();
        let generation = registry.inspect().expect("registry").active.generation;

        // The dashboard's nostrconnect path: create the pairing link (the URI
        // the operator opens on the other machine).
        let preview = Nip46PermissionPreview::omega_first_profile(
            None,
            vec![RELAY.to_string()],
            NOW,
            NOW + 3_600,
        )
        .expect("preview");
        let fence = Nip46PairingFence::new(generation).expect("fence");
        let (mut session, pairing_uri) = service
            .create_nostrconnect_pairing(preview, fence, "Omega")
            .expect("create nostrconnect pairing");
        assert_eq!(session.state(), Nip46PairingState::AwaitingAcknowledgement);

        // The remote signer reads the URI and echoes the pairing secret in its
        // acknowledgement (the real `receive_nostrconnect_acknowledgement`
        // flow — the secret is what binds the inbound signer).
        let secret = {
            let uri = url::Url::parse(pairing_uri.expose()).expect("parse pairing URI");
            uri.query_pairs()
                .find(|(key, _)| key == "secret")
                .map(|(_, value)| value.into_owned())
                .expect("pairing secret in URI")
        };
        let acknowledgement = connect_response(
            &signer,
            PublicKey::from_hex(session.client_public_key().as_str()).expect("client pubkey"),
            &secret,
            Some(secret.clone()),
            None,
            NOW + 1,
        );
        let get_public_key = session
            .receive_nostrconnect_acknowledgement(
                generation,
                Nip46InboundEvent {
                    relay_url: RELAY,
                    event_json: &acknowledgement,
                    received_at: NOW + 1,
                },
                30,
            )
            .expect("nostrconnect acknowledgement");
        assert_eq!(session.state(), Nip46PairingState::AwaitingUserPublicKey);
        assert_eq!(
            session.remote_signer_public_key().expect("remote signer").as_str(),
            signer.public_key().to_hex()
        );

        // The public-key report (same as the bunker path).
        let public_key_response = connect_response(
            &signer,
            PublicKey::from_hex(session.client_public_key().as_str()).expect("client pubkey"),
            &get_public_key.request_id,
            Some(signer.public_key().to_hex()),
            None,
            NOW + 2,
        );
        let reported = session
            .receive_user_public_key(
                generation,
                Nip46InboundEvent {
                    relay_url: RELAY,
                    event_json: &public_key_response,
                    received_at: NOW + 2,
                },
                30,
            )
            .expect("reported signer");
        assert_eq!(session.state(), Nip46PairingState::AwaitingFinalApproval);
        assert_eq!(
            reported.remote_signer_public_key.as_str(),
            signer.public_key().to_hex()
        );
    }

    /// Build a NIP-46 (kind 24133) response event encrypted to the client —
    /// the same shape the remote signer emits over the relay.
    fn connect_response(
        signer: &nostr::Keys,
        recipient: PublicKey,
        request_id: &str,
        result: Option<String>,
        error: Option<String>,
        created_at: u64,
    ) -> String {
        nostr::EventBuilder::nostr_connect(
            signer,
            recipient,
            NostrConnectMessage::Response {
                id: request_id.to_string(),
                result,
                error,
            },
        )
        .expect("nostr connect event")
        .custom_created_at(nostr::Timestamp::from_secs(created_at))
        .sign_with_keys(signer)
        .expect("sign response")
        .try_as_json()
        .expect("response json")
    }

    // -------------------------------------------------------------------
    // WP-7 operator-surface helpers: the honesty wording of every rendered
    // line is pinned here (real state only; no authority claim without
    // backing; un-landed WPs named).
    // -------------------------------------------------------------------

    fn wp7_snapshot(
        env_killed: bool,
        persisted_killed: bool,
        kill_reason: Option<&str>,
    ) -> SpendPolicySnapshot {
        SpendPolicySnapshot {
            env_killed,
            persisted_killed,
            kill_reason: kill_reason.map(|reason| reason.to_string()),
            killed_at_unix: None,
            halt_message: if env_killed || persisted_killed {
                "SPEND_HALTED: …".to_string()
            } else {
                String::new()
            },
            default_ceiling_sats: DAILY_CEILING_SATS,
            budget_path: "C:\\data\\run\\spend-budget.json".to_string(),
            surfaces: vec![SurfaceSpendSnapshot {
                surface: SURFACE_WALLET_L402.to_string(),
                utc_day: "2026-09-01".to_string(),
                spent_sats: 250,
                ceiling_sats: 2_000,
                ceiling_is_override: true,
            }],
        }
    }

    #[test]
    fn wallet_network_gate_line_renders_the_real_0286_gate_state() {
        // Lane off: the honest unconfigured posture — never a "signet" claim.
        let line = wallet_network_gate_line(None, None, false);
        assert!(line.contains("lane off"), "{line}");
        assert!(line.contains("unset"), "{line}");
        assert!(line.contains("allow-mainnet opt-in"), "{line}");
        // Configured signet, sidecar reporting: the opt-in state is named.
        let line = wallet_network_gate_line(Some("signet"), Some("signet"), false);
        assert!(line.contains("configured signet"), "{line}");
        assert!(line.contains("reported signet"), "{line}");
        assert!(line.contains("opt-in absent (mainnet refused)"), "{line}");
        // Opted-in mainnet (the only way mainnet renders as configured).
        let line = wallet_network_gate_line(Some("mainnet"), Some("mainnet"), true);
        assert!(line.contains("configured mainnet"), "{line}");
        assert!(line.contains("opt-in present"), "{line}");
        // Sidecar not reporting yet is stated, never fabricated.
        let line = wallet_network_gate_line(Some("signet"), None, false);
        assert!(line.contains("sidecar not reporting yet"), "{line}");
    }

    #[test]
    fn wallet_network_note_matches_the_real_network() {
        assert_eq!(
            wallet_network_note("signet"),
            "Test coins only — never mainnet."
        );
        assert_eq!(wallet_network_note("regtest"), "Test coins only — never mainnet.");
        let mainnet = wallet_network_note("mainnet");
        assert!(mainnet.contains("real-funds"), "{mainnet}");
        assert!(mainnet.contains("0286"), "{mainnet}");
    }

    #[test]
    fn nautilus_gate_line_renders_the_current_lock_honestly() {
        // Off + unset env: the sidecar default and the honest lock.
        let line = nautilus_gate_line(false, None);
        assert!(line.contains("off (OMEGA_NAUTILUS_SIDECAR unset)"), "{line}");
        assert!(line.contains("testnet"), "{line}");
        assert!(line.contains("mainnet locked"), "{line}");
        assert!(line.contains("not landed on this branch"), "{line}");
        // Enabled on testnet: still locked for mainnet (WP-5 not landed).
        let line = nautilus_gate_line(true, Some("testnet"));
        assert!(line.contains("enabled"), "{line}");
        assert!(line.contains("mainnet locked"), "{line}");
        // A configured mainnet env is REFUSED in this build — the line says
        // exactly that (no graduation gate exists here to pass).
        let line = nautilus_gate_line(true, Some("mainnet"));
        assert!(line.contains("REFUSED by the current build"), "{line}");
        assert!(line.contains("not landed on this branch"), "{line}");
    }

    #[test]
    fn lnmarkets_admission_line_is_display_only_and_honest() {
        // Unset: the current signet-only posture, named as display-only.
        let line = lnmarkets_admission_line(None);
        assert!(line.contains("signet-only"), "{line}");
        assert!(line.contains("unset"), "{line}");
        assert!(line.contains("display-only"), "{line}");
        assert!(line.contains("not landed on this branch"), "{line}");
        // Even a set env is honest: nothing consumes it in this build.
        let line = lnmarkets_admission_line(Some("1"));
        assert!(line.contains("nothing consumes it yet"), "{line}");
        assert!(line.contains("signet-only"), "{line}");
    }

    #[test]
    fn nipac_projection_line_renders_the_honest_flag_absence() {
        // The brief's requirement: the honest disabled state while the flag
        // is unset — a display of the flag's absence, not a feature.
        let line = nipac_projection_line(None);
        assert!(line.contains("NIP-AC projection: disabled"), "{line}");
        assert!(line.contains("unset"), "{line}");
        assert!(line.contains("the flag's absence, not a feature"), "{line}");
        // A non-enabled value: still disabled, honestly.
        let line = nipac_projection_line(Some("0"));
        assert!(line.contains("NIP-AC projection: disabled"), "{line}");
        // An enabled flag does NOT claim a feature: WP-12 is not landed, so
        // nothing emits and the line says so.
        let line = nipac_projection_line(Some("1"));
        assert!(line.contains("NOT implemented"), "{line}");
        assert!(line.contains("nothing emits"), "{line}");
    }

    #[test]
    fn spend_kill_state_line_names_both_kill_sources() {
        // Both sources clear.
        let line = spend_kill_state_line(&wp7_snapshot(false, false, None));
        assert!(line.contains("env not set"), "{line}");
        assert!(line.contains("persisted not set"), "{line}");
        // The env kill latched: named with its env, separately from the
        // persisted kill.
        let line = spend_kill_state_line(&wp7_snapshot(true, false, None));
        assert!(line.contains("env SET (OMEGA_SPEND_KILL=1)"), "{line}");
        assert!(line.contains("persisted not set"), "{line}");
        // The persisted loss-rule kill: the reason is shown as stored.
        let line = spend_kill_state_line(&wp7_snapshot(
            false,
            true,
            Some("loss-rule: over-settlement"),
        ));
        assert!(line.contains("env not set"), "{line}");
        assert!(line.contains("persisted SET (loss-rule: over-settlement)"), "{line}");
        // Founder-only re-enable is always named (no self-clear authority).
        assert!(line.contains("founder-only re-enable"), "{line}");
    }

    #[test]
    fn surface_budget_line_states_the_ceiling_source() {
        let row = SurfaceSpendSnapshot {
            surface: SURFACE_WALLET_L402.to_string(),
            utc_day: "2026-09-01".to_string(),
            spent_sats: 250,
            ceiling_sats: 2_000,
            ceiling_is_override: true,
        };
        let line = surface_budget_line(&row);
        assert!(line.contains("wallet-l402"), "{line}");
        assert!(line.contains("250 sats"), "{line}");
        assert!(line.contains("2_000") || line.contains("2000") || line.contains("2,000"), "{line}");
        assert!(line.contains("operator override"), "{line}");
        let default_row = SurfaceSpendSnapshot {
            ceiling_is_override: false,
            ceiling_sats: DAILY_CEILING_SATS,
            ..row
        };
        let line = surface_budget_line(&default_row);
        assert!(line.contains("first-phase default"), "{line}");
    }

    #[test]
    fn credential_slot_line_renders_presence_only_and_never_material() {
        let detail = "slot omega://…; provisioning is founder-held";
        // Present / Absent / Unreadable / not-read-yet — presence wording
        // only; no secret material ever enters the line (the helper has no
        // material parameter by construction).
        let line = credential_slot_line(
            "Hyperliquid mainnet agent wallet",
            detail,
            Some(&CredentialSlotState::Present),
        );
        assert!(line.contains("PROVISIONED"), "{line}");
        assert!(line.contains("founder-held"), "{line}");
        let line = credential_slot_line(
            "LN Markets mainnet Trade key",
            detail,
            Some(&CredentialSlotState::Absent),
        );
        assert!(line.contains("empty (no credential)"), "{line}");
        let line = credential_slot_line(
            "Hyperliquid mainnet agent wallet",
            detail,
            Some(&CredentialSlotState::Unreadable("store error".to_string())),
        );
        assert!(line.contains("UNREADABLE"), "{line}");
        assert!(line.contains("store error"), "{line}");
        let line = credential_slot_line("LN Markets mainnet Trade key", detail, None);
        assert!(line.contains("not read yet"), "{line}");
    }

    #[test]
    fn lnmarkets_mainnet_slot_state_maps_the_record_network() {
        // A mainnet record = the mainnet slot is provisioned.
        assert_eq!(
            lnmarkets_mainnet_slot_state(Some(Ok(LnMarketsNetwork::Mainnet))),
            CredentialSlotState::Present
        );
        // The single stored record holding a signet network = the mainnet
        // slot is empty (honest absence, not a fabricated present).
        assert_eq!(
            lnmarkets_mainnet_slot_state(Some(Ok(LnMarketsNetwork::Signet))),
            CredentialSlotState::Absent
        );
        assert_eq!(lnmarkets_mainnet_slot_state(None), CredentialSlotState::Absent);
        // A record that cannot be decoded is UNREADABLE with the reason.
        match lnmarkets_mainnet_slot_state(Some(Err("decode failed".to_string()))) {
            CredentialSlotState::Unreadable(reason) => {
                assert!(reason.contains("decode failed"), "{reason}");
            }
            state => panic!("expected Unreadable, got {state:?}"),
        }
    }
}