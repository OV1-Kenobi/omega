//! Framed protocol types for `openagents.omega.sovereign-wallet.v1` (design §2).

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_SCHEMA: &str = "openagents.omega.sovereign-wallet.v1";
pub const PROTOCOL_VERSION: u32 = 1;
pub const SERVICE_VERSION: &str = "0.1.0";
/// Newline-framed JSON frames must stay under this byte budget (design §2.1).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// wavecli-style stable error codes (design §2.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArgs,
    WalletNotCreated,
    WalletLocked,
    WalletSyncing,
    NotFound,
    MethodNotFound,
    ConfirmationRequired,
    InsufficientBalance,
    InvoiceExpired,
    Canceled,
    DeadlineExceeded,
    Aborted,
    WaitTimeout,
    MainnetRefused,
    PaymentHashMismatch,
    CredentialConsumed,
    StaleGeneration,
    AlreadyRunning,
    /// The one-time Nostr-secret export bridge has already been consumed and
    /// refuses to re-export (design §2.2 `export-nostr-secret`).
    ExportAlreadyConsumed,
    /// OMEGA-DELTA-0303 (rail renames): the waved codes are replaced on the
    /// rail. `WAVED_BINARY_MISSING` -> `NODE_UNCONFIGURED` (the missing
    /// phoenixd env / rail connection); `WAVED_WALLET_API_UNAVAILABLE` is
    /// removed (the waved wallet-API probe has no phoenixd equivalent);
    /// `WAVED_HEIGHT_UNAVAILABLE` -> `TIP_HEIGHT_UNAVAILABLE` (the public
    /// tip-API fail-closed code; 0304 carries the tip client — this slice's
    /// wallet-height seam answers it fail-closed, so the escrow timeout gate
    /// never substitutes wall-clock).
    NodeUnconfigured,
    TipHeightUnavailable,
    /// OMEGA-DELTA-0300 (kill closure): the sidecar's gateway mint path
    /// reads the environment-level spend kill and refuses with this code.
    /// The Rust choke point refuses BEFORE forwarding when killed, so this
    /// code can only arrive across the check/forward race — the variant
    /// keeps the envelope decodable (additive; the client maps it to a
    /// Protocol error).
    SpendHalted,
    IncompatibleVersion,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorEnvelope {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub retryable: bool,
    #[serde(default)]
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFrame {
    pub schema: String,
    pub kind: String,
    pub id: String,
    pub generation: u64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFrame {
    pub schema: String,
    pub kind: String,
    pub id: String,
    pub generation: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorEnvelope>,
}

/// Wallet state normalized from the node rail (design §1.4; the phoenixd
/// rail derives "ready" from the getinfo probe, "error" from a failed probe;
/// the waved lifecycle states none/locked/syncing no longer apply to a remote
/// operator-managed node — OMEGA-DELTA-0303).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletState {
    None,
    Locked,
    Syncing,
    Ready,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub schema: String,
    pub protocol_version: u32,
    pub service_version: String,
    pub generation: u64,
    pub capabilities: Vec<String>,
    pub data_root: String,
    pub network: String,
    /// OMEGA-DELTA-0303 (honest renames): the node's ACTUAL runtime network
    /// from the rail's getinfo probe (the `chain` field when present, else
    /// `None` — the assertion is then carried by the env gate + the invoice
    /// HRP guard, design §2.6.3), never the env value alone.
    #[serde(default)]
    pub node_network: Option<String>,
    #[serde(default)]
    pub node_state: String,
    #[serde(default)]
    pub http_surface: HttpSurface,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpSurface {
    #[serde(default)]
    pub bound: bool,
    #[serde(default)]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResult {
    pub ok: bool,
    pub status: String,
    pub generation: u64,
    pub data_root: String,
    pub wallet_state: WalletState,
    #[serde(default)]
    pub node_connected: bool,
    pub network: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResult {
    pub schema: String,
    pub protocol_version: u32,
    pub service_version: String,
    pub network: String,
    #[serde(default)]
    pub node_connected: bool,
    #[serde(default)]
    pub node_unavailable_reason: String,
    pub wallet_state: WalletState,
    #[serde(default)]
    pub vault_state: String,
    #[serde(default)]
    pub l402_gateway_state: String,
    pub http_surface: HttpSurface,
    pub data_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResult {
    pub confirmed_sat: String,
    pub pending_in_sat: String,
    pub pending_out_sat: String,
    pub credit_available_sat: String,
    pub credit_reserved_sat: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceResult {
    pub invoice: String,
    #[serde(default)]
    pub payment_hash: Option<String>,
    pub amount_sat: u64,
    #[serde(default)]
    pub memo: String,
    #[serde(default)]
    pub hrp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayResult {
    #[serde(default)]
    pub payment_hash: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub activity_id: String,
    #[serde(default)]
    pub actual_amount_sat: String,
    #[serde(default)]
    pub expected_fee_sat: String,
    #[serde(default)]
    pub fee_known: bool,
    /// OMEGA-DELTA-0300 (loss rule, SEC-2026-098): the prepared-for total
    /// outflow (invoice amount + expected fee) — the EXPECTED bound of the
    /// expected-vs-actual settle comparison at `pay_invoice`. Only meaningful
    /// when `total_outflow_known` is true (the sidecar's prepare-send quote
    /// answered).
    #[serde(default)]
    pub expected_total_outflow_sat: String,
    /// OMEGA-DELTA-0300: whether the sidecar's prepare-send answered a known
    /// total outflow. When false, no expected bound exists and the loss rule
    /// cannot fire (it must not false-trigger on unknown quotes).
    #[serde(default)]
    pub total_outflow_known: bool,
    #[serde(default)]
    pub warning: String,
    /// Proof of payment; the sidecar redacts it from every log and never
    /// persists it (SEC-2026-046/047).
    #[serde(default)]
    pub preimage: Option<String>,
}

/// Identity/vault projection (design §2.2 `identity-status`). Read-only,
/// public projection only — never key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityStatusResult {
    pub vault_state: String,
    pub derived_npub: Option<String>,
    /// Public-key hex (64-hex) of the derived identity — public projection
    /// (same key material as the npub, different encoding). WP-5: used as the
    /// principal for pubkey-keyed spending authorizations.
    #[serde(default)]
    pub derived_pubkey_hex: Option<String>,
    #[serde(default)]
    pub recovery_artifact_state: String,
    #[serde(default)]
    pub note: String,
}

/// One-time Nostr-secret export (design §2.2 `export-nostr-secret`; operator
/// only — the bridge into the Rust `omega_identity` import path). The nsec is
/// returned exactly once; the sidecar refuses re-export with
/// `ExportAlreadyConsumed` and never logs the material (SEC-2026-046).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportNostrSecretResult {
    /// bech32 `nsec1…` material, shown once to the operator.
    pub nsec: String,
    pub npub: String,
    pub exported: bool,
}

/// Create-wallet result (operator-only). The aezeed is shown once; the wallet
/// DB password and aezeed are captured into the vault when it is unlocked
/// (WP-5 seam: create-wallet → vault capture).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWalletResult {
    /// Show-once 24-word Wavelength aezeed backup phrase.
    pub mnemonic: Vec<String>,
    #[serde(default)]
    pub identity_pubkey: Option<String>,
    /// True when the wallet DB password + aezeed were captured into the vault
    /// at create (vault unlocked). False (with `note`) when the vault is
    /// locked/absent — the password is then operator-held only.
    pub wallet_db_password_vaulted: bool,
    #[serde(default)]
    pub vault_wallet_id: Option<String>,
    #[serde(default)]
    pub note: String,
}

/// WP-4b (SEC-2026-087) / OMEGA-DELTA-0303: the observed tip height, read
/// through the sidecar's `wallet-height` seam. THIS SLICE fails closed with
/// `TIP_HEIGHT_UNAVAILABLE` (the public tip API lands under OMEGA-DELTA-0304
/// in the C3-2 slice); the escrow `timeout_at_height` gate must fail closed
/// on it — the tip never comes from wall-clock.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeightResult {
    pub block_height: u32,
}

pub fn request_frame(id: impl Into<String>, generation: u64, method: &str, params: Option<Value>) -> RequestFrame {
    RequestFrame {
        schema: PROTOCOL_SCHEMA.to_string(),
        kind: "request".to_string(),
        id: id.into(),
        generation,
        method: method.to_string(),
        params,
    }
}