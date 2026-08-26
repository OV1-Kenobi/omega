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
    WavedBinaryMissing,
    WavedWalletApiUnavailable,
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

/// Wallet state normalized from the Wavelength daemon (design §1.4).
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
    /// The waved daemon's ACTUAL runtime network from the probe (SEC-2026-050),
    /// never the env value alone. `None` when waved is unavailable.
    #[serde(default)]
    pub waved_network: Option<String>,
    #[serde(default)]
    pub waved_state: String,
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
    pub waved_connected: bool,
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
    pub waved_connected: bool,
    #[serde(default)]
    pub waved_unavailable_reason: String,
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
    #[serde(default)]
    pub warning: String,
    /// Proof of payment; the sidecar redacts it from every log and never
    /// persists it (SEC-2026-046/047).
    #[serde(default)]
    pub preimage: Option<String>,
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