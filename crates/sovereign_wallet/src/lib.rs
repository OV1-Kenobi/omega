//! Sovereign wallet: Rust supervisor + typed client for the supervised
//! Node 24/Effect wallet sidecar (Phase 2 wallet wiring, WP-3).
//!
//! The supervisor launches and supervises `sidecar/sovereign-wallet`
//! (newline-framed JSON over stdio, generation fencing, bounded frames,
//! redacted stderr), enforces the signet/regtest-only posture (mainnet
//! hard-bail mirrored from `nautilus_sidecar`), and exposes a typed client
//! for the loopback protocol contract (design §2).
//!
//! The whole surface is gated behind `OMEGA_SOVEREIGN_WALLET=1` (default
//! OFF), following the `market_ui` env-gate precedent. WP-5 owns the
//! construction/activation site (dashboard wiring); this crate provides the
//! supervisor, the client, and the gate.

mod client;
mod protocol;
mod supervisor;
#[cfg(test)]
mod tests;

pub use client::SovereignWalletError;
pub use protocol::{
    BalanceResult, ErrorCode, HealthResult, InitializeResult, InvoiceResult, PayResult,
    PROTOCOL_SCHEMA, PROTOCOL_VERSION, SERVICE_VERSION, StatusResult, WalletState,
};
pub use supervisor::{
    SovereignWalletCommand, SovereignWalletSupervisor, SovereignWalletSupervisorOptions,
    default_options, fixture_command, fixture_command_with_network, fixture_node,
    resolve_sidecar_command, resolve_node_binary,
};

use gpui::App;

/// Environment gate for the sovereign wallet lane (market_ui precedent).
pub const SOVEREIGN_WALLET_ENVIRONMENT_VARIABLE: &str = "OMEGA_SOVEREIGN_WALLET";
/// The sidecar is only ever launched on signet or regtest (D4).
pub const SUPPORTED_NETWORKS: &[&str] = &["signet", "regtest"];

pub fn sovereign_wallet_enabled() -> bool {
    std::env::var(SOVEREIGN_WALLET_ENVIRONMENT_VARIABLE).as_deref() == Ok("1")
}

/// Registers the sovereign wallet lane. Default OFF: a normal build launches
/// no sidecar, spawns no waved, and mints no invoices (design §7.1).
pub fn init(cx: &mut App) {
    if !sovereign_wallet_enabled() {
        return;
    }
    log::info!(
        "OMEGA_SOVEREIGN_WALLET=1: the sovereign wallet lane is enabled; \
         supervisor construction is wired by WP-5 (dashboard integration)"
    );
    let _ = cx;
}