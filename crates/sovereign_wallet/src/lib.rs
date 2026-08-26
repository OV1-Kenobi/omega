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
//! OFF), following the `market_ui` env-gate precedent. WP-5 wires the
//! construction site: when the gate is on, `init` constructs the shared
//! supervisor (the dashboard consumes it via [`shared_supervisor`]) and
//! kicks off the async start so the sidecar spawns in the running app.

mod client;
mod l402;
mod mandate;
mod protocol;
mod supervisor;
#[cfg(test)]
mod tests;

pub use client::SovereignWalletError;
pub use l402::{L402PayError, L402Proof, call_paid_route, pay_l402_challenge, parse_l402_challenge_body};
pub use mandate::{
    SOVEREIGN_WALLET_STRATEGY, authorize_sovereign_spend, sovereign_wallet_instruction,
    sovereign_wallet_mandate_candidate,
};
pub use protocol::{
    BalanceResult, CreateWalletResult, ErrorCode, ExportNostrSecretResult, HealthResult,
    IdentityStatusResult, InitializeResult, InvoiceResult, PayResult, PROTOCOL_SCHEMA,
    PROTOCOL_VERSION, SERVICE_VERSION, StatusResult, WalletState,
};
pub use supervisor::{
    SovereignWalletCommand, SovereignWalletSupervisor, SovereignWalletSupervisorOptions,
    default_options, fixture_command, fixture_command_with_network, fixture_node,
    resolve_sidecar_command, resolve_node_binary,
};

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use gpui::{App, Global};
use smol::lock::Mutex as AsyncMutex;

/// Environment gate for the sovereign wallet lane (market_ui precedent).
pub const SOVEREIGN_WALLET_ENVIRONMENT_VARIABLE: &str = "OMEGA_SOVEREIGN_WALLET";
/// The sidecar is only ever launched on signet or regtest (D4).
pub const SUPPORTED_NETWORKS: &[&str] = &["signet", "regtest"];
/// Optional override for the node binary used to launch the sidecar.
pub const NODE_BIN_ENVIRONMENT_VARIABLE: &str = "OMEGA_SOVEREIGN_WALLET_NODE_BIN";
/// Optional override for the sidecar network (defaults to signet).
pub const NETWORK_ENVIRONMENT_VARIABLE: &str = "OMEGA_SOVEREIGN_WALLET_NETWORK";
/// Optional override for the sidecar data root (defaults to
/// `<paths::data_dir()>/sovereign-wallet`).
pub const DATA_ROOT_ENVIRONMENT_VARIABLE: &str = "OMEGA_SOVEREIGN_WALLET_DATA_ROOT";

pub fn sovereign_wallet_enabled() -> bool {
    std::env::var(SOVEREIGN_WALLET_ENVIRONMENT_VARIABLE).as_deref() == Ok("1")
}

/// Shared handle to the app-wide sidecar supervisor (effectd pattern:
/// `Rc<AsyncMutex<Supervisor>>`, UI-thread affine).
pub type SharedSovereignWalletSupervisor = Rc<AsyncMutex<SovereignWalletSupervisor>>;

enum SovereignWalletRuntime {
    Available(SharedSovereignWalletSupervisor),
    Unavailable(Arc<str>),
}

impl Global for SovereignWalletRuntime {}

/// Registers the sovereign wallet lane. Default OFF: a normal build launches
/// no sidecar, spawns no waved, and mints no invoices (design §7.1).
///
/// WP-5 construction site: when the gate is ON, the supervisor is constructed
/// (config-level mainnet hard-bail included) and registered as a global, and
/// an async start is kicked off on the foreground executor so the sidecar
/// spawns in the running app. The flag-OFF path is byte-identical to today:
/// no global, no construction, no spawn.
pub fn init(cx: &mut App) {
    if !sovereign_wallet_enabled() {
        return;
    }
    if cx.has_global::<SovereignWalletRuntime>() {
        return;
    }
    let network = std::env::var(NETWORK_ENVIRONMENT_VARIABLE).unwrap_or_else(|_| "signet".to_owned());
    let data_root = std::env::var_os(DATA_ROOT_ENVIRONMENT_VARIABLE)
        .map(PathBuf::from)
        .unwrap_or_else(|| paths::data_dir().join("sovereign-wallet"));
    let node = std::env::var_os(NODE_BIN_ENVIRONMENT_VARIABLE)
        .map(PathBuf::from)
        .filter(|path| path.exists())
        .unwrap_or_else(fixture_node);
    let command = resolve_sidecar_command(&node);
    // Test-only knob: point the construction site at the protocol fixture so
    // the flag-ON path is testable without a built sidecar artifact.
    #[cfg(test)]
    let command = {
        if std::env::var_os("OMEGA_SOVEREIGN_WALLET_FIXTURE").is_some() {
            fixture_command(
                &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-fixtures/fixture-sidecar.mjs"),
            )
        } else {
            command
        }
    };

    let runtime = match SovereignWalletSupervisor::new(
        default_options(data_root, command, &network).expect("build sovereign wallet options"),
    ) {
        Ok(supervisor) => SovereignWalletRuntime::Available(Rc::new(AsyncMutex::new(supervisor))),
        Err(error) => SovereignWalletRuntime::Unavailable(error.to_string().into()),
    };
    cx.set_global(runtime);

    // Kick off the async start on the foreground executor (the supervisor is
    // `Rc`-based and UI-thread affine, so the background executor cannot take
    // it). The dashboard also calls `ensure_started` on first use, so a
    // failed start here is surfaced there as a named state, never a hang.
    if let Some(shared) = match cx.try_global::<SovereignWalletRuntime>() {
        Some(SovereignWalletRuntime::Available(shared)) => Some(shared.clone()),
        _ => None,
    } {
        cx.foreground_executor()
            .spawn(async move {
                match shared.lock().await.ensure_started().await {
                    Ok(_) => log::info!(
                        "sovereign wallet sidecar started under supervision (network signet/regtest only)"
                    ),
                    Err(error) => log::error!("sovereign wallet sidecar failed to start: {error:#}"),
                }
            })
            .detach();
    }
    log::info!(
        "OMEGA_SOVEREIGN_WALLET=1: the sovereign wallet lane is enabled; \
         supervisor constructed and sidecar start kicked off (WP-5 construction site)"
    );
}

/// Access the shared supervisor. `Err` when the lane is off, unavailable, or
/// not yet initialized — the dashboard renders that as a named state.
pub fn shared_supervisor(cx: &App) -> Result<SharedSovereignWalletSupervisor> {
    match cx.try_global::<SovereignWalletRuntime>() {
        Some(SovereignWalletRuntime::Available(supervisor)) => Ok(supervisor.clone()),
        Some(SovereignWalletRuntime::Unavailable(message)) => Err(anyhow!(message.to_string())),
        None => Err(anyhow!(
            "the sovereign wallet lane is off (OMEGA_SOVEREIGN_WALLET is not 1)"
        )),
    }
}

/// True when the shared supervisor exists (flag ON and constructed).
pub fn supervisor_available(cx: &App) -> bool {
    shared_supervisor(cx).is_ok()
}