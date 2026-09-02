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
/// OMEGA-DELTA-0302: the NIP-AC authority projection (WP-11 design note
/// §2-§5, §6, §7, §10-§13) — flag-gated OFF, read-only over the stores,
/// emitting only after the local decision, and kind-limited to
/// 39242/39243/39244/1985. Public so the wired lanes (l402 here, market_ui
/// escrow) can reach the emission seam.
pub mod nipac;
mod protocol;
mod spend_policy;
mod supervisor;
#[cfg(test)]
mod tests;

pub use client::SovereignWalletError;
pub use l402::{L402PayError, L402Proof, call_paid_route, pay_l402_challenge, parse_l402_challenge_body};
pub use mandate::{
    SOVEREIGN_WALLET_STRATEGY, authorize_sovereign_spend, sovereign_wallet_instruction,
    sovereign_wallet_mandate_candidate, sovereign_wallet_network,
};
pub use protocol::{
    BalanceResult, BlockHeightResult, CreateWalletResult, ErrorCode, ExportNostrSecretResult,
    HealthResult, IdentityStatusResult, InitializeResult, InvoiceResult, PayResult,
    PROTOCOL_SCHEMA, PROTOCOL_VERSION, SERVICE_VERSION, StatusResult, WalletState,
};
/// WP-7: the spend-policy projection types + the enforced-surface name and
/// the default ceiling, consumed by the operator surface (sovereign_dashboard).
pub use spend_policy::{
    DAILY_CEILING_SATS, SURFACE_WALLET_L402, SpendPolicySnapshot, SurfaceSpendSnapshot,
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
/// The sidecar runs on signet, regtest, or mainnet — mainnet ONLY with the
/// explicit allow-mainnet opt-in (OMEGA-DELTA-0286); the supervisor config
/// gate and the sidecar env gate both enforce it.
pub const SUPPORTED_NETWORKS: &[&str] = &["signet", "regtest", "mainnet"];
/// OMEGA-DELTA-0286: the explicit mainnet opt-in env name (mirrors waved's
/// `--allow-mainnet`). `OMEGA_SOVEREIGN_WALLET_NETWORK=mainnet` is refused
/// without this at the supervisor config gate AND the sidecar env gate.
pub const ALLOW_MAINNET_ENVIRONMENT_VARIABLE: &str = "OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET";
/// OMEGA-DELTA-0300 (Decision 4): the environment-level spend kill. When
/// "1", every funded flow through the supervisor client refuses BEFORE
/// touching the sidecar; only the founder re-enables. Defined in
/// `spend_policy` (the 0300 check binds the name there); re-exported here
/// for the supervisor's construction gate.
pub const SPEND_KILL_ENVIRONMENT_VARIABLE: &str = spend_policy::SPEND_KILL_ENVIRONMENT_VARIABLE;
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

/// OMEGA-DELTA-0286: test support shared by the crate's test modules. The
/// allow-mainnet opt-in env is process-global, so tests that set it (the
/// gated-mainnet paths) and tests that assert its absence (the inherited
/// refusal paths) are serialized on one lock — a parallel race would make
/// either side flaky.
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) static MAINNET_OPT_IN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    pub(crate) static SPEND_KILL_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    pub(crate) static NIPAC_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Run `run` with the allow-mainnet opt-in env set (serialized), then
    /// remove it. The unsafe env mutation matches the crate's existing test
    /// style (edition-2024 env API).
    pub(crate) fn with_allow_mainnet_opt_in<T>(run: impl FnOnce() -> T) -> T {
        let _guard = MAINNET_OPT_IN_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            std::env::set_var(crate::ALLOW_MAINNET_ENVIRONMENT_VARIABLE, "1");
        }
        let result = run();
        unsafe {
            std::env::remove_var(crate::ALLOW_MAINNET_ENVIRONMENT_VARIABLE);
        }
        result
    }

    /// Run `run` with the allow-mainnet opt-in env guaranteed ABSENT
    /// (serialized) — the inherited un-opted-in refusal paths use this so a
    /// concurrently-running gated test cannot make them flaky.
    pub(crate) fn assert_allow_mainnet_opt_in_absent<T>(run: impl FnOnce() -> T) -> T {
        let _guard = MAINNET_OPT_IN_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            std::env::remove_var(crate::ALLOW_MAINNET_ENVIRONMENT_VARIABLE);
        }
        run()
    }

    /// Run `run` with OMEGA_SPEND_KILL=1 set (serialized), then remove it.
    /// Keep the closure as short as possible — the env is process-global and
    /// a concurrently-running test that constructs a supervisor would observe
    /// the kill.
    pub(crate) fn with_spend_kill_env<T>(run: impl FnOnce() -> T) -> T {
        let _guard = SPEND_KILL_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            std::env::set_var(crate::SPEND_KILL_ENVIRONMENT_VARIABLE, "1");
        }
        let result = run();
        unsafe {
            std::env::remove_var(crate::SPEND_KILL_ENVIRONMENT_VARIABLE);
        }
        result
    }

    /// OMEGA-DELTA-0302: run `run` with the NIP-AC projection env state
    /// exactly as requested (serialized on one lock — the flag and the relay
    /// URL are process-global and a concurrently-running test constructing a
    /// projection would race). `flag` = `Some(value)` sets
    /// `OMEGA_NIPAC_PROJECTION` to that exact value (the tests exercise "1"
    /// and "0"); `None` guarantees it ABSENT. `relay` does the same for
    /// `OMEGA_NIPAC_RELAY_URL` (only ever None in this crate's tests — the
    /// URL value itself is founder-held at activation and never committed).
    /// Both envs are removed before returning.
    pub(crate) fn with_nipac_projection_env<T>(
        flag: Option<&str>,
        relay: Option<&str>,
        run: impl FnOnce() -> T,
    ) -> T {
        let _guard = NIPAC_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match flag {
            Some(value) => unsafe {
                std::env::set_var(crate::nipac::NIPAC_PROJECTION_ENVIRONMENT_VARIABLE, value);
            },
            None => unsafe {
                std::env::remove_var(crate::nipac::NIPAC_PROJECTION_ENVIRONMENT_VARIABLE);
            },
        }
        match relay {
            Some(value) => unsafe {
                std::env::set_var(crate::nipac::NIPAC_RELAY_URL_ENVIRONMENT_VARIABLE, value);
            },
            None => unsafe {
                std::env::remove_var(crate::nipac::NIPAC_RELAY_URL_ENVIRONMENT_VARIABLE);
            },
        }
        let result = run();
        unsafe {
            std::env::remove_var(crate::nipac::NIPAC_PROJECTION_ENVIRONMENT_VARIABLE);
            std::env::remove_var(crate::nipac::NIPAC_RELAY_URL_ENVIRONMENT_VARIABLE);
        }
        result
    }
}