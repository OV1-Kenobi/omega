//! Supervisor integration tests: spawn a fixture sidecar (JS) over the framed
//! protocol and drive the typed client. Covers: initialize handshake, health,
//! balance round-trip, mainnet hard-bail at config AND at startup
//! (SEC-2026-050), generation fencing, and the default-OFF flag gate.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use tempfile::tempdir;

use crate::client::SovereignWalletError;
use crate::{
    SovereignWalletCommand, SovereignWalletSupervisor, SovereignWalletSupervisorOptions,
    default_options, fixture_command, fixture_command_with_network, sovereign_wallet_enabled,
};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-fixtures/fixture-sidecar.mjs")
}

fn make_supervisor(network: &str, command: SovereignWalletCommand) -> Result<SovereignWalletSupervisor> {
    let dir = tempdir().context("create temp data root")?;
    let options = SovereignWalletSupervisorOptions {
        data_root: dir.path().to_path_buf(),
        command,
        network: network.to_string(),
        initial_generation: 1,
        request_timeout: Duration::from_secs(10),
        node_require_minor: None,
    };
    SovereignWalletSupervisor::new(options)
}

#[test]
fn flag_is_off_by_default() {
    // The gate follows the market_ui precedent: absent env == OFF.
    unsafe {
        std::env::remove_var("OMEGA_SOVEREIGN_WALLET");
    }
    assert!(!sovereign_wallet_enabled());
    unsafe {
        std::env::set_var("OMEGA_SOVEREIGN_WALLET", "1");
    }
    assert!(sovereign_wallet_enabled());
    unsafe {
        std::env::set_var("OMEGA_SOVEREIGN_WALLET", "0");
    }
    assert!(!sovereign_wallet_enabled());
    unsafe {
        std::env::remove_var("OMEGA_SOVEREIGN_WALLET");
    }
}

#[test]
fn supervisor_refuses_mainnet_at_config() {
    let options = default_options(
        PathBuf::from(std::env::temp_dir()),
        fixture_command(&fixture_path()),
        "mainnet",
    )
    .unwrap();
    let error = SovereignWalletSupervisor::new(options)
        .err()
        .expect("construction with mainnet must fail");
    assert!(
        error.to_string().contains("mainnet"),
        "expected a mainnet refusal, got: {error}"
    );
}

#[test]
fn initialize_health_balance_round_trip() {
    smol::block_on(async {
        let mut supervisor = make_supervisor("signet", fixture_command(&fixture_path()))
            .expect("supervisor");
        let initialize = supervisor.start().await.context("initialize handshake").unwrap();
        assert_eq!(initialize.network, "signet");
        assert_eq!(initialize.waved_network.as_deref(), Some("signet"));
        assert_eq!(initialize.protocol_version, 1);

        let health = supervisor.health().await.context("health").unwrap();
        assert!(health.ok);
        assert_eq!(health.network, "signet");
        assert!(health.waved_connected);

        let status = supervisor.status().await.context("status").unwrap();
        assert_eq!(status.network, "signet");
        assert_eq!(status.vault_state, "absent");

        let balance = supervisor.balance().await.context("balance").unwrap();
        assert_eq!(balance.confirmed_sat, "12345");

        let shutdown = supervisor.shutdown().await.context("shutdown").unwrap();
        assert_eq!(
            shutdown.get("stopping").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        supervisor.stop().await.context("stop").unwrap();
    });
}

#[test]
fn mainnet_runtime_report_is_a_hard_bail() {
    smol::block_on(async {
        // SEC-2026-050: the supervisor refuses the initialize-reported
        // network (waved's ACTUAL runtime network from the sidecar probe),
        // not just the env value. The fixture reports mainnet here.
        let mut supervisor =
            make_supervisor("signet", fixture_command_with_network(&fixture_path(), "mainnet"))
                .expect("supervisor");
        let result = supervisor.start().await;
        let error = result.unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("MAINNET_REFUSED") || text.contains("mainnet"),
            "expected a mainnet refusal, got: {text}"
        );
        // The child must be torn down after the bail: ensure_started cannot
        // silently keep a running child (it would re-spawn the same mainnet
        // fixture and refuse again).
        assert!(
            supervisor.ensure_started().await.is_err(),
            "no sidecar may be running after a mainnet hard-bail"
        );
    });
}

#[test]
fn unsupported_runtime_network_is_refused() {
    smol::block_on(async {
        let mut supervisor =
            make_supervisor("signet", fixture_command_with_network(&fixture_path(), "testnet"))
                .expect("supervisor");
        let result = supervisor.start().await;
        assert!(
            result.is_err(),
            "a non-signet/regtest runtime network must be refused"
        );
        supervisor.stop().await.ok();
    });
}

#[test]
fn protocol_error_mapping_is_typed() {
    smol::block_on(async {
        let mut supervisor = make_supervisor("signet", fixture_command(&fixture_path()))
            .expect("supervisor");
        supervisor.start().await.context("initialize handshake").unwrap();
        let result = supervisor
            .request("status", None, 999)
            .await
            .expect_err("a stale generation must be refused");
        match result {
            SovereignWalletError::StaleGeneration => {}
            other => panic!("expected the dedicated StaleGeneration variant, got: {other:?}"),
        }
        supervisor.stop().await.ok();
    });
}