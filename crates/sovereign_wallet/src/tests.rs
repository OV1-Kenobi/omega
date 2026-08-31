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
    default_options, fixture_command, fixture_command_with_network, fixture_node,
    sovereign_wallet_enabled,
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
    // OMEGA-DELTA-0286 (updated-with-citation): the refusal remains for the
    // UN-OPTED-IN case — `mainnet` construction requires
    // OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET=1 at the process level; without
    // it the exact refusal stays. The gated construction path is covered by
    // `supervisor_accepts_opted_in_mainnet_at_config` below.
    crate::test_support::assert_allow_mainnet_opt_in_absent(|| {
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
    });
}

#[test]
fn supervisor_accepts_opted_in_mainnet_at_config() {
    // OMEGA-DELTA-0286: with the explicit allow-mainnet opt-in at the
    // process level, a mainnet-configured supervisor constructs (the sidecar
    // env gate and the runtime assertion are covered by the sidecar suite).
    crate::test_support::with_allow_mainnet_opt_in(|| {
        let options = default_options(
            PathBuf::from(std::env::temp_dir()),
            fixture_command(&fixture_path()),
            "mainnet",
        )
        .unwrap();
        assert!(
            SovereignWalletSupervisor::new(options).is_ok(),
            "opted-in mainnet construction must succeed (OMEGA-DELTA-0286)"
        );
    });
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
        // SEC-2026-050 (OMEGA-DELTA-0286, updated-with-citation): the
        // supervisor refuses the initialize-reported network (waved's ACTUAL
        // runtime network from the sidecar probe), not just the env value.
        // A mainnet report on a SIGNET-configured supervisor is still a
        // hard bail — mainnet is accepted only when configured mainnet AND
        // opted in (covered by
        // `mainnet_runtime_report_is_accepted_when_configured_and_opted_in`).
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
fn mainnet_runtime_report_is_accepted_when_configured_and_opted_in() {
    // OMEGA-DELTA-0286: the SEC-2026-050 revision — reported network MUST
    // equal configured; a mainnet report is accepted ONLY when configured
    // mainnet AND the allow-mainnet opt-in is set at the process level.
    crate::test_support::with_allow_mainnet_opt_in(|| {
        smol::block_on(async {
            let mut supervisor = make_supervisor(
                "mainnet",
                fixture_command_with_network(&fixture_path(), "mainnet"),
            )
            .expect("supervisor");
            let initialize = supervisor.start().await.context("initialize").unwrap();
            assert_eq!(initialize.network, "mainnet");
            assert_eq!(initialize.waved_network.as_deref(), Some("mainnet"));
            assert_eq!(supervisor.network(), "mainnet");
            supervisor.stop().await.ok();
        });
    });
}

#[test]
fn unsupported_runtime_network_is_refused() {
    smol::block_on(async {
        // OMEGA-DELTA-0286 (updated-with-citation): the assertion is now
        // "reported MUST equal configured" — `testnet` remains unsupported
        // (a testnet report on a signet-configured supervisor is a mismatch,
        // refused; a testnet-configured supervisor cannot even be
        // constructed — the config gate refuses it).
        let mut supervisor =
            make_supervisor("signet", fixture_command_with_network(&fixture_path(), "testnet"))
                .expect("supervisor");
        let result = supervisor.start().await;
        assert!(
            result.is_err(),
            "a non-configured runtime network must be refused"
        );
        supervisor.stop().await.ok();
    });
}

#[test]
fn the_spend_kill_refuses_mint_and_pay_before_forwarding() {
    // OMEGA-DELTA-0300 (C2 semantics, SEC-2026-100): ALL-VALUE-TOUCHING —
    // when the kill is set, mint AND pay are both refused at the supervisor
    // choke point BEFORE the sidecar is touched (the fixture would answer
    // both; the refusal must happen first).
    smol::block_on(async {
        // The env is set ONLY for the construction window (the supervisor
        // reads OMEGA_SPEND_KILL once at construction); the policy snapshot
        // stays killed for the assertions.
        let mut supervisor = crate::test_support::with_spend_kill_env(|| {
            make_supervisor("signet", fixture_command(&fixture_path())).expect("supervisor")
        });
        supervisor.start().await.context("initialize").unwrap();

        let mint = supervisor
            .make_invoice(10, "killed mint", "kill-key-1")
            .await
            .expect_err("a killed surface must refuse minting");
        assert!(matches!(mint, SovereignWalletError::SpendHalted(_)), "{mint:?}");
        assert!(mint.to_string().contains("SPEND_HALTED"), "{mint}");

        let pay = supervisor
            .pay_invoice("lntbs10u1p0example", "kill-key-2")
            .await
            .expect_err("a killed surface must refuse paying");
        assert!(matches!(pay, SovereignWalletError::SpendHalted(_)), "{pay:?}");
        assert!(pay.to_string().contains("SPEND_HALTED"), "{pay}");

        supervisor.stop().await.ok();
    });
}

#[test]
fn the_daily_ceiling_refuses_an_over_limit_mint_and_allows_under_ceiling_flows() {
    // OMEGA-DELTA-0300: the per-surface daily ceiling (1,000 sats first
    // phase, reversible assumption) counts mints + payments on
    // `wallet-l402` and refuses BEFORE forwarding.
    smol::block_on(async {
        let mut supervisor =
            make_supervisor("signet", fixture_command(&fixture_path())).expect("supervisor");
        supervisor.start().await.context("initialize").unwrap();

        let over = supervisor
            .make_invoice(1_001, "over the ceiling", "ceiling-key-1")
            .await
            .expect_err("a mint above the daily ceiling must be refused");
        assert!(
            matches!(over, SovereignWalletError::SpendPolicyRefused(_)),
            "{over:?}"
        );
        assert!(over.to_string().contains("ceiling"), "{over}");

        // Under the ceiling: 999 + 1 = 1,000 passes; the next 1 sat refuses.
        supervisor
            .make_invoice(999, "within the ceiling", "ceiling-key-2")
            .await
            .expect("999 sats fits the ceiling");
        supervisor
            .make_invoice(1, "ceiling edge", "ceiling-key-3")
            .await
            .expect("exactly 1,000 sats fits the ceiling");
        let again = supervisor
            .make_invoice(1, "over the ceiling now", "ceiling-key-4")
            .await
            .expect_err("1,001 sats across the day must be refused");
        assert!(matches!(again, SovereignWalletError::SpendPolicyRefused(_)));

        supervisor.stop().await.ok();
    });
}

#[test]
fn over_settlement_auto_kills_the_surface_fail_closed() {
    // C3 / SEC-2026-098: the loss rule — a payment settling for MORE than
    // the prepared-for total auto-sets the kill fail-closed, reports the
    // named halted state, persists the kill, and refuses every later funded
    // flow (mint AND pay) until the founder re-enables.
    smol::block_on(async {
        let dir = tempdir().context("create temp data root").expect("tempdir");
        let options = SovereignWalletSupervisorOptions {
            data_root: dir.path().to_path_buf(),
            command: {
                let mut command = fixture_command(&fixture_path());
                command.args.push("--over-settle".to_owned());
                command
            },
            network: "signet".to_string(),
            initial_generation: 1,
            request_timeout: Duration::from_secs(10),
            node_require_minor: None,
        };
        let mut supervisor = SovereignWalletSupervisor::new(options).expect("supervisor");
        supervisor.start().await.context("initialize").unwrap();

        let over = supervisor
            .pay_invoice("lntbs10u1p0example", "loss-key-1")
            .await
            .expect_err("an over-settled payment must trip the loss rule");
        assert!(matches!(over, SovereignWalletError::SpendHalted(_)), "{over:?}");
        assert!(
            over.to_string().contains("over-settlement"),
            "the named halted state must name the trigger: {over}"
        );
        assert!(
            over.to_string().contains("Debug & Incident"),
            "the halted state must open the Debug & Incident route: {over}"
        );

        // The auto-kill is persisted (a restart cannot silently un-halt):
        // the budget file records the kill with the reason.
        let budget_path = dir.path().join("run").join(crate::spend_policy::SPEND_BUDGET_FILE_NAME);
        let raw = std::fs::read_to_string(&budget_path)
            .expect("the spend-budget file must exist after the loss rule fires");
        let state: serde_json::Value =
            serde_json::from_str(&raw).expect("the budget file must be valid JSON");
        assert_eq!(state["killed"], serde_json::json!(true));
        assert!(
            state["kill_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("over-settlement")),
            "the persisted kill must name the loss-rule reason: {raw}"
        );

        // Every later funded flow refuses (C2 all-value-touching).
        let mint = supervisor
            .make_invoice(10, "after loss", "loss-key-2")
            .await
            .expect_err("a killed surface must refuse minting after the loss rule");
        assert!(matches!(mint, SovereignWalletError::SpendHalted(_)));
        let pay = supervisor
            .pay_invoice("lntbs10u1p0example", "loss-key-3")
            .await
            .expect_err("a killed surface must refuse paying after the loss rule");
        assert!(matches!(pay, SovereignWalletError::SpendHalted(_)));

        supervisor.stop().await.ok();
    });
}

#[test]
fn wallet_height_round_trips_the_observed_daemon_tip() {
    // WP-4b (SEC-2026-087): the tip is read through the sidecar `wallet-height`
    // seam. Daemon-level: answers while the wallet surface is still untouched.
    smol::block_on(async {
        let mut supervisor = make_supervisor("signet", fixture_command(&fixture_path()))
            .expect("supervisor");
        supervisor.start().await.context("initialize handshake").unwrap();
        let height = supervisor.wallet_height().await.context("wallet height").unwrap();
        assert_eq!(height.block_height, 250_000);
        supervisor.stop().await.context("stop").unwrap();
    });
}

#[test]
fn wallet_height_unavailable_is_a_typed_fail_closed_error() {
    // WP-4b (SEC-2026-087): when the waved build does not serve the REST
    // getinfo surface (the pinned build's recorded posture), no tip exists —
    // the typed error forces the escrow caller to fail closed instead of
    // substituting wall-clock.
    smol::block_on(async {
        let command = {
            let mut command = fixture_command(&fixture_path());
            command.args.push("--no-wallet-height".to_owned());
            command
        };
        let mut supervisor = make_supervisor("signet", command).expect("supervisor");
        supervisor.start().await.context("initialize handshake").unwrap();
        let error = supervisor
            .wallet_height()
            .await
            .expect_err("the height probe must fail closed");
        match error {
            SovereignWalletError::Protocol { code, .. } => {
                assert_eq!(code, crate::ErrorCode::WavedHeightUnavailable);
            }
            other => panic!("expected a typed WavedHeightUnavailable error, got: {other:?}"),
        }
        supervisor.stop().await.context("stop").unwrap();
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

#[test]
fn crash_respawn_recovers_the_sidecar_and_increments_generation() {
    // WP-10 (QA condition 2 — the missing crash->respawn test): kill the
    // sidecar process mid-run BY PID, assert the supervisor respawns it, the
    // generation increments, and the protocol state is intact afterwards.
    smol::block_on(async {
        let mut supervisor = make_supervisor("signet", fixture_command(&fixture_path()))
            .expect("supervisor");
        let initialize = supervisor.start().await.context("initialize").unwrap();
        assert_eq!(initialize.generation, 1);
        assert_eq!(supervisor.generation(), 1);
        assert!(supervisor.health().await.context("health before crash").unwrap().ok);

        // The fixture wrote its own PID under the data root (kill-by-PID
        // discipline — never a blanket taskkill by image name).
        let pid_path = supervisor
            .data_root()
            .join("run/fixture.pid");
        let first_pid: u32 = std::fs::read_to_string(&pid_path)
            .context("read fixture pid")
            .expect("fixture pid")
            .trim()
            .parse()
            .expect("parse fixture pid");
        assert!(pid_alive(first_pid), "the fixture must be alive before the kill");

        // Kill the child EXTERNALLY (a crash, not a supervised stop).
        kill_pid(first_pid).expect("kill the sidecar child by pid");
        // Give the OS a moment to reap the process, then assert it is gone.
        for _ in 0..50 {
            if !pid_alive(first_pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!pid_alive(first_pid), "the killed child must actually be dead");

        // The supervisor's restart path: stop the dead child handle, bump the
        // generation, spawn a fresh child, and re-run the initialize handshake.
        let restarted = supervisor.restart().await.context("restart after crash").unwrap();
        assert_eq!(restarted.network, "signet");
        assert_eq!(supervisor.generation(), 2, "the crash->respawn must increment the generation");
        assert_eq!(restarted.generation, 2);

        // The respawned child is a NEW process, and the protocol state is
        // intact: health reports ready and balance still answers.
        let second_pid: u32 = std::fs::read_to_string(&pid_path)
            .context("read respawned fixture pid")
            .expect("respawned fixture pid")
            .trim()
            .parse()
            .expect("parse respawned fixture pid");
        assert_ne!(
            first_pid, second_pid,
            "the respawned sidecar must be a new process (first pid {first_pid}, second {second_pid})"
        );
        assert!(pid_alive(second_pid), "the respawned fixture must be alive");
        let health = supervisor.health().await.context("health after respawn").unwrap();
        assert!(health.ok, "the respawned sidecar must report healthy");
        assert_eq!(health.network, "signet");
        let balance = supervisor.balance().await.context("balance after respawn").unwrap();
        assert_eq!(balance.confirmed_sat, "12345", "state is intact after respawn");

        supervisor.stop().await.context("stop").unwrap();
        assert!(!pid_alive(second_pid), "the supervised stop must terminate the respawned child");
    });
}

/// True when a process with the given pid is alive (Windows + Unix).
fn pid_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        // tasklist is always present on Windows; a live process's line
        // contains the pid, a dead pid yields the "no tasks" notice.
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .expect("run tasklist");
        let text = String::from_utf8_lossy(&output.stdout);
        text.contains(&pid.to_string())
    }
    #[cfg(not(windows))]
    {
        unsafe {
            libc::kill(pid as i32, 0) == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        }
    }
}

/// Kill a process by pid: taskkill /T /F on Windows (tree kill, by PID only),
/// SIGKILL on Unix.
fn kill_pid(pid: u32) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let status = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "taskkill failed for pid {pid}: {status:?}"
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let result = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WP-5 construction site (design §7.1 + §6.1): the flag-ON path constructs
// the shared supervisor in the running app and spawns the sidecar; the
// flag-OFF path is byte-identical to today (no global, no spawn).
// ---------------------------------------------------------------------------

fn unset_construction_env() {
    unsafe {
        std::env::remove_var(crate::SOVEREIGN_WALLET_ENVIRONMENT_VARIABLE);
        std::env::remove_var(crate::NODE_BIN_ENVIRONMENT_VARIABLE);
        std::env::remove_var(crate::DATA_ROOT_ENVIRONMENT_VARIABLE);
        std::env::remove_var(crate::NETWORK_ENVIRONMENT_VARIABLE);
        std::env::remove_var("OMEGA_SOVEREIGN_WALLET_FIXTURE");
    }
}

#[gpui::test]
fn construction_is_inert_when_flag_off(cx: &mut gpui::TestAppContext) {
    cx.update(|cx| {
        unset_construction_env();
        crate::init(cx);
        assert!(
            !crate::supervisor_available(cx),
            "the flag-OFF path must not construct the supervisor"
        );
        assert!(
            crate::shared_supervisor(cx).is_err(),
            "the flag-OFF path must not register a runtime"
        );
    });
}

#[gpui::test]
async fn construction_spawns_the_sidecar_when_flag_on(cx: &mut gpui::TestAppContext) {
    let data_root = tempdir().expect("data root");
    cx.update(|cx| {
        unset_construction_env();
        unsafe {
            std::env::set_var(crate::SOVEREIGN_WALLET_ENVIRONMENT_VARIABLE, "1");
            std::env::set_var(crate::NODE_BIN_ENVIRONMENT_VARIABLE, fixture_node());
            std::env::set_var(crate::DATA_ROOT_ENVIRONMENT_VARIABLE, data_root.path());
            std::env::set_var("OMEGA_SOVEREIGN_WALLET_FIXTURE", "1");
        }
        crate::init(cx);
        assert!(
            crate::supervisor_available(cx),
            "the flag-ON path must construct the shared supervisor"
        );
        assert!(
            crate::shared_supervisor(cx).is_ok(),
            "the flag-ON path must register a runtime"
        );
    });
    // The construction site is real: the shared supervisor drives the typed
    // client against the spawned sidecar (initialize → health → balance).
    // The async drive happens on the smol runtime (parking allowed), NOT on
    // the gpui test scheduler (which forbids parking); the init's own
    // foreground spawn is left to teardown, where ensure_started is a no-op
    // once the child is already running.
    let supervisor = cx.update(|cx| crate::shared_supervisor(cx).expect("shared supervisor"));
    let balance = {
        let supervisor = supervisor.clone();
        smol::block_on(async move {
            let mut guard = supervisor.lock().await;
            guard.ensure_started().await.context("start via the construction site").unwrap();
            let health = guard.health().await.context("health").unwrap();
            assert!(health.ok, "the spawned sidecar must report healthy");
            guard.balance().await.context("balance").unwrap()
        })
    };
    assert_eq!(balance.confirmed_sat, "12345");
    // The shared supervisor is process-wide: a second access returns the SAME
    // instance (one Omega instance never spawns two sidecars).
    let again = cx.update(|cx| crate::shared_supervisor(cx).expect("shared supervisor again"));
    assert!(std::rc::Rc::ptr_eq(&supervisor, &again));
    drop(supervisor);
    drop(data_root);
    unset_construction_env();
}