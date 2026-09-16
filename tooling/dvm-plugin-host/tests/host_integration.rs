//! Integration tests for dvm-plugin-host (WP-M2b acceptance evidence).
//!
//! These tests encode the acceptance criteria as repeatable checks:
//! - shared validator by construction (malformed/importing plugin refused at
//!   load with the SAME error the CLI produces),
//! - catalog discovery (list/find), inspection,
//! - capability execution with bounds: fuel-limited timeout, memory-limited
//!   termination, wall-clock hard kill (epoch),
//! - permission prompts: PureCompute auto, Mounts approval/denial, Hosts
//!   refused.
//!
//! Fixtures: the crate's `fixtures/spin_plugin` and the repo's
//! `plugins/dvm/white-label-seed`. A temp catalog is created per test via
//! `CODER_PLUGINS_DIR` pointing at the fixture installs.

use dvm_plugin_host::{
    Approval, RunOutcome, RunRequest, find_plugins, inspect_plugin, list_plugins, run_plugin,
    runtime::LimitsOverride,
};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // tests run with CWD = crate root (tooling/dvm-plugin-host)
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `CODER_PLUGINS_DIR` is process-global, so every test that touches the
/// catalog must hold this lock for its whole body to avoid parallel
/// cross-contamination. Poison-tolerant: a panicked test must not kill the
/// remaining tests.
fn catalog_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn seed_dir() -> PathBuf {
    // repo: plugins/dvm/white-label-seed (three levels up from the crate)
    let p = repo_root().join("..").join("..").join("plugins").join("dvm").join("white-label-seed");
    assert!(p.join("manifest.json").exists(), "seed fixture missing: {}", p.display());
    p
}

fn spin_dir() -> PathBuf {
    let p = repo_root().join("fixtures").join("spin_plugin");
    assert!(p.join("manifest.json").exists(), "spin fixture missing: {}", p.display());
    p
}

/// Create a temp catalog with the seed + spin plugins installed (via the
/// shared CLI install path, mirroring the real flow), then set CODER_PLUGINS_DIR.
fn setup_catalog(test_name: &str) -> PathBuf {
    let catalog = std::env::temp_dir()
        .join("opencode")
        .join(format!("wp-m2b-test-{test_name}-{}", std::process::id()));
    if catalog.exists() {
        std::fs::remove_dir_all(&catalog).unwrap();
    }
    std::fs::create_dir_all(&catalog).unwrap();
    install_into(&catalog, &seed_dir(), "white_label_seed");
    install_into(&catalog, &spin_dir(), "spin_plugin");
    std::env::set_var("CODER_PLUGINS_DIR", &catalog);
    catalog
}

/// Install a plugin dir into the catalog (shared validator gate; mirrors CLI
/// install semantics).
fn install_into(catalog: &Path, src: &Path, name: &str) {
    let dest = catalog.join(name);
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::copy(src.join("manifest.json"), dest.join("manifest.json")).unwrap();
    std::fs::copy(src.join("plugin.wasm"), dest.join("plugin.wasm")).unwrap();
    // Re-verify through the shared validator (digest + module shape).
    dvm_plugin_core::validate_plugin(&dest).expect("fixture must pass the shared validator");
}

fn temp_dir_cleanup(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}

// ---------------------------------------------------------------------------
// Discovery + inspection
// ---------------------------------------------------------------------------

#[test]
fn discovery_lists_catalog_and_resolves_tiers() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("discovery");
    let plugins = list_plugins().unwrap();
    assert_eq!(plugins.len(), 2, "expected seed + spin in catalog");
    let seed = plugins.iter().find(|p| p.name == "white_label_seed").expect("seed listed");
    assert!(seed.loadable);
    assert!(seed.digest_verified);
    assert_eq!(seed.tier, "PureCompute");
    assert!(seed.capabilities.contains(&"text/stats".to_string()));
    let spin = plugins.iter().find(|p| p.name == "spin_plugin").expect("spin listed");
    assert!(spin.loadable);
    assert_eq!(spin.tier, "PureCompute");
    temp_dir_cleanup(&catalog);
}

#[test]
fn find_filters_by_capability_and_name() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("find");
    let found = find_plugins("text/stats").unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "white_label_seed");
    let found = find_plugins("spin").unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "spin_plugin");
    let none = find_plugins("no-such-capability-xyz").unwrap();
    assert!(none.is_empty());
    temp_dir_cleanup(&catalog);
}

#[test]
fn inspect_reports_full_validation_and_digest() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("inspect");
    let insp = inspect_plugin("white_label_seed").unwrap();
    assert!(insp.loadable);
    assert!(insp.digest_verified);
    assert_eq!(insp.abi.entry, "_start");
    assert_eq!(insp.abi.alloc, "allocate");
    assert!(insp.imports.is_empty());
    assert_eq!(insp.tier, "PureCompute");
    temp_dir_cleanup(&catalog);
}

#[test]
fn inspect_missing_plugin_errors() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("inspect-missing");
    assert!(inspect_plugin("does_not_exist").is_err());
    temp_dir_cleanup(&catalog);
}

// ---------------------------------------------------------------------------
// Shared validator by construction (CH-01 / F-02)
// ---------------------------------------------------------------------------

#[test]
fn host_refuses_importing_plugin_with_same_error_as_cli() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("shared-validator");
    // Plant a valid module importing env.f directly in the catalog (bypasses
    // install; proves the host LOAD path is the gate).
    let imp_dir = catalog.join("imp_plugin");
    std::fs::create_dir_all(&imp_dir).unwrap();
    let wasm = [
        0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
        0x02, 0x09, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x01, 0x66, 0x00, 0x00, // import env.f
    ];
    std::fs::write(imp_dir.join("plugin.wasm"), wasm).unwrap();
    let digest = dvm_plugin_core::sha256_hex(&wasm);
    let manifest = serde_json::json!({
        "schema": "openagents.plugin/v0",
        "name": "imp_plugin",
        "version": "0.1.0",
        "description": "negative fixture: imports env.f",
        "artifact_path": "plugin.wasm",
        "artifact_digest": format!("sha256:{digest}"),
        "abi_entry": "_start",
        "abi_alloc": "allocate",
        "input_schema": { "type": "object" },
        "output_schema": { "type": "object" },
        "mounts": [],
        "hosts": [],
        "timeout_ms": 1000,
        "memory_max_mib": 64,
        "omega": { "schema": "omega.dvm-plugin/delta-v0", "capabilities": ["test/import"], "cost_hint_msats": 0, "tier": "PureCompute" }
    });
    std::fs::write(
        imp_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // The CLI's validator error (the "same code path" contract).
    let cli_error = dvm_plugin_core::validate_plugin(&imp_dir).unwrap_err().to_string();
    assert!(
        cli_error.contains("imports ambient capabilities"),
        "expected import rejection, got: {cli_error}"
    );

    // The host run must refuse with the SAME validator message.
    let req = RunRequest {
        plugin: "imp_plugin".into(),
        input: serde_json::json!({}),
        approval: Approval::Auto,
        limits_override: None,
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => {
            assert_eq!(e.code, "abi_error");
            assert_eq!(e.message, cli_error, "host and CLI must agree (shared validator)");
        }
        RunOutcome::Success(_) => panic!("importing plugin must NOT run"),
    }
    temp_dir_cleanup(&catalog);
}

// ---------------------------------------------------------------------------
// Bounds (F-03): fuel, memory, hard kill
// ---------------------------------------------------------------------------

#[test]
fn fuel_limited_run_terminates_with_timeout() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("fuel");
    let req = RunRequest {
        plugin: "spin_plugin".into(),
        input: serde_json::json!({ "text": "x" }),
        approval: Approval::Auto,
        limits_override: Some(LimitsOverride {
            memory_max_mib: None,
            timeout_ms: Some(60_000), // generous wall-clock; fuel is the bound
            fuel_budget: Some(5_000),
        }),
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => {
            assert_eq!(e.code, "timeout", "fuel exhaustion must map to timeout: {}", e.message);
            assert!(e.message.contains("fuel"), "message should name fuel: {}", e.message);
        }
        RunOutcome::Success(_) => panic!("spin plugin must not complete within a 5000-fuel budget"),
    }
    temp_dir_cleanup(&catalog);
}

#[test]
fn wall_clock_hard_kill_terminates_at_timeout() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("hardkill");
    let started = std::time::Instant::now();
    let req = RunRequest {
        plugin: "spin_plugin".into(),
        input: serde_json::json!({ "text": "x" }),
        approval: Approval::Auto,
        limits_override: Some(LimitsOverride {
            memory_max_mib: None,
            timeout_ms: Some(150),
            fuel_budget: Some(u64::MAX / 2), // generous; epoch is the bound
        }),
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => {
            assert_eq!(e.code, "timeout", "epoch hard kill must map to timeout: {}", e.message);
            assert!(e.message.contains("hard kill"), "message should name hard kill: {}", e.message);
        }
        RunOutcome::Success(_) => panic!("spin plugin must not outlive timeout_ms"),
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_millis() < 5_000,
        "hard kill must terminate promptly, took {elapsed:?}"
    );
    temp_dir_cleanup(&catalog);
}

#[test]
fn memory_limited_run_terminates_with_memory_exceeded() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("memory");
    // Seed's linear memory minimum (~17 pages = 1.06 MiB) exceeds a 1 MiB cap,
    // so instantiation itself must fail with memory_exceeded.
    let req = RunRequest {
        plugin: "white_label_seed".into(),
        input: serde_json::json!({ "text": "x" }),
        approval: Approval::Auto,
        limits_override: Some(LimitsOverride {
            memory_max_mib: Some(1),
            timeout_ms: Some(60_000),
            fuel_budget: None,
        }),
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => {
            assert_eq!(e.code, "memory_exceeded", "memory cap must map to memory_exceeded: {}", e.message);
        }
        RunOutcome::Success(_) => panic!("seed must not run under a 1 MiB memory cap"),
    }
    temp_dir_cleanup(&catalog);
}

// ---------------------------------------------------------------------------
// Permission tiers
// ---------------------------------------------------------------------------

#[test]
fn purecompute_runs_without_prompt() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("purecompute");
    let req = RunRequest {
        plugin: "white_label_seed".into(),
        input: serde_json::json!({ "text": "hello world\nsecond line" }),
        approval: Approval::Auto,
        limits_override: None,
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Success(r) => {
            assert!(r.ok);
            assert_eq!(r.tier, "PureCompute");
            assert_eq!(r.result["words"], 4);
            assert_eq!(r.result["lines"], 2);
            assert_eq!(r.result["chars"], 23);
        }
        RunOutcome::Failure(e) => panic!("PureCompute seed must auto-run, got: {} {}", e.code, e.message),
    }
    temp_dir_cleanup(&catalog);
}

#[test]
fn mounts_requires_approval() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("mounts");
    // Clone seed as a Mounts plugin in the catalog.
    let m_dir = catalog.join("mounts_plugin");
    std::fs::create_dir_all(&m_dir).unwrap();
    let seed_manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(seed_dir().join("manifest.json")).unwrap())
            .unwrap();
let mut m = seed_manifest.as_object().unwrap().clone();
    m.insert("name".into(), serde_json::json!("mounts_plugin"));
    m.insert(
        "mounts".into(),
        serde_json::json!([{ "path": "C:\\nonexistent\\dir", "read_only": true }]),
    );
    // The tier must be declared in the delta block (misdeclaration of a
    // Mounts plugin as PureCompute is itself a load rejection).
    let omega = m.get_mut("omega").unwrap().as_object_mut().unwrap();
    omega.insert("tier".into(), serde_json::json!("Mounts"));
    std::fs::write(
        m_dir.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::Value::Object(m)).unwrap(),
    )
    .unwrap();
    std::fs::copy(seed_dir().join("plugin.wasm"), m_dir.join("plugin.wasm")).unwrap();
    dvm_plugin_core::validate_plugin(&m_dir).expect("mounts fixture must pass shared validator");

    // Auto -> denied.
    let req = RunRequest {
        plugin: "mounts_plugin".into(),
        input: serde_json::json!({ "text": "x" }),
        approval: Approval::Auto,
        limits_override: None,
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => assert_eq!(e.code, "operator_denied"),
        RunOutcome::Success(_) => panic!("Mounts must not run without approval"),
    }
    // Explicit deny -> denied.
    let req = RunRequest {
        plugin: "mounts_plugin".into(),
        input: serde_json::json!({ "text": "x" }),
        approval: Approval::Denied,
        limits_override: None,
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => assert_eq!(e.code, "operator_denied"),
        RunOutcome::Success(_) => panic!("Mounts must not run when denied"),
    }
    // Approved -> runs.
    let req = RunRequest {
        plugin: "mounts_plugin".into(),
        input: serde_json::json!({ "text": "x" }),
        approval: Approval::Granted,
        limits_override: None,
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Success(r) => assert!(r.ok),
        RunOutcome::Failure(e) => panic!("approved Mounts must run, got: {} {}", e.code, e.message),
    }
    temp_dir_cleanup(&catalog);
}

#[test]
fn hosts_refused_at_load() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("hosts");
    // Clone seed as a Hosts plugin (declares an outbound host).
    let h_dir = catalog.join("hosts_plugin");
    std::fs::create_dir_all(&h_dir).unwrap();
    let seed_manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(seed_dir().join("manifest.json")).unwrap())
            .unwrap();
let mut h = seed_manifest.as_object().unwrap().clone();
    h.insert("name".into(), serde_json::json!("hosts_plugin"));
    h.insert("hosts".into(), serde_json::json!(["https://example.com"]));
    // The delta tier must agree with the effective tier (Hosts).
    let omega = h.get_mut("omega").unwrap().as_object_mut().unwrap();
    omega.insert("tier".into(), serde_json::json!("Hosts"));
    std::fs::write(
        h_dir.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::Value::Object(h)).unwrap(),
    )
    .unwrap();
    std::fs::copy(seed_dir().join("plugin.wasm"), h_dir.join("plugin.wasm")).unwrap();
    // Hosts is refused by the shared validator itself (hosts -> load refusal).
    assert!(dvm_plugin_core::validate_plugin(&h_dir).is_err());

    let req = RunRequest {
        plugin: "hosts_plugin".into(),
        input: serde_json::json!({ "text": "x" }),
        approval: Approval::Auto,
        limits_override: None,
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => assert_eq!(e.code, "tier_denied"),
        RunOutcome::Success(_) => panic!("Hosts tier must be refused"),
    }
    temp_dir_cleanup(&catalog);
}

#[test]
fn abi_policy_gate_refuses_plugins_without_omega_abi_marker() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("abi-policy");
    // Clone the seed without the omega.sdk ABI marker (F-06: the host loads
    // only plugins declaring the Omega ABI v0 marker until RV-M1-01 resolves).
    let d = catalog.join("no_abi_marker");
    std::fs::create_dir_all(&d).unwrap();
    let seed_manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(seed_dir().join("manifest.json")).unwrap())
            .unwrap();
    let mut m = seed_manifest.as_object().unwrap().clone();
    m.insert("name".into(), serde_json::json!("no_abi_marker"));
    m.get_mut("omega").unwrap().as_object_mut().unwrap().remove("sdk");
    std::fs::write(
        d.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::Value::Object(m)).unwrap(),
    )
    .unwrap();
    std::fs::copy(seed_dir().join("plugin.wasm"), d.join("plugin.wasm")).unwrap();

    let req = RunRequest {
        plugin: "no_abi_marker".into(),
        input: serde_json::json!({ "text": "x" }),
        approval: Approval::Auto,
        limits_override: None,
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => {
            assert_eq!(e.code, "abi_error");
            assert!(
                e.message.contains("omega.sdk.abi"),
                "policy refusal must name the marker: {}",
                e.message
            );
        }
        RunOutcome::Success(_) => panic!("plugin without the Omega ABI marker must not load"),
    }
    temp_dir_cleanup(&catalog);
}

#[test]
fn input_schema_validated_before_execution() {
    let _guard = catalog_guard();
    let catalog = setup_catalog("schema");
    let req = RunRequest {
        plugin: "white_label_seed".into(),
        input: serde_json::json!({ "no_text": 1 }),
        approval: Approval::Auto,
        limits_override: None,
    };
    match run_plugin(&req).unwrap() {
        RunOutcome::Failure(e) => {
            assert_eq!(e.code, "input_invalid");
            assert!(e.message.contains("missing required property 'text'"));
        }
        RunOutcome::Success(_) => panic!("input violating input_schema must not execute"),
    }
    temp_dir_cleanup(&catalog);
}
