//! Integration tests for the Omega ABI v0 conformance harness.
//!
//! Fixtures: a byte-identical copy of the white-label seed's
//! `manifest.json` + `plugin.wasm` (the committed placeholder seed — correct
//! for ABI conformance; identity checks are out of scope here).

use dvm_conformance_harness::abi::{OMEGA_ABI_V0_MARKER, check_abi_marker};
use dvm_conformance_harness::check::{load_manifest_for, run_conformance_check};
use dvm_conformance_harness::runtime::{WasmiReferenceRuntime, known_runtimes};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/white-label-seed");

fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(FIXTURE)
}

#[test]
fn template_plugin_passes_abi_v0_conformance_on_reference_runtime() {
    let dir = fixture_dir();
    let manifest = load_manifest_for(&dir).expect("load fixture manifest");
    let mut runtime = WasmiReferenceRuntime::new(&manifest.abi_alloc, &manifest.abi_entry);

    let report = run_conformance_check(
        &dir,
        &mut runtime,
        &serde_json::json!({ "text": "omega abi v0 conformance probe" }),
        None,
    )
    .expect("conformance check should run");

    assert_eq!(report.plugin, "white_label_seed");
    assert_eq!(report.runtime, "wasmi-reference");
    assert!(report.validated);
    assert!(report.static_contract.static_contract_ok, "static contract must pass");
    assert!(report.static_contract.marker_ok, "ABI marker must be present");
    assert_eq!(
        report.static_contract.marker.as_deref(),
        Some(OMEGA_ABI_V0_MARKER)
    );
    assert!(report.static_contract.memory_export_ok);
    assert!(report.conformance_pass, "template plugin must be conformant");

    // The probe must have captured a real output envelope (words/lines/chars/service).
    let out = &report.probe.output_json;
    assert!(out.get("words").is_some());
    assert!(out.get("lines").is_some());
    assert!(out.get("chars").is_some());
    assert!(out.get("service").is_some());
    assert!(report.probe.out_len > 0);
    assert_eq!(report.probe.header_hex.len(), 16, "8-byte result header");
}

#[test]
fn probe_output_matches_expected_fixture_byte_level() {
    let dir = fixture_dir();
    let manifest = load_manifest_for(&dir).expect("load fixture manifest");
    let mut runtime = WasmiReferenceRuntime::new(&manifest.abi_alloc, &manifest.abi_entry);

    let input = serde_json::json!({ "text": "alpha beta gamma" });
    let expected = serde_json::json!({
        "words": 3,
        "lines": 1,
        "chars": 16,
        "service": {
            "kind": 5900,
            "npub": "0000000000000000000000000000000000000000000000000000000000000000",
            "relays": []
        }
    });

    let report = run_conformance_check(&dir, &mut runtime, &input, Some(&expected))
        .expect("conformance check should run");
    assert_eq!(report.expected_match, Some(true), "expected output must match");
    assert!(report.conformance_pass);
}

#[test]
fn abi_marker_gate_refuses_missing_marker() {
    // The ABI policy gate (F-06/RV-M1-01 interim posture): a manifest without
    // the omega.sdk.abi marker is not conformant. The harness mirrors the host
    // gate; a missing marker fails `check_abi_marker` with the same wording.
    let dir = fixture_dir();
    let manifest = load_manifest_for(&dir).expect("load fixture manifest");
    // Sanity: the fixture DOES carry the marker (positive control).
    check_abi_marker(&manifest).expect("fixture must carry the ABI marker");

    // Build a manifest without the marker and assert the gate refuses it.
    let mut stripped = manifest.clone();
    if let Some(omega) = stripped.omega.as_mut() {
        omega.sdk = Some(serde_json::json!({ "lang": "rust", "target": "wasm32-unknown-unknown" }));
    }
    let err = check_abi_marker(&stripped).expect_err("missing marker must be refused");
    assert!(err.to_string().contains(OMEGA_ABI_V0_MARKER));
}

#[test]
fn known_runtimes_ships_reference_adapter() {
    let runtimes = known_runtimes();
    assert!(runtimes.contains(&"wasmi-reference"));
    assert!(runtimes.len() == 1, "only the reference adapter ships today");
}