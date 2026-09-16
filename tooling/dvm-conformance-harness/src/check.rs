//! Full conformance check: shared validation + static ABI contract + byte-level
//! probe through a runtime + optional expected-fixture comparison.

use anyhow::{Context, Result};
use dvm_plugin_core::{
    Manifest, PluginInfo, artifact_bytes, load_manifest, load_module, validate_plugin,
};
use serde::Serialize;

use crate::abi::{StaticAbiReport, check_static_contract};
use crate::probe::{ProbeOutput, run_probe};
use crate::runtime::AbiRuntime;

#[derive(Debug, Clone, Serialize)]
pub struct ConformanceReport {
    pub plugin_dir: String,
    pub plugin: String,
    pub version: String,
    pub runtime: String,
    pub validated: bool,
    pub static_contract: StaticAbiReport,
    pub probe: ProbeOutput,
    pub expected_match: Option<bool>,
    pub conformance_pass: bool,
}

/// Run the full conformance check against a plugin directory.
///
/// `expected` is optional: when supplied, the probe's parsed output is
/// compared against it with structural JSON equality (byte-level on the
/// canonical JSON object). The probe output bytes are captured in the report
/// regardless, so a future real-runtime run can be compared byte-for-byte
/// against the reference baseline.
pub fn run_conformance_check(
    dir: &std::path::Path,
    runtime: &mut dyn AbiRuntime,
    input: &serde_json::Value,
    expected: Option<&serde_json::Value>,
) -> Result<ConformanceReport> {
    // Shared validator first: digest, imports, tier, schemas, ABI signatures —
    // the exact gate the CLI and the Omega host enforce (CH-01/F-02).
    let info: PluginInfo = validate_plugin(dir)
        .with_context(|| format!("shared validation failed for {}", dir.display()))?;
    let manifest: &Manifest = &info.manifest;

    let bytes = artifact_bytes(dir, manifest).context("read artifact bytes")?;
    let (_engine, _module, _, exports) = load_module(&bytes).context("load module")?;

    // Runtime-independent ABI static contract (marker + exact signatures +
    // exported memory). Signature enforcement is delegated to the shared
    // validator's verify_abi_signatures inside check_static_contract.
    let static_contract = check_static_contract(manifest, &exports)
        .with_context(|| "static ABI contract check failed")?;

    // Load the runtime and run the byte-level probe.
    runtime.load(&bytes).context("runtime load failed")?;
    let probe = run_probe(runtime, input).context("ABI probe failed")?;

    let expected_match = expected.map(|e| e == &probe.output_json);

    let conformance_pass = info.tier == "PureCompute"
        && static_contract.static_contract_ok
        && expected_match.unwrap_or(true);

    Ok(ConformanceReport {
        plugin_dir: dir.display().to_string(),
        plugin: manifest.name.clone(),
        version: manifest.version.clone(),
        runtime: runtime.name().to_string(),
        validated: true,
        static_contract,
        probe,
        expected_match,
        conformance_pass,
    })
}

/// Load a manifest alone (used by the CLI to resolve alloc/entry names before
/// constructing the runtime adapter).
pub fn load_manifest_for(dir: &std::path::Path) -> Result<Manifest> {
    load_manifest(dir)
}