//! Runtime-independent static checks for the declared Omega Plugin ABI v0.

use anyhow::{Context, Result};
use dvm_plugin_core::{Manifest, verify_abi_signatures};
use serde::Serialize;
use wasmi::ExternType;

/// The declared ABI marker every template plugin must carry.
pub const OMEGA_ABI_V0_MARKER: &str = "omega-plugin-abi-v0";

/// Runtime-independent ABI static contract report.
#[derive(Debug, Clone, Serialize)]
pub struct StaticAbiReport {
    pub marker: Option<String>,
    pub marker_ok: bool,
    pub alloc_export: String,
    pub alloc_signature_ok: bool,
    pub entry_export: String,
    pub entry_signature_ok: bool,
    pub memory_export_ok: bool,
    pub static_contract_ok: bool,
}

fn abi_marker(manifest: &Manifest) -> Option<String> {
    let sdk = manifest.omega.as_ref()?.sdk.as_ref()?;
    match sdk {
        serde_json::Value::Object(map) => map.get("abi").and_then(|v| v.as_str()).map(String::from),
        _ => None,
    }
}

/// Verify the runtime-independent ABI contract on a loaded module's exports.
///
/// Signature checks are delegated to the SHARED validator
/// (`dvm_plugin_core::verify_abi_signatures` — exact `(i32)->i32` /
/// `(i32,i32)->i32` / exported-memory), so this harness cannot disagree with
/// `dvm-plugin-cli` or the Omega host (WP-M2 condition CH-01/F-02).
pub fn check_static_contract(
    manifest: &Manifest,
    exports: &[(String, ExternType)],
) -> Result<StaticAbiReport> {
    let marker = abi_marker(manifest);
    let marker_ok = marker.as_deref() == Some(OMEGA_ABI_V0_MARKER);

    // The shared signature check enforces the exact ABI signatures and the
    // exported memory; a failure here is a hard contract violation.
    verify_abi_signatures(manifest, exports)
        .with_context(|| "ABI signature verification failed (shared validator)")?;

    let memory_ok = exports.iter().any(|(name, ty)| {
        name == "memory" && matches!(ty, ExternType::Memory(_))
    });

    let report = StaticAbiReport {
        marker,
        marker_ok,
        alloc_export: manifest.abi_alloc.clone(),
        alloc_signature_ok: true, // enforced by the shared validator above
        entry_export: manifest.abi_entry.clone(),
        entry_signature_ok: true, // enforced by the shared validator above
        memory_export_ok: memory_ok,
        static_contract_ok: marker_ok && memory_ok,
    };
    Ok(report)
}

/// Convenience: the marker check alone (used by the ABI policy gate in the
/// host; mirrored here so the harness surfaces the same policy).
pub fn check_abi_marker(manifest: &Manifest) -> Result<()> {
    if abi_marker(manifest).as_deref() != Some(OMEGA_ABI_V0_MARKER) {
        anyhow::bail!(
            "plugin does not declare omega.sdk.abi = '{OMEGA_ABI_V0_MARKER}' (ABI policy gate, F-06/RV-M1-01)"
        );
    }
    Ok(())
}