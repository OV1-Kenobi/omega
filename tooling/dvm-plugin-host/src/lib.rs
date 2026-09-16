//! dvm-plugin-host — Omega DVM plugin host (WP-M2b).
//!
//! The host exposes the `capability` tool contract from the WP-M1 catalog
//! contract (03-catalog-and-capability-tool.md):
//!
//! - **discovery** (`list` / `find`) — reads the catalog manifests, resolves
//!   tiers, never executes a plugin.
//! - **inspection** (`inspect`) — runs the SAME shared validator as the CLI
//!   (`dvm_plugin_core::validate_plugin`), re-verifies the SHA-256 digest, and
//!   reports ABI/import/tier/schema details.
//! - **execution** (`run`) — validates input against `input_schema`, executes
//!   in a fresh wasmtime instance with enforced memory/time bounds (see
//!   `runtime`), validates the output against `output_schema`, and returns the
//!   structured answer envelope.
//!
//! Permission model (per WP-M1 02-permission-tiers.md):
//! - PureCompute: runs automatically (no prompt).
//! - Mounts: operator approval required before every run; `Approval::Denied`
//!   yields `operator_denied`.
//! - Hosts: refused load (`tier_denied`) — the shared validator also rejects
//!   any manifest declaring hosts.
//!
//! Error codes (per the 03 contract): `not_found`, `digest_mismatch`,
//! `tier_denied`, `operator_denied`, `input_invalid`, `timeout`,
//! `memory_exceeded`, `abi_error`, `output_invalid`, `internal`.

use anyhow::{bail, Result};
use dvm_plugin_core::{
    CatalogEntry, HOST_MAX_MEMORY_MIB, HOST_MAX_TIMEOUT_MS, OmegaDelta, PluginInfo, artifact_bytes,
    catalog_dir, effective_tier, load_manifest, validate_json_schema, validate_plugin, verify_digest,
};
use serde::Serialize;
use std::path::PathBuf;

pub mod runtime;

// ---------------------------------------------------------------------------
// Capability tool surface
// ---------------------------------------------------------------------------

/// A catalog row with host load-readiness (F-10 re-validation, F-02 surface).
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredPlugin {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub tier: String,
    pub cost_hint_msats: u64,
    pub digest_verified: bool,
    pub digest_error: Option<String>,
    /// Full shared-validator pass at discovery time. False = not loadable.
    pub loadable: bool,
    pub load_error: Option<String>,
    pub timeout_ms: u64,
    pub memory_max_mib: u64,
}

impl From<CatalogEntry> for DiscoveredPlugin {
    fn from(e: CatalogEntry) -> Self {
        DiscoveredPlugin {
            name: e.name,
            version: e.version,
            description: e.description,
            capabilities: e.capabilities,
            tier: e.tier,
            cost_hint_msats: e.cost_hint_msats,
            digest_verified: e.digest_verified,
            digest_error: e.digest_error,
            loadable: false,
            load_error: None,
            timeout_ms: e.timeout_ms,
            memory_max_mib: e.memory_max_mib,
        }
    }
}

/// Full inspection report (03 §2.3 shape).
#[derive(Debug, Clone, Serialize)]
pub struct Inspection {
    pub name: String,
    pub version: String,
    pub description: String,
    pub artifact_digest: String,
    pub digest_verified: bool,
    pub abi: AbiInfo,
    pub imports: Vec<String>,
    pub tier: String,
    pub mounts: Vec<serde_json::Value>,
    pub hosts: Vec<String>,
    pub timeout_ms: u64,
    pub memory_max_mib: u64,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    pub omega: Option<OmegaDelta>,
    pub loadable: bool,
    pub load_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AbiInfo {
    pub entry: String,
    pub alloc: String,
}

/// Operator approval state for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    /// No explicit operator decision. PureCompute proceeds; Mounts is denied.
    Auto,
    /// Operator approved the run (used for Mounts).
    Granted,
    /// Operator denied the run (Mounts).
    Denied,
}

/// A capability execution request.
#[derive(Debug, Clone)]
pub struct RunRequest {
    pub plugin: String,
    pub input: serde_json::Value,
    pub approval: Approval,
    /// Optional host-level ceilings overriding the manifest's declared values
    /// (host caps are the ceiling regardless of manifest claims, per 03 §2.5).
    /// `None` fields fall back to the manifest values, and the standing host
    /// ceilings (F-13) cap the effective limits in every case — including an
    /// operator override above the ceiling.
    pub limits_override: Option<runtime::LimitsOverride>,
}

/// Successful structured answer envelope (03 §2.4).
#[derive(Debug, Clone, Serialize)]
pub struct RunReport {
    pub ok: bool,
    pub plugin: String,
    pub version: String,
    pub tier: String,
    pub elapsed_ms: u128,
    pub result: serde_json::Value,
}

/// Capability error with a machine-readable code (03 §2.4 error list).
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityError {
    pub code: &'static str,
    pub message: String,
}

impl CapabilityError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        CapabilityError {
            code,
            message: message.into(),
        }
    }
}

/// Envelope returned to a caller: success report or structured error.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum RunOutcome {
    Success(RunReport),
    Failure(CapabilityError),
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// WP-M2 host policy marker (F-06 / RV-M1-01): the Omega Plugin ABI v0.
///
/// The shared validator cannot PROVE ABI conformance (the digest pin proves
/// byte identity, not calling-convention conformance). Until byte-exact
/// conformance to the real Coder/OpenAgents runtime is verified (RV-M1-01,
/// deadline WP-M4 publish), the host loads ONLY plugins that declare this ABI
/// marker in `omega.sdk.abi`. This is a POLICY gate, explicitly not proof.
pub const OMEGA_ABI: &str = "omega-plugin-abi-v0";

/// Enforce the WP-M2 ABI policy gate. Returns `Err(reason)` when the manifest
/// does not declare the Omega ABI v0 marker.
fn check_abi_policy(manifest: &dvm_plugin_core::Manifest) -> Result<(), String> {
    let declared = manifest
        .omega
        .as_ref()
        .and_then(|o| o.sdk.as_ref())
        .and_then(|s| s.get("abi"))
        .and_then(|v| v.as_str());
    match declared {
        Some(abi) if abi == OMEGA_ABI => Ok(()),
        Some(other) => Err(format!(
            "omega.sdk.abi '{other}' is not the declared Omega ABI '{OMEGA_ABI}' \
             (WP-M2 host policy, F-06/RV-M1-01: only template-built plugins load)"
        )),
        None => Err(format!(
            "plugin does not declare omega.sdk.abi = '{OMEGA_ABI}' \
             (WP-M2 host policy, F-06/RV-M1-01: only template-built plugins load)"
        )),
    }
}

/// Resolve the plugin directory for a plugin name, confined to the catalog.
fn plugin_dir(name: &str) -> Result<PathBuf> {
    if name.is_empty() || name == "." || name == ".." {
        bail!("plugin name is not a safe directory name");
    }
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
            bail!("plugin name '{name}' contains non-ASCII-alphanumeric character {c:?}");
        }
    }
    Ok(catalog_dir()?.join(name))
}

/// `capability(operation: "list")` — discovery reads manifests only.
pub fn list_plugins() -> Result<Vec<DiscoveredPlugin>> {
    let entries = dvm_plugin_core::list_catalog()?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        // F-12: the discovery join is confined EXACTLY like the run path
        // (`plugin_dir`'s name check). `manifest.name` is a display field
        // only — a manifest-controlled name containing path traversal
        // (`..\x`, `../x`, absolute, or any non-safe character) is refused
        // here (entry marked not-loadable with the confinement error) and is
        // never joined onto the catalog path. The plugin is never read from
        // outside the catalog.
        let dir = match plugin_dir(&e.name) {
            Ok(dir) => dir,
            Err(reason) => {
                let mut d: DiscoveredPlugin = e.into();
                d.loadable = false;
                d.load_error = Some(reason.to_string());
                out.push(d);
                continue;
            }
        };
        let (loadable, load_error) = match validate_plugin(&dir) {
            // The ABI policy gate is part of host loadability (F-06).
            Ok(info) => match check_abi_policy(&info.manifest) {
                Ok(()) => (true, None),
                Err(reason) => (false, Some(reason)),
            },
            Err(err) => (false, Some(err.to_string())),
        };
        let mut d: DiscoveredPlugin = e.into();
        d.loadable = loadable;
        d.load_error = load_error;
        out.push(d);
    }
    Ok(out)
}

/// `capability(operation: "find", query: ...)` — filter by tag/name/description.
pub fn find_plugins(query: &str) -> Result<Vec<DiscoveredPlugin>> {
    let q = query.to_lowercase();
    Ok(list_plugins()?
        .into_iter()
        .filter(|p| {
            p.name.to_lowercase().contains(&q)
                || p.description.to_lowercase().contains(&q)
                || p
                    .capabilities
                    .iter()
                    .any(|c| c.to_lowercase().contains(&q))
        })
        .collect())
}

/// `capability(operation: "inspect", plugin: ...)` — full validation report.
pub fn inspect_plugin(name: &str) -> Result<Inspection> {
    let dir = plugin_dir(name)?;
    if !dir.exists() {
        bail!("plugin '{name}' not found in catalog {}", catalog_dir()?.display());
    }
    // Digest first so a tamper is reported as digest_mismatch distinctly.
    let manifest = load_manifest(&dir)?;
    let digest_verified = verify_digest(&dir, &manifest).is_ok();
    let info: PluginInfo = match validate_plugin(&dir) {
        Ok(info) => info,
        Err(err) => {
            // Build the report from the manifest we already parsed so the
            // inspection still surfaces what we know (F-10 style).
            let imports = Vec::new();
            let abi = AbiInfo {
                entry: manifest.abi_entry.clone(),
                alloc: manifest.abi_alloc.clone(),
            };
            return Ok(Inspection {
                name: manifest.name.clone(),
                version: manifest.version.clone(),
                description: manifest.description.clone(),
                artifact_digest: manifest.artifact_digest.clone(),
                digest_verified,
                abi,
                imports,
                tier: effective_tier(&manifest).to_string(),
                mounts: manifest.mounts.clone(),
                hosts: manifest.hosts.clone(),
                // Declared bounds for display; 0 = not declared in manifest
                // (F-13: the effective run limits are the host ceilings).
                timeout_ms: manifest.timeout_ms.unwrap_or(0),
                memory_max_mib: manifest.memory_max_mib.unwrap_or(0),
                input_schema: manifest.input_schema.clone(),
                output_schema: manifest.output_schema.clone(),
                omega: manifest.omega.clone(),
                loadable: false,
                load_error: Some(err.to_string()),
            });
        }
    };
    let imports: Vec<String> = info
        .imports
        .iter()
        .map(|(m, n, _)| format!("{m}.{n}"))
        .collect();
    // F-06: the ABI policy gate is part of host loadability.
    let (loadable, load_error) = match check_abi_policy(&info.manifest) {
        Ok(()) => (true, None),
        Err(reason) => (false, Some(reason)),
    };
    Ok(Inspection {
        name: info.manifest.name.clone(),
        version: info.manifest.version.clone(),
        description: info.manifest.description.clone(),
        artifact_digest: info.artifact_digest.clone(),
        digest_verified,
        abi: AbiInfo {
            entry: info.manifest.abi_entry.clone(),
            alloc: info.manifest.abi_alloc.clone(),
        },
        imports,
        tier: info.tier.to_string(),
        mounts: info.manifest.mounts.clone(),
        hosts: info.manifest.hosts.clone(),
        // Declared bounds for display; 0 = not declared in manifest (F-13:
        // the effective run limits are the host ceilings).
        timeout_ms: info.manifest.timeout_ms.unwrap_or(0),
        memory_max_mib: info.manifest.memory_max_mib.unwrap_or(0),
        input_schema: info.manifest.input_schema.clone(),
        output_schema: info.manifest.output_schema.clone(),
        omega: info.manifest.omega.clone(),
        loadable,
        load_error,
    })
}

// ---------------------------------------------------------------------------
// Execution (capability run)
// ---------------------------------------------------------------------------

/// Resolve the effective runtime limits for a run (F-13 / 03 §2.5).
///
/// Order: the operator `limits_override` takes precedence over the manifest
/// claim; the STANDING HOST CEILING caps the result in every case. A manifest
/// that omits a bound (or an operator that provides no override) defaults to
/// the ceiling. The ceiling therefore binds manifest claims AND operator
/// overrides — raising it is a host policy change, never a per-run argument.
pub fn resolve_limits(
    override_: Option<&runtime::LimitsOverride>,
    manifest: &dvm_plugin_core::Manifest,
) -> runtime::RuntimeLimits {
    let requested_memory = override_
        .and_then(|o| o.memory_max_mib)
        .or(manifest.memory_max_mib);
    let requested_timeout = override_
        .and_then(|o| o.timeout_ms)
        .or(manifest.timeout_ms);
    runtime::RuntimeLimits {
        memory_max_mib: requested_memory
            .unwrap_or(HOST_MAX_MEMORY_MIB)
            .min(HOST_MAX_MEMORY_MIB),
        timeout_ms: requested_timeout
            .unwrap_or(HOST_MAX_TIMEOUT_MS)
            .min(HOST_MAX_TIMEOUT_MS),
        // Fuel is operator-only (the manifest has no fuel field) and is
        // bounded in wall-clock effect by the capped timeout's epoch hard
        // kill (WP-M2b bounds implementation: fuel + epoch).
        fuel_budget: override_.and_then(|o| o.fuel_budget),
    }
}

/// `capability(operation: "run", plugin: ..., input: ...)`.
///
/// The full gate: resolve by name -> shared validator (same as inspect/install)
/// -> tier + permission -> input schema -> bounded execution -> output schema.
pub fn run_plugin(req: &RunRequest) -> Result<RunOutcome> {
    let dir = plugin_dir(&req.plugin)?;
    if !dir.exists() {
        return Ok(RunOutcome::Failure(CapabilityError::new(
            "not_found",
            format!(
                "plugin '{}' not found in catalog {}",
                req.plugin,
                catalog_dir()?.display()
            ),
        )));
    }

    // Shared validator by construction: the host load path calls the SAME
    // function as inspect/install. A malformed/importing/tampered plugin is
    // refused here, before any runtime instantiation.
    let info = match validate_plugin(&dir) {
        Ok(info) => info,
        Err(err) => {
            let msg = err.to_string();
            let code = if msg.contains("digest mismatch") {
                "digest_mismatch"
            } else if msg.contains("Hosts tier is BLOCKED") {
                "tier_denied"
            } else if msg.contains("imports ambient capabilities")
                || msg.contains("wrong signature")
                || msg.contains("missing required export")
                || msg.contains("wasm module failed validation")
            {
                "abi_error"
            } else {
                "internal"
            };
            return Ok(RunOutcome::Failure(CapabilityError::new(code, msg)));
        }
    };
    let manifest = &info.manifest;
    let tier = info.tier;

    // WP-M2 ABI policy gate (F-06 / RV-M1-01): only plugins declaring the
    // Omega ABI v0 marker load until real-runtime conformance is verified.
    if let Err(reason) = check_abi_policy(manifest) {
        return Ok(RunOutcome::Failure(CapabilityError::new("abi_error", reason)));
    }

    // Tier + permission gate (02-permission-tiers.md).
    match (tier, req.approval) {
        ("Hosts", _) => {
            return Ok(RunOutcome::Failure(CapabilityError::new(
                "tier_denied",
                "Hosts tier is BLOCKED by Omega policy",
            )))
        }
        ("Mounts", Approval::Denied) | ("Mounts", Approval::Auto) => {
            return Ok(RunOutcome::Failure(CapabilityError::new(
                "operator_denied",
                format!(
                    "operator approval required for Mounts plugin '{}' (mounts: {:?})",
                    req.plugin, manifest.mounts
                ),
            )))
        }
        _ => {}
    }

    // Input schema validation (F-07 at the host).
    if let Err(e) = validate_json_schema(&req.input, &manifest.input_schema) {
        return Ok(RunOutcome::Failure(CapabilityError::new(
            "input_invalid",
            format!("input fails input_schema: {e}"),
        )));
    }

    // F-13 (03 §2.5): resolve effective limits — the operator override takes
    // precedence over the manifest claim, and the STANDING HOST CEILING caps
    // both. A manifest that omits a bound defaults to the ceiling.
    let limits = resolve_limits(req.limits_override.as_ref(), manifest);

    let bytes = match artifact_bytes(&dir, manifest) {
        Ok(b) => b,
        Err(e) => {
            return Ok(RunOutcome::Failure(CapabilityError::new("internal", e.to_string())))
        }
    };

    let input_json = match serde_json::to_vec(&req.input) {
        Ok(v) => v,
        Err(e) => {
            return Ok(RunOutcome::Failure(CapabilityError::new(
                "input_invalid",
                format!("cannot serialize input: {e}"),
            )))
        }
    };

    let started = std::time::Instant::now();
    let out_bytes = match runtime::execute(&bytes, &input_json, manifest, &limits) {
        Ok(b) => b,
        Err(failure) => {
            return Ok(RunOutcome::Failure(CapabilityError::new(
                failure.code(),
                failure.message().to_string(),
            )))
        }
    };
    let elapsed_ms = started.elapsed().as_millis();

    // Output schema validation (F-07 at the host).
    let output: serde_json::Value = match serde_json::from_slice(&out_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Ok(RunOutcome::Failure(CapabilityError::new(
                "output_invalid",
                format!("plugin output is not valid JSON: {e}"),
            )))
        }
    };
    if let Err(e) = validate_json_schema(&output, &manifest.output_schema) {
        return Ok(RunOutcome::Failure(CapabilityError::new(
            "output_invalid",
            format!("output fails output_schema: {e}"),
        )));
    }

    Ok(RunOutcome::Success(RunReport {
        ok: true,
        plugin: manifest.name.clone(),
        version: manifest.version.clone(),
        tier: tier.to_string(),
        elapsed_ms,
        result: output,
    }))
}