//! dvm-plugin-core — shared DVM plugin model, validator, and catalog reader.
//!
//! This crate is the SINGLE validator code path shared by construction between:
//! - `dvm-plugin-cli` (the authoring tool: inspect/test/install/list), and
//! - the Omega plugin host (`dvm-plugin-host`: catalog discovery, capability
//!   tool, runtime load).
//!
//! WP-M2 condition CH-01/F-02: the tool and the host cannot disagree because
//! both call the same functions in this crate.
//!
//! F-01 (path confinement) is implemented here as `confine_artifact_path`:
//! every read/write of a manifest-controlled path MUST go through it.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use wasmi::{Engine, ExternType, Module};
use wasmi::core::ValType;

// ---------------------------------------------------------------------------
// F-13: standing host-level default ceilings (03 §2.5 — host caps are the
// ceiling regardless of manifest claims)
// ---------------------------------------------------------------------------

/// Standing host ceiling for linear memory (MiB). The host caps the effective
/// limit at this value even when the manifest declares a higher bound, and a
/// manifest that omits `memory_max_mib` defaults to this ceiling. Template
/// plugins declare 64 MiB; 256 MiB is a generous but bounded ceiling against
/// attacker-chosen multi-GiB/TiB claims (F-13 remediation, founder decision 7).
pub const HOST_MAX_MEMORY_MIB: u64 = 256;

/// Standing host ceiling for wall-clock execution time (ms). The host caps
/// the effective limit at this value even when the manifest declares a longer
/// timeout, and a manifest that omits `timeout_ms` defaults to this ceiling.
/// 60 s bounds CPU resource use per run (the runtime's derived fuel budget is
/// proportional to this ceiling; the epoch watchdog hard-kills at it).
pub const HOST_MAX_TIMEOUT_MS: u64 = 60_000;

// ---------------------------------------------------------------------------
// Manifest model (openagents.plugin/v0 + omega delta)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manifest {
    pub schema: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub artifact_path: String,
    pub artifact_digest: String,
    pub abi_entry: String,
    pub abi_alloc: String,
    pub input_schema: serde_json::Value,
    pub output_schema: serde_json::Value,
    pub mounts: Vec<serde_json::Value>,
    pub hosts: Vec<String>,
    /// Execution time bound claimed by the manifest (the plugin's request).
    /// Optional since F-13: when omitted, the host's standing ceiling
    /// (`HOST_MAX_TIMEOUT_MS`) is the effective bound. Never a grant — the
    /// host caps at the ceiling regardless (03 §2.5).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Linear-memory bound claimed by the manifest (the plugin's request).
    /// Optional since F-13: when omitted, the host's standing ceiling
    /// (`HOST_MAX_MEMORY_MIB`) is the effective bound. Never a grant — the
    /// host caps at the ceiling regardless (03 §2.5).
    #[serde(default)]
    pub memory_max_mib: Option<u64>,
    #[serde(default)]
    pub omega: Option<OmegaDelta>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OmegaDelta {
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    #[serde(default)]
    pub cost_hint_msats: Option<u64>,
    #[serde(default)]
    pub service: Option<serde_json::Value>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub sdk: Option<serde_json::Value>,
}

/// A validated catalog entry (discovery row).
#[derive(Serialize, Debug, Clone)]
pub struct CatalogEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub tier: String,
    pub cost_hint_msats: u64,
    /// Digest re-verification state at listing time (F-10).
    pub digest_verified: bool,
    pub digest_error: Option<String>,
    /// Declared memory/time bounds from the manifest.
    pub timeout_ms: u64,
    pub memory_max_mib: u64,
}

/// Result of the full shared validator.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub manifest: Manifest,
    pub artifact_digest: String,
    pub imports: Vec<(String, String, ExternType)>,
    pub exports: Vec<(String, ExternType)>,
    pub tier: &'static str,
}

// ---------------------------------------------------------------------------
// Catalog location (spec: ~/.openagents/plugins, CODER_PLUGINS_DIR override)
// ---------------------------------------------------------------------------

pub fn catalog_dir() -> Result<PathBuf> {
    if let Ok(dir) = env::var("CODER_PLUGINS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = if cfg!(windows) {
        env::var("USERPROFILE").map_err(|_| anyhow!("USERPROFILE not set"))?
    } else {
        env::var("HOME").map_err(|_| anyhow!("HOME not set"))?
    };
    Ok(PathBuf::from(home).join(".openagents").join("plugins"))
}

// ---------------------------------------------------------------------------
// F-01: path confinement (mandatory fix, HIGH)
// ---------------------------------------------------------------------------

/// Confine a manifest-controlled `artifact_path` to a plain filename inside
/// `base`. Rejects:
/// - absolute paths,
/// - any `..` / parent component,
/// - any path with more than one component (subdirectories),
/// - empty or `.`-only names,
/// - Windows drive/prefix components.
///
/// Every read or write of a manifest-controlled path MUST be resolved through
/// this function before touching the filesystem (install copy, build copy,
/// digest read, host load).
pub fn confine_artifact_path(base: &Path, artifact_path: &str) -> Result<PathBuf> {
    if artifact_path.is_empty() {
        bail!("artifact_path must not be empty");
    }
    let raw = Path::new(artifact_path);
    if raw.is_absolute() {
        bail!("artifact_path must be a relative plain filename, got absolute: {artifact_path:?}");
    }
    let mut components = raw.components();
    let first = components
        .next()
        .ok_or_else(|| anyhow!("artifact_path must not be empty"))?;
    match first {
        Component::Normal(name) => {
            let name = name
                .to_str()
                .ok_or_else(|| anyhow!("artifact_path is not valid UTF-8: {artifact_path:?}"))?;
            if name.is_empty() || name == "." {
                bail!("artifact_path must be a plain filename, got: {artifact_path:?}");
            }
        }
        Component::ParentDir => {
            bail!(
                "artifact_path must not contain '..' (traversal rejected): {artifact_path:?}"
            );
        }
        Component::CurDir => bail!("artifact_path must be a plain filename: {artifact_path:?}"),
        Component::RootDir | Component::Prefix(_) => {
            bail!("artifact_path must be a relative plain filename: {artifact_path:?}")
        }
    }
    if components.next().is_some() {
        bail!(
            "artifact_path must be a plain filename (no subdirectories): {artifact_path:?}"
        );
    }
    // Resolve against the canonical base and verify the result stays inside
    // it. `canonicalize()` yields a verbatim `\\?\`-prefixed path on Windows;
    // joining against the canonical base (rather than the raw `base`) keeps
    // both sides of the containment check in the same prefix style, so a
    // plain filename inside the directory never fails spuriously.
    let canonical_base = base
        .canonicalize()
        .with_context(|| format!("cannot canonicalize base {}", base.display()))?;
    let resolved_abs = canonical_base.join(raw);
    if !resolved_abs.starts_with(&canonical_base) {
        bail!(
            "artifact_path resolves outside the plugin directory: {artifact_path:?}"
        );
    }
    Ok(resolved_abs)
}

/// Read the artifact bytes through the confined path (F-01 read path).
pub fn artifact_bytes(dir: &Path, manifest: &Manifest) -> Result<Vec<u8>> {
    let artifact_path = confine_artifact_path(dir, &manifest.artifact_path)?;
    fs::read(&artifact_path)
        .with_context(|| format!("cannot read artifact {}", artifact_path.display()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

pub fn verify_digest(dir: &Path, manifest: &Manifest) -> Result<()> {
    let expected = manifest
        .artifact_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("artifact_digest must be 'sha256:<hex>'"))?;
    let bytes = artifact_bytes(dir, manifest)?;
    let actual = sha256_hex(&bytes);
    if actual != expected {
        bail!(
            "digest mismatch for {}: manifest claims sha256:{}, artifact is sha256:{}",
            manifest.artifact_path,
            expected,
            actual
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Module inspection (wasmi) + ABI signature validation (F-05)
// ---------------------------------------------------------------------------

/// Load + validate the module, return (engine, module, imports, exports).
pub fn load_module(
    bytes: &[u8],
) -> Result<(
    Engine,
    Module,
    Vec<(String, String, ExternType)>,
    Vec<(String, ExternType)>,
)> {
    let engine = Engine::default();
    let module = Module::new(&engine, bytes).context("wasm module failed validation")?;
    let imports: Vec<(String, String, ExternType)> = module
        .imports()
        .map(|import| {
            (
                import.module().to_string(),
                import.name().to_string(),
                import.ty().clone(),
            )
        })
        .collect();
    let exports: Vec<(String, ExternType)> = module
        .exports()
        .map(|export| (export.name().to_string(), export.ty().clone()))
        .collect();
    Ok((engine, module, imports, exports))
}

fn func_sig(ty: &ExternType) -> Option<(Vec<ValType>, Vec<ValType>)> {
    match ty {
        ExternType::Func(func_ty) => Some((func_ty.params().to_vec(), func_ty.results().to_vec())),
        _ => None,
    }
}

/// F-05: verify the exact ABI signatures and exported memory shape.
/// Contract: `abi_alloc: (i32) -> i32`, `abi_entry: (i32, i32) -> i32`,
/// plus an exported `memory`.
pub fn verify_abi_signatures(
    manifest: &Manifest,
    exports: &[(String, ExternType)],
) -> Result<()> {
    let find_ty = |name: &str| -> Option<&ExternType> {
        exports.iter().find(|(n, _)| n == name).map(|(_, t)| t)
    };

    let alloc_ty = find_ty(&manifest.abi_alloc).ok_or_else(|| {
        anyhow!("missing required export '{}' (alloc)", manifest.abi_alloc)
    })?;
    match func_sig(alloc_ty) {
        Some((params, results)) if params == [ValType::I32] && results == [ValType::I32] => {}
        Some((params, results)) => bail!(
            "abi_alloc '{}' has wrong signature: expected (i32) -> i32, got ({:?}) -> {:?}",
            manifest.abi_alloc,
            params,
            results
        ),
        None => bail!("abi_alloc '{}' is not a function", manifest.abi_alloc),
    }

    let entry_ty = find_ty(&manifest.abi_entry).ok_or_else(|| {
        anyhow!("missing required export '{}' (entry)", manifest.abi_entry)
    })?;
    match func_sig(entry_ty) {
        Some((params, results))
            if params == [ValType::I32, ValType::I32] && results == [ValType::I32] => {}
        Some((params, results)) => bail!(
            "abi_entry '{}' has wrong signature: expected (i32, i32) -> i32, got ({:?}) -> {:?}",
            manifest.abi_entry,
            params,
            results
        ),
        None => bail!("abi_entry '{}' is not a function", manifest.abi_entry),
    }

    let memory_ty = find_ty("memory")
        .ok_or_else(|| anyhow!("missing required export 'memory'"))?;
    match memory_ty {
        ExternType::Memory(_) => {}
        _ => bail!("'memory' export is not a memory"),
    }

    Ok(())
}

/// F-03 (inspect half): the module's DECLARED memory maximum must not exceed
/// the manifest's `memory_max_mib`. Returns the declared maximum in bytes.
pub fn check_declared_memory_max(
    manifest: &Manifest,
    exports: &[(String, ExternType)],
) -> Result<u64> {
    let memory_ty = exports
        .iter()
        .find(|(n, _)| n == "memory")
        .map(|(_, t)| t)
        .ok_or_else(|| anyhow!("missing required export 'memory'"))?;
    let declared_max_pages = match memory_ty {
        ExternType::Memory(mem_ty) => mem_ty.maximum_pages(),
        _ => bail!("'memory' export is not a memory"),
    };
    // F-13: when the manifest omits `memory_max_mib` there is no declared
    // bound to compare against; the runtime limiter (host ceiling) is the
    // enforcement point. 0 = "no manifest-declared bound".
    let Some(manifest_mib) = manifest.memory_max_mib else {
        return Ok(0);
    };
    let bound_bytes = manifest_mib * 1024 * 1024;
    if let Some(max_pages) = declared_max_pages {
        let max_pages: u32 = max_pages.into();
        let max_bytes = u64::from(max_pages) * 65536;
        if max_bytes > bound_bytes {
            bail!(
                "module declares memory maximum {} bytes ({} pages), exceeding manifest memory_max_mib {} ({} bytes)",
                max_bytes,
                max_pages,
                manifest_mib,
                bound_bytes
            );
        }
        Ok(max_bytes)
    } else {
        // No declared maximum: the runtime limit is the enforcement point.
        Ok(bound_bytes)
    }
}

// ---------------------------------------------------------------------------
// Tier resolution + import/export validation (shared validator)
// ---------------------------------------------------------------------------

pub fn effective_tier(manifest: &Manifest) -> &'static str {
    if !manifest.hosts.is_empty() {
        "Hosts"
    } else if !manifest.mounts.is_empty() {
        "Mounts"
    } else {
        "PureCompute"
    }
}

pub fn validate_tier_and_imports(
    manifest: &Manifest,
    imports: &[(String, String, ExternType)],
) -> Result<()> {
    let tier = effective_tier(manifest);
    match tier {
        "Hosts" => bail!(
            "Hosts tier is BLOCKED by Omega policy: manifest declares hosts but the capability sandbox denies all network"
        ),
        "Mounts" => {
            for mount in &manifest.mounts {
                let ro = mount
                    .get("read_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !ro {
                    bail!("mounts must be read_only: true (found {mount})");
                }
            }
        }
        _ => {}
    }
    if let Some(omega) = &manifest.omega {
        if let Some(declared) = &omega.tier {
            if declared != tier {
                bail!(
                    "omega.tier '{declared}' understates effective tier '{tier}' — misdeclaration"
                );
            }
        }
    }
    if !imports.is_empty() {
        let names: Vec<String> = imports
            .iter()
            .map(|(m, n, _)| format!("{m}.{n}"))
            .collect();
        bail!(
            "plugin imports ambient capabilities {:?}; PureCompute/Mounts plugins must have zero imports",
            names
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// F-07: JSON Schema validation (draft-07 subset: type/properties/required/items)
// ---------------------------------------------------------------------------

/// Validate `value` against a draft-07 subset JSON Schema. The subset is
/// deliberate and documented in the manifest contract (01-manifest-schema.md):
/// `type`, `properties`, `required`, `items` (with nested type checks).
pub fn validate_json_schema(value: &serde_json::Value, schema: &serde_json::Value) -> Result<()> {
    if !schema.is_object() {
        bail!("schema must be a JSON Schema object");
    }
    let schema = schema.as_object().unwrap();

    if let Some(expected) = schema.get("type").and_then(|t| t.as_str()) {
        match expected {
            "object" => {
                if !value.is_object() {
                    bail!("expected object, got {}", json_type_name(value));
                }
            }
            "string" => {
                if !value.is_string() {
                    bail!("expected string, got {}", json_type_name(value));
                }
            }
            "integer" => {
                if !value.is_i64() && !value.is_u64() {
                    bail!("expected integer, got {}", json_type_name(value));
                }
            }
            "number" => {
                if !value.is_number() {
                    bail!("expected number, got {}", json_type_name(value));
                }
            }
            "array" => {
                if !value.is_array() {
                    bail!("expected array, got {}", json_type_name(value));
                }
            }
            "boolean" => {
                if !value.is_boolean() {
                    bail!("expected boolean, got {}", json_type_name(value));
                }
            }
            "null" => {
                if !value.is_null() {
                    bail!("expected null, got {}", json_type_name(value));
                }
            }
            other => bail!("unsupported schema type: {other:?}"),
        }
    }

    if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
        if let Some(obj) = value.as_object() {
            for (name, prop_schema) in props {
                if let Some(prop_value) = obj.get(name) {
                    validate_json_schema(prop_value, prop_schema)
                        .with_context(|| format!("property '{name}'"))?;
                }
            }
        }
    }

    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        let obj = value
            .as_object()
            .ok_or_else(|| anyhow!("expected object, got {}", json_type_name(value)))?;
        for name in required {
            let name = name
                .as_str()
                .ok_or_else(|| anyhow!("'required' entries must be strings"))?;
            if !obj.contains_key(name) {
                bail!("missing required property '{name}'");
            }
        }
    }

    if let Some(items) = schema.get("items") {
        if let Some(arr) = value.as_array() {
            for (i, item) in arr.iter().enumerate() {
                validate_json_schema(item, items).with_context(|| format!("items[{i}]"))?;
            }
        }
    }

    Ok(())
}

fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// Shared full validator (F-02 / CH-01)
// ---------------------------------------------------------------------------

/// Run the FULL validator: manifest schema, confined artifact read, digest,
/// module well-formedness, zero-import enforcement, exact ABI signatures,
/// declared memory maximum vs manifest bound, tier consistency, mounts
/// read-only, hosts blocked, schema well-formedness (input/output schemas must
/// themselves be objects).
///
/// This is the ONLY validation entry point used by:
/// - CLI `inspect` and `install` (F-02: install refuses anything that fails),
/// - the host load path (`dvm-plugin-host`).
pub fn validate_plugin(dir: &Path) -> Result<PluginInfo> {
    let manifest = load_manifest(dir)?;
    validate_manifest_schemas(&manifest)?;
    verify_digest(dir, &manifest)?;
    let bytes = artifact_bytes(dir, &manifest)?;
    let (_, _, imports, exports) = load_module(&bytes)?;
    validate_tier_and_imports(&manifest, &imports)?;
    verify_abi_signatures(&manifest, &exports)?;
    check_declared_memory_max(&manifest, &exports)?;
    let tier = effective_tier(&manifest);
    Ok(PluginInfo {
        manifest,
        artifact_digest: sha256_hex(&bytes),
        imports,
        exports,
        tier,
    })
}

/// The manifest's input/output schemas must themselves be well-formed JSON
/// Schema objects (F-07). Enforced at install/inspect/load time.
pub fn validate_manifest_schemas(manifest: &Manifest) -> Result<()> {
    if !manifest.input_schema.is_object() {
        bail!("input_schema must be a JSON Schema object");
    }
    if !manifest.output_schema.is_object() {
        bail!("output_schema must be a JSON Schema object");
    }
    Ok(())
}

pub fn load_manifest(dir: &Path) -> Result<Manifest> {
    let manifest_path = dir.join("manifest.json");
    let text = fs::read_to_string(&manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_str(&text)
        .with_context(|| format!("manifest.json is not valid: {}", manifest_path.display()))?;
    if manifest.schema != "openagents.plugin/v0" {
        bail!(
            "schema '{}' is not 'openagents.plugin/v0'",
            manifest.schema
        );
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Catalog discovery (F-10: list re-verifies digests)
// ---------------------------------------------------------------------------

/// List installed plugins, re-verifying each digest at listing time. Entries
/// that fail re-validation are still surfaced with `digest_verified=false`
/// and a reason — never silently dropped.
pub fn list_catalog() -> Result<Vec<CatalogEntry>> {
    let catalog = catalog_dir()?;
    if !catalog.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&catalog)? {
        let entry = entry?;
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let manifest_path = dir.join("manifest.json");
        if !manifest_path.exists() {
            continue;
        }
        let Ok(manifest) = load_manifest(&dir) else {
            // A manifest that cannot even parse is surfaced as a failed entry.
            entries.push(CatalogEntry {
                name: dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "<unknown>".into()),
                version: "<unparsed>".into(),
                description: "<manifest.json unreadable>".into(),
                capabilities: Vec::new(),
                tier: "<unreadable>".into(),
                cost_hint_msats: 0,
                digest_verified: false,
                digest_error: Some("manifest.json unreadable or invalid".into()),
                timeout_ms: 0,
                memory_max_mib: 0,
            });
            continue;
        };
        // F-10: re-verify the digest against the artifact bytes on disk.
        let (digest_verified, digest_error) = match verify_digest(&dir, &manifest) {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        let capabilities = manifest
            .omega
            .as_ref()
            .and_then(|o| o.capabilities.clone())
            .unwrap_or_default();
        let cost_hint_msats = manifest
            .omega
            .as_ref()
            .and_then(|o| o.cost_hint_msats)
            .unwrap_or(0);
        let tier = effective_tier(&manifest).to_string();
        entries.push(CatalogEntry {
            name: manifest.name,
            version: manifest.version,
            description: manifest.description,
            capabilities,
            tier,
            cost_hint_msats,
            digest_verified,
            digest_error,
            timeout_ms: manifest.timeout_ms.unwrap_or(0),
            memory_max_mib: manifest.memory_max_mib.unwrap_or(0),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}
