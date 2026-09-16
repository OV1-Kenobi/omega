//! dvm-plugin-cli — Omega DVM plugin authoring tool (WP-M1).
//!
//! Command surface mirrors `coder-cli plugin`:
//!   init / build / inspect / test / install / list
//!
//! Contract source: openagents.plugin/v0 + Omega delta layer
//! (see planning/2026/09-september/15-plan-omega-dvm-marketplace/wp-m1-output/).

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use wasmi::{Engine, ExternType, Linker, Module, Store};

// ---------------------------------------------------------------------------
// Manifest model (openagents.plugin/v0 + omega delta)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Manifest {
    schema: String,
    name: String,
    version: String,
    description: String,
    artifact_path: String,
    artifact_digest: String,
    abi_entry: String,
    abi_alloc: String,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    mounts: Vec<serde_json::Value>,
    hosts: Vec<String>,
    timeout_ms: u64,
    memory_max_mib: u64,
    #[serde(default)]
    omega: Option<OmegaDelta>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct OmegaDelta {
    #[serde(default)]
    schema: Option<String>,
    #[serde(default)]
    capabilities: Option<Vec<String>>,
    #[serde(default)]
    cost_hint_msats: Option<u64>,
    #[serde(default)]
    service: Option<serde_json::Value>,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    sdk: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "dvm-plugin-cli",
    version,
    about = "Omega DVM plugin authoring tool (WP-M1): init/build/inspect/test/install/list"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scaffold a new plugin directory from the white-label seed template.
    Init { name: String },
    /// Build the Wasm artifact and pin the SHA-256 digest into manifest.json.
    Build { dir: PathBuf },
    /// Validate manifest, digest, imports, exports, tier consistency.
    Inspect { dir: PathBuf },
    /// Run test fixtures against the compiled artifact.
    Test { dir: PathBuf },
    /// Install the built plugin into the catalog (~/.openagents/plugins).
    Install { dir: PathBuf },
    /// List installed plugins in the catalog.
    List,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { name } => cmd_init(&name),
        Commands::Build { dir } => cmd_build(&dir),
        Commands::Inspect { dir } => cmd_inspect(&dir, false),
        Commands::Test { dir } => cmd_test(&dir),
        Commands::Install { dir } => cmd_install(&dir),
        Commands::List => cmd_list(),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn catalog_dir() -> Result<PathBuf> {
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

fn load_manifest(dir: &Path) -> Result<Manifest> {
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

fn artifact_bytes(dir: &Path, manifest: &Manifest) -> Result<Vec<u8>> {
    let artifact_path = dir.join(&manifest.artifact_path);
    fs::read(&artifact_path)
        .with_context(|| format!("cannot read artifact {}", artifact_path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

fn verify_digest(dir: &Path, manifest: &Manifest) -> Result<()> {
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

/// Load + validate the module, return (engine, module, imports, exports).
fn load_module(bytes: &[u8]) -> Result<(Engine, Module, Vec<(String, String, ExternType)>, Vec<(String, ExternType)>)> {
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

fn effective_tier(manifest: &Manifest) -> &'static str {
    if !manifest.hosts.is_empty() {
        "Hosts"
    } else if !manifest.mounts.is_empty() {
        "Mounts"
    } else {
        "PureCompute"
    }
}

fn validate_tier_and_imports(manifest: &Manifest, imports: &[(String, String, ExternType)]) -> Result<()> {
    let tier = effective_tier(manifest);
    match tier {
        "Hosts" => bail!(
            "Hosts tier is BLOCKED by Omega policy (WP-M1): manifest declares hosts but the capability sandbox denies all network"
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

fn require_export<'a>(
    exports: &'a [(String, ExternType)],
    name: &str,
    kind: &str,
) -> Result<&'a ExternType> {
    exports
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, t)| t)
        .ok_or_else(|| anyhow!("missing required export '{name}' ({kind})"))
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

const TEMPLATE_CARGO_TOML: &str = r#"[package]
name = "{{pkg_name}}"
version = "0.1.0"
edition = "2021"
description = "DVM plugin scaffolded from white-label-seed (WP-M1)"
license = "GPL-3.0-or-later"

[workspace]

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1", default-features = false, features = ["derive"] }
serde_json = { version = "1", default-features = false, features = ["alloc"] }

[profile.release]
opt-level = "s"
lto = true
panic = "abort"
"#;

const TEMPLATE_LIB_RS: &str = include_str!("template_lib.rs");

fn cmd_init(name: &str) -> Result<()> {
    let normalized: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect::<String>()
        .to_lowercase();
    if normalized.is_empty() {
        bail!("plugin name must contain at least one alphanumeric character");
    }
    let dir = PathBuf::from(&normalized);
    if dir.exists() {
        bail!("directory '{}' already exists", dir.display());
    }
    let src_dir = dir.join("src");
    let fixtures_dir = dir.join("tests").join("fixtures");
    fs::create_dir_all(&src_dir)?;
    fs::create_dir_all(&fixtures_dir)?;

    let pkg_name = normalized.replace('_', "-");
    let cargo_toml = TEMPLATE_CARGO_TOML.replace("{{pkg_name}}", &pkg_name);
    fs::write(dir.join("Cargo.toml"), cargo_toml)?;
    fs::write(src_dir.join("lib.rs"), TEMPLATE_LIB_RS)?;
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "openagents.plugin/v0",
            "name": normalized,
            "version": "0.1.0",
            "description": "DVM plugin scaffolded from the white-label seed (WP-M1).",
            "artifact_path": "plugin.wasm",
            "artifact_digest": "sha256:<set-by-build>",
            "abi_entry": "_start",
            "abi_alloc": "allocate",
            "input_schema": { "type": "object", "properties": { "text": { "type": "string" } }, "required": ["text"] },
            "output_schema": { "type": "object", "properties": { "words": { "type": "integer" }, "lines": { "type": "integer" }, "chars": { "type": "integer" } }, "required": ["words", "lines", "chars"] },
            "mounts": [],
            "hosts": [],
            "timeout_ms": 1000,
            "memory_max_mib": 64,
            "omega": { "schema": "omega.dvm-plugin/delta-v0", "capabilities": ["text/stats"], "cost_hint_msats": 0, "tier": "PureCompute", "sdk": { "lang": "rust", "target": "wasm32-unknown-unknown", "abi": "omega-plugin-abi-v0" } }
        }))
        .with_context(|| "serialize manifest template")?,
    )?;
    fs::write(
        fixtures_dir.join("basic.json"),
        r#"{ "input": { "text": "hello world\nsecond line" }, "expect": { "words": 4, "lines": 2, "chars": 23 } }"#,
    )?;
    fs::write(
        fixtures_dir.join("empty.json"),
        r#"{ "input": { "text": "" }, "expect": { "words": 0, "lines": 0, "chars": 0 } }"#,
    )?;

    println!(
        "init: created {} (run: dvm-plugin-cli build {})",
        dir.display(),
        dir.display()
    );
    Ok(())
}

fn cmd_build(dir: &Path) -> Result<()> {
    let manifest = load_manifest(dir)?;
    println!("build: compiling {} ({})", manifest.name, dir.display());

    // Ensure the wasm target is installed (idempotent; no-op when present).
    // Standard local toolchain operation — the build itself stays local.
    let target_status = std::process::Command::new("rustup")
        .args(["target", "add", "wasm32-unknown-unknown"])
        .current_dir(dir)
        .status()
        .context("failed to run rustup target add wasm32-unknown-unknown")?;
    if !target_status.success() {
        bail!("rustup target add wasm32-unknown-unknown failed with status {target_status}");
    }

    let status = std::process::Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
        .current_dir(dir)
        .status()
        .context("failed to run cargo build")?;
    if !status.success() {
        bail!("cargo build failed with status {status}");
    }

    let release_dir = dir.join("target").join("wasm32-unknown-unknown").join("release");
    let mut wasm_files: Vec<PathBuf> = fs::read_dir(&release_dir)
        .with_context(|| format!("no build output at {}", release_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "wasm").unwrap_or(false))
        .collect();
    if wasm_files.is_empty() {
        bail!("no .wasm artifact found in {}", release_dir.display());
    }
    wasm_files.sort();
    let wasm_path = wasm_files.last().unwrap().clone();
    let artifact_path = dir.join(&manifest.artifact_path);
    fs::copy(&wasm_path, &artifact_path)
        .with_context(|| format!("copy {} -> {}", wasm_path.display(), artifact_path.display()))?;

    let bytes = fs::read(&artifact_path)?;
    let digest = sha256_hex(&bytes);
    let pinned = format!("sha256:{digest}");

    let mut manifest = manifest;
    manifest.artifact_digest = pinned.clone();
    let text = serde_json::to_string_pretty(&manifest)?;
    fs::write(dir.join("manifest.json"), text)?;

    println!("build: pinned {} -> {}", manifest.artifact_path, pinned);
    Ok(())
}

fn cmd_inspect(dir: &Path, quiet: bool) -> Result<()> {
    let manifest = load_manifest(dir)?;
    verify_digest(dir, &manifest)?;
    let bytes = artifact_bytes(dir, &manifest)?;
    let (_, _, imports, exports) = load_module(&bytes)?;
    validate_tier_and_imports(&manifest, &imports)?;

    let entry_ty = require_export(&exports, &manifest.abi_entry, "entry")?;
    if !matches!(entry_ty, ExternType::Func(_)) {
        bail!("abi_entry '{}' is not a function", manifest.abi_entry);
    }
    let alloc_ty = require_export(&exports, &manifest.abi_alloc, "alloc")?;
    if !matches!(alloc_ty, ExternType::Func(_)) {
        bail!("abi_alloc '{}' is not a function", manifest.abi_alloc);
    }
    require_export(&exports, "memory", "memory")?;

    if !quiet {
        let capabilities = manifest
            .omega
            .as_ref()
            .and_then(|o| o.capabilities.as_ref())
            .cloned()
            .unwrap_or_default()
            .join(",");
        println!("inspect: OK");
        println!("  name           : {}", manifest.name);
        println!("  version        : {}", manifest.version);
        println!("  schema         : {}", manifest.schema);
        println!("  artifact       : {} ({})", manifest.artifact_path, manifest.artifact_digest);
        println!("  abi            : entry={} alloc={}", manifest.abi_entry, manifest.abi_alloc);
        println!("  tier           : {} (mounts={} hosts={})", effective_tier(&manifest), manifest.mounts.len(), manifest.hosts.len());
        println!("  capabilities   : {}", capabilities);
        println!("  cost_hint_msats: {}", manifest.omega.as_ref().and_then(|o| o.cost_hint_msats).unwrap_or(0));
        println!("  timeout_ms     : {}", manifest.timeout_ms);
        println!("  memory_max_mib : {}", manifest.memory_max_mib);
        println!("  imports        : 0 (clean — no ambient capabilities)");
    }
    Ok(())
}

fn cmd_test(dir: &Path) -> Result<()> {
    let manifest = load_manifest(dir)?;
    verify_digest(dir, &manifest)?;
    let bytes = artifact_bytes(dir, &manifest)?;
    let (engine, module, imports, exports) = load_module(&bytes)?;
    validate_tier_and_imports(&manifest, &imports)?;
    require_export(&exports, &manifest.abi_entry, "entry")?;
    require_export(&exports, &manifest.abi_alloc, "alloc")?;

    let fixtures_dir = dir.join("tests").join("fixtures");
    if !fixtures_dir.exists() {
        bail!("no fixtures at {}", fixtures_dir.display());
    }
    let mut fixtures: Vec<PathBuf> = fs::read_dir(&fixtures_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    fixtures.sort();
    if fixtures.is_empty() {
        bail!("no fixtures found in {}", fixtures_dir.display());
    }

    let mut failures = 0usize;
    let memory_max = (manifest.memory_max_mib as usize) * 1024 * 1024;

    for fixture_path in &fixtures {
        let fixture_text = fs::read_to_string(fixture_path)?;
        let fixture: serde_json::Value = serde_json::from_str(&fixture_text)
            .with_context(|| format!("fixture {} is not valid JSON", fixture_path.display()))?;
        let input = fixture
            .get("input")
            .ok_or_else(|| anyhow!("fixture {} missing 'input'", fixture_path.display()))?;
        let expect = fixture.get("expect");

        let mut store = Store::new(&engine, ());
        let linker = Linker::<()>::new(&engine);
        let instance_pre = linker
            .instantiate(&mut store, &module)
            .map_err(|e| anyhow!("instantiate failed: {e}"))?;
        let instance = instance_pre
            .start(&mut store)
            .map_err(|e| anyhow!("start failed: {e}"))?;

        let alloc = instance.get_typed_func::<i32, i32>(&mut store, &manifest.abi_alloc)?;
        let entry = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, &manifest.abi_entry)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("module does not export 'memory'"))?;

        let input_json = serde_json::to_vec(input)?;
        let len = input_json.len() as i32;
        let ptr = alloc
            .call(&mut store, len)
            .map_err(|e| anyhow!("allocate failed: {e}"))?;
        if ptr == 0 {
            bail!("allocate returned 0 (out of memory) for fixture {}", fixture_path.display());
        }
        memory
            .write(&mut store, ptr as usize, &input_json)
            .map_err(|e| anyhow!("memory.write failed: {e}"))?;

        let header_ptr = entry
            .call(&mut store, (ptr, len))
            .map_err(|e| anyhow!("_start trapped: {e}"))?;
        let mut header = [0u8; 8];
        memory
            .read(&store, header_ptr as usize, &mut header)
            .map_err(|e| anyhow!("memory.read header failed: {e}"))?;
        let out_ptr = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let out_len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if out_len == 0 {
            let mut err_body = [0u8; 512];
            let read_len = err_body.len().min(memory.data(&store).len().saturating_sub(out_ptr));
            memory
                .read(&store, out_ptr, &mut err_body[..read_len])
                .ok();
            let err_text = String::from_utf8_lossy(&err_body[..read_len]);
            bail!(
                "fixture {}: plugin returned zero-length result (error body: {})",
                fixture_path.display(),
                err_text
            );
        }
        let mut out_buf = vec![0u8; out_len];
        memory
            .read(&store, out_ptr, &mut out_buf)
            .map_err(|e| anyhow!("memory.read output failed: {e}"))?;
        let output: serde_json::Value = serde_json::from_slice(&out_buf)
            .with_context(|| format!("plugin output is not valid JSON (fixture {})", fixture_path.display()))?;

        let memory_used = memory.data(&store).len();
        if memory_used > memory_max {
            bail!(
                "fixture {}: memory {} exceeds memory_max_mib {}",
                fixture_path.display(),
                memory_used,
                manifest.memory_max_mib
            );
        }

        let mut ok = true;
        if let Some(expect) = expect {
            if let (Some(expected_obj), Some(output_obj)) = (expect.as_object(), output.as_object()) {
                for (key, expected_value) in expected_obj {
                    match output_obj.get(key) {
                        Some(actual) if actual == expected_value => {}
                        Some(actual) => {
                            println!(
                                "  FAIL  {}: key '{}' expected {} got {}",
                                fixture_path.file_name().unwrap().to_string_lossy(),
                                key,
                                expected_value,
                                actual
                            );
                            ok = false;
                        }
                        None => {
                            println!(
                                "  FAIL  {}: key '{}' missing from output",
                                fixture_path.file_name().unwrap().to_string_lossy(),
                                key
                            );
                            ok = false;
                        }
                    }
                }
            } else {
                println!(
                    "  FAIL  {}: expect/output are not objects",
                    fixture_path.file_name().unwrap().to_string_lossy()
                );
                ok = false;
            }
        }

        if ok {
            println!(
                "  PASS  {} (out_len={}, memory={} bytes)",
                fixture_path.file_name().unwrap().to_string_lossy(),
                out_len,
                memory_used
            );
        } else {
            failures += 1;
        }
    }

    if failures > 0 {
        bail!("test: {failures} fixture(s) failed");
    }
    println!("test: OK — {} fixture(s) passed", fixtures.len());
    Ok(())
}

fn cmd_install(dir: &Path) -> Result<()> {
    let manifest = load_manifest(dir)?;
    verify_digest(dir, &manifest)?;
    let catalog = catalog_dir()?;
    let dest = catalog.join(&manifest.name);
    fs::create_dir_all(&dest)?;
    fs::copy(dir.join("manifest.json"), dest.join("manifest.json"))?;
    fs::copy(dir.join(&manifest.artifact_path), dest.join(&manifest.artifact_path))?;

    // Re-verify digest at the destination.
    let installed = load_manifest(&dest)?;
    verify_digest(&dest, &installed)?;
    println!(
        "install: {} v{} -> {} (digest verified)",
        installed.name,
        installed.version,
        dest.display()
    );
    Ok(())
}

fn cmd_list() -> Result<()> {
    let catalog = catalog_dir()?;
    if !catalog.exists() {
        println!("list: catalog {} does not exist yet", catalog.display());
        return Ok(());
    }
    let mut entries: Vec<(String, String, String, String, u64)> = Vec::new();
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
        if let Ok(text) = fs::read_to_string(&manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<Manifest>(&text) {
                let tier = effective_tier(&manifest);
                let capabilities = manifest
                    .omega
                    .as_ref()
                    .and_then(|o| o.capabilities.as_ref())
                    .cloned()
                    .unwrap_or_default()
                    .join(",");
                let cost = manifest
                    .omega
                    .as_ref()
                    .and_then(|o| o.cost_hint_msats)
                    .unwrap_or(0);
                entries.push((manifest.name, manifest.version, tier.to_string(), capabilities, cost));
            }
        }
    }
    entries.sort();
    if entries.is_empty() {
        println!("list: no plugins installed in {}", catalog.display());
        return Ok(());
    }
    println!("list: {} plugin(s) in {}", entries.len(), catalog.display());
    for (name, version, tier, capabilities, cost) in entries {
        println!("  {name} v{version} [tier={tier}, cost={cost} msats, caps={capabilities}]");
    }
    Ok(())
}