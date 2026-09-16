//! dvm-plugin-cli — Omega DVM plugin authoring tool (WP-M1, hardened WP-M2).
//!
//! Command surface mirrors `coder-cli plugin`:
//!   init / build / inspect / test / install / list
//!
//! WP-M2 hardening (all security-review conditions):
//! - F-01: all manifest-controlled paths go through
//!   `dvm_plugin_core::confine_artifact_path` (traversal refused).
//! - F-02: `install` runs the SAME full validator as `inspect`
//!   (`dvm_plugin_core::validate_plugin`) before copying; a malformed or
//!   importing artifact never installs.
//! - F-05: exact ABI signatures are verified by the shared validator.
//! - F-07: fixture input/output are validated against the manifest schemas.
//! - F-08: `cargo build --locked` enforces the committed lockfile.
//! - F-10: `list` re-verifies installed digests.
//! - F-11: `init` rejects non-ASCII plugin names.
//!
//! Contract source: openagents.plugin/v0 + Omega delta layer
//! (see planning/2026/09-september/15-plan-omega-dvm-marketplace/).

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use dvm_plugin_core::{
    CatalogEntry, artifact_bytes, catalog_dir, confine_artifact_path, list_catalog, load_manifest,
    sha256_hex, validate_json_schema, validate_plugin, verify_abi_signatures,
};
use std::fs;
use std::path::{Path, PathBuf};
use wasmi::{Linker, Store};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "dvm-plugin-cli",
    version,
    about = "Omega DVM plugin authoring tool (WP-M1/M2): init/build/inspect/test/install/list"
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
    // F-11: reject non-ASCII names (the old `is_alphanumeric()` accepted
    // Unicode letters, producing non-ASCII directory ids).
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            bail!(
                "plugin name must contain only ASCII alphanumeric characters or '_' (got {c:?}); \
                 non-ASCII names are rejected (F-11)"
            );
        }
    }
    let normalized: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
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
    // NOTE (F-08): rustup target add performs a network download on a fresh
    // machine; documented in README.md as install-time egress.
    let target_status = std::process::Command::new("rustup")
        .args(["target", "add", "wasm32-unknown-unknown"])
        .current_dir(dir)
        .status()
        .context("failed to run rustup target add wasm32-unknown-unknown")?;
    if !target_status.success() {
        bail!("rustup target add wasm32-unknown-unknown failed with status {target_status}");
    }

    // F-08: --locked enforces the committed Cargo.lock (reproducibility).
    // A fresh `init` scaffold has no Cargo.lock yet; generate it offline
    // (from the local cargo cache, no network) so the locked build below
    // can proceed and then stays reproducible for that scaffold.
    if !dir.join("Cargo.lock").exists() {
        let gen_status = std::process::Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(dir)
            .status()
            .context("failed to run cargo generate-lockfile --offline")?;
        if !gen_status.success() {
            bail!("cargo generate-lockfile --offline failed with status {gen_status}");
        }
    }
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .current_dir(dir)
        .status()
        .context("failed to run cargo build")?;
    if !status.success() {
        bail!("cargo build --locked failed with status {status}");
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
    // F-01: the artifact copy target must be confined (manifest-controlled).
    let artifact_path = confine_artifact_path(dir, &manifest.artifact_path)?;
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
    // The FULL shared validator: digest, imports, exports + exact ABI
    // signatures (F-05), declared memory maximum vs manifest bound (F-03),
    // tier consistency, mounts read-only, hosts blocked, schema
    // well-formedness (F-07).
    let info = validate_plugin(dir)?;
    let manifest = &info.manifest;

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
        println!("  tier           : {} (mounts={} hosts={})", info.tier, manifest.mounts.len(), manifest.hosts.len());
        println!("  capabilities   : {}", capabilities);
        println!("  cost_hint_msats: {}", manifest.omega.as_ref().and_then(|o| o.cost_hint_msats).unwrap_or(0));
        println!("  timeout_ms     : {}", manifest.timeout_ms);
        println!("  memory_max_mib : {}", manifest.memory_max_mib);
        println!("  imports        : 0 (clean — no ambient capabilities)");
    }
    Ok(())
}

fn cmd_test(dir: &Path) -> Result<()> {
    // Shared validator first — same gate the host load path uses.
    let info = validate_plugin(dir)?;
    let manifest = &info.manifest;
    let bytes = artifact_bytes(dir, manifest)?;
    let (engine, module, _, _) = dvm_plugin_core::load_module(&bytes)?;
    verify_abi_signatures(manifest, &info.exports)?;

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

        // F-07: fixture input must satisfy the manifest's input_schema.
        validate_json_schema(input, &manifest.input_schema).with_context(|| {
            format!(
                "fixture {} input fails input_schema: {}",
                fixture_path.display(),
                fixture_path.display()
            )
        })?;

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

        // F-07: plugin output must satisfy the manifest's output_schema.
        validate_json_schema(&output, &manifest.output_schema).with_context(|| {
            format!("fixture {} output fails output_schema", fixture_path.display())
        })?;

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
    // F-02 (mandatory): install runs the SAME full validator as inspect
    // (digest, imports, exports + ABI signatures, tier consistency,
    // memory-max declaration, schema well-formedness). A malformed or
    // importing artifact NEVER installs.
    let info = validate_plugin(dir)?;
    let manifest = &info.manifest;

    // F-01 (mandatory): resolve the artifact through the confined path; the
    // manifest-controlled artifact_path can never escape the plugin dir.
    let src_artifact = confine_artifact_path(dir, &manifest.artifact_path)?;
    let catalog = catalog_dir()?;
    let dest = catalog.join(&manifest.name);

    // Manifest name confinement: `name` is also manifest-controlled and joins
    // into the catalog path — it must be a plain directory name.
    let plugin_name = &manifest.name;
    for c in plugin_name.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '-' {
            bail!(
                "plugin name '{plugin_name}' contains non-ASCII-alphanumeric character {c:?}; \
                 install refused (name confinement, F-01)"
            );
        }
    }
    if plugin_name.is_empty() || plugin_name == "." || plugin_name == ".." {
        bail!("plugin name is not a safe directory name; install refused");
    }

    fs::create_dir_all(&dest)?;
    fs::copy(dir.join("manifest.json"), dest.join("manifest.json"))?;
    fs::copy(&src_artifact, dest.join(&manifest.artifact_path))?;

    // Re-verify digest at the destination.
    let installed = load_manifest(&dest)?;
    dvm_plugin_core::verify_digest(&dest, &installed)?;
    println!(
        "install: {} v{} -> {} (full validation OK, digest verified)",
        installed.name,
        installed.version,
        dest.display()
    );
    Ok(())
}

fn cmd_list() -> Result<()> {
    let catalog = catalog_dir()?;
    let entries: Vec<CatalogEntry> = list_catalog()?;
    if entries.is_empty() {
        if !catalog.exists() {
            println!("list: catalog {} does not exist yet", catalog.display());
        } else {
            println!("list: no plugins installed in {}", catalog.display());
        }
        return Ok(());
    }
    println!("list: {} plugin(s) in {}", entries.len(), catalog.display());
    for e in &entries {
        // F-10: list surfaces digest re-verification failures explicitly.
        let digest_state = if e.digest_verified {
            "digest OK".to_string()
        } else {
            format!("DIGEST FAILED ({})", e.digest_error.as_deref().unwrap_or("re-verification failed"))
        };
        println!(
            "  {} v{} [tier={}, cost={} msats, caps={}, {}]",
            e.name,
            e.version,
            e.tier,
            e.cost_hint_msats,
            e.capabilities.join(","),
            digest_state
        );
    }
    Ok(())
}