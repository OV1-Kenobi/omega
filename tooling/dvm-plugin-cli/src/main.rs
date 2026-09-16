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
    CatalogEntry, Manifest, artifact_bytes, catalog_dir, confine_artifact_path, list_catalog,
    load_manifest, load_module, sha256_hex, validate_json_schema, validate_plugin,
    verify_abi_signatures,
};
use std::fs;
use std::path::{Path, PathBuf};
use wasmi::{Engine, Linker, Module, Store};

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
    /// Publish with a real service identity (F-04): write the identity into
    /// the manifest AND the plugin source's single substitution point, then
    /// rebuild + re-pin the digest, then run the mandatory identity-consistency
    /// assertion. Fails the publish if the pinned artifact's reported identity
    /// does not match the manifest's omega.service, or if the identity is the
    /// all-zero placeholder.
    Publish {
        dir: PathBuf,
        /// DVM service npub: exactly 64 hex characters (public, never a secret).
        #[arg(long)]
        npub: String,
        /// Nostr relay URL (wss:// or ws://). Repeatable; at least one required.
        #[arg(long)]
        relay: Vec<String>,
        /// NIP-90 job-request kind this DVM serves (default 5900).
        #[arg(long, default_value_t = 5900)]
        kind: u32,
    },
    /// Re-run the mandatory identity-consistency assertion on an existing
    /// build (no writes, no rebuild): the pinned artifact's reported
    /// `result.service` must equal the manifest's `omega.service` and the npub
    /// must not be the placeholder. Fails (exit 1) on any inconsistency.
    VerifyIdentity { dir: PathBuf },
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
        Commands::Publish { dir, npub, relay, kind } => cmd_publish(&dir, &npub, &relay, kind),
        Commands::VerifyIdentity { dir } => cmd_verify_identity(&dir),
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

// F-14 (WP-M2b security review): the scaffold ships a rust-toolchain.toml so
// duplicators build under the SAME pinned compiler as the Omega repo (Rust
// 1.95.0) regardless of the machine's default toolchain. Digests are then
// reproducible for the same source + toolchain.
const TEMPLATE_RUST_TOOLCHAIN: &str = r#"# F-14 toolchain pin (WP-M4): the white-label template builds under a
# PINNED Rust compiler so duplicators produce reproducible digests regardless
# of the machine's default toolchain. Recorded pin: Rust 1.95.0.
[toolchain]
channel = "1.95.0"
profile = "minimal"
components = ["rustfmt"]
targets = ["wasm32-unknown-unknown"]
"#;

// The template's SINGLE service-identity substitution point (F-04 / WP-M2b
// design §4.2). `dvm-plugin-cli publish` rewrites this file from the
// manifest's omega.service block and rebuilds. Hand-editing is unsupported.
const TEMPLATE_SERVICE_IDENTITY_RS: &str = r#"// GENERATED FILE — owned by `dvm-plugin-cli publish`. Do not hand-edit.
//
// This file is the template's SINGLE service-identity substitution point
// (WP-M4 F-04; WP-M2b service-identity design §4.2). `dvm-plugin-cli
// publish` rewrites this file from the manifest's `omega.service` block and
// rebuilds the artifact, so the manifest value and the compiled-in value
// cannot diverge. Hand-editing is unsupported.
//
// The placeholder below is the TEMPLATE default. A published artifact never
// carries the all-zero placeholder npub: `dvm-plugin-cli publish` refuses it
// and `dvm-plugin-cli verify-identity` fails it.

pub const SERVICE_NPUB: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const SERVICE_RELAYS: &[&str] = &[];
pub const SERVICE_KIND: u32 = 5900;
"#;

// The white-label duplicator README (identical in spirit to the repo template
// README at plugins/dvm/white-label-seed/README.md). Documented in WP-M4:
// what a duplicator changes (capability name, tools, pricing, service
// identity) and what must NOT change (permission tier, no secrets, ABI v0).
const TEMPLATE_README: &str = r#"# <name> — DVM Plugin (white-label template duplicate)

Created by `dvm-plugin-cli init` from the Omega white-label DVM template.

## What to change before publishing

1. **Capability name** — already set at `init` (this directory + manifest name).
   To rename, change `manifest.json` -> `name` AND `Cargo.toml` -> `package.name`.
2. **Tools / capability tags** — `manifest.json` -> `omega.capabilities`
   (e.g. `text/stats`). Tags drive discovery and the `capability` tool's `find`.
3. **Pricing** — `manifest.json` -> `omega.cost_hint_msats` (0 = free hint;
   never a commitment; the L-402 gate is the real payment path).
4. **Description** — `manifest.json` -> `description` (used verbatim in the
   catalog and the DVM service listing).
5. **Service identity** — publish-time, pipeline-owned:

   ```sh
   dvm-plugin-cli publish <dir> --npub <64-hex> --relay wss://relay.example [--relay wss://...] [--kind 5900]
   ```

   `publish` writes the identity into `manifest.json` -> `omega.service`,
   rewrites `src/service_identity.rs` (the single substitution point) with the
   SAME identity, rebuilds + re-pins the digest, and runs the mandatory
   identity-consistency assertion (artifact-reported identity == manifest
   identity; mismatch fails publish). `dvm-plugin-cli verify-identity <dir>`
   re-runs the assertion on an existing build.

6. **Plugin logic + schemas** — `src/lib.rs` (`run`) and `manifest.json`
   `input_schema`/`output_schema`. Keep the ABI exports untouched.

## What must NOT change

- **Permission tier** — stay PureCompute: `mounts: []`, `hosts: []`, zero
  imports, no WASI, no network. The host refuses anything else.
- **No secrets** — manifest, Wasm, and service identity contain PUBLIC data
  only. Never put credentials or keys in the artifact or the listing.
- **ABI v0** — do not change `abi_entry`/`abi_alloc`/`memory`/result-header
  convention; the host's shared validator and ABI policy gate enforce it.
- **`omega.sdk`** — leave `lang`/`target`/`abi` as the template declares them.
- **Digest pinning** — `artifact_digest` is written by `build`, never by hand.

## Build / pin / inspect / test / install

```sh
dvm-plugin-cli build <dir>
dvm-plugin-cli inspect <dir>
dvm-plugin-cli test <dir>
dvm-plugin-cli install <dir>
dvm-plugin-cli list
```

Toolchain: Rust 1.95.0 pinned by `rust-toolchain.toml` (F-14); builds are
offline with `--locked`.
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
    // F-04 single substitution point (generated-style template placeholder;
    // `publish` rewrites it from the manifest's omega.service block).
    fs::write(src_dir.join("service_identity.rs"), TEMPLATE_SERVICE_IDENTITY_RS)?;
    // F-14 toolchain pin: scaffolded duplicates build under Rust 1.95.0.
    fs::write(dir.join("rust-toolchain.toml"), TEMPLATE_RUST_TOOLCHAIN)?;
    // White-label duplicator README (what to change / what must NOT change).
    fs::write(dir.join("README.md"), TEMPLATE_README.replace("<name>", &normalized))?;
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "openagents.plugin/v0",
            "name": normalized,
            "version": "0.1.0",
            "description": "DVM plugin scaffolded from the white-label seed (WP-M1): text statistics + DVM service identity.",
            "artifact_path": "plugin.wasm",
            "artifact_digest": "sha256:<set-by-build>",
            "abi_entry": "_start",
            "abi_alloc": "allocate",
            "input_schema": { "type": "object", "properties": { "text": { "type": "string" } }, "required": ["text"] },
            "output_schema": {
                "type": "object",
                "properties": {
                    "words": { "type": "integer" },
                    "lines": { "type": "integer" },
                    "chars": { "type": "integer" },
                    "service": {
                        "type": "object",
                        "properties": {
                            "npub": { "type": "string" },
                            "relays": { "type": "array", "items": { "type": "string" } },
                            "kind": { "type": "integer" }
                        }
                    }
                },
                "required": ["words", "lines", "chars", "service"]
            },
            "mounts": [],
            "hosts": [],
            "timeout_ms": 1000,
            "memory_max_mib": 64,
            "omega": {
                "schema": "omega.dvm-plugin/delta-v0",
                "capabilities": ["text/stats", "dvm/service-identity"],
                "cost_hint_msats": 0,
                "service": {
                    "npub": "0000000000000000000000000000000000000000000000000000000000000000",
                    "relays": [],
                    "kind": 5900
                },
                "tier": "PureCompute",
                "sdk": { "lang": "rust", "target": "wasm32-unknown-unknown", "abi": "omega-plugin-abi-v0" }
            }
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
        println!("  timeout_ms     : {}", manifest.timeout_ms.unwrap_or(0));
        println!("  memory_max_mib : {}", manifest.memory_max_mib.unwrap_or(0));
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
    let memory_max = (manifest
        .memory_max_mib
        .unwrap_or(dvm_plugin_core::HOST_MAX_MEMORY_MIB)
        as usize)
        * 1024
        * 1024;

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

        let (output, out_len, memory_used) = run_module_once(&engine, &module, manifest, input, memory_max)
            .with_context(|| format!("executing fixture {}", fixture_path.display()))?;

        // F-07: plugin output must satisfy the manifest's output_schema.
        validate_json_schema(&output, &manifest.output_schema).with_context(|| {
            format!("fixture {} output fails output_schema", fixture_path.display())
        })?;

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

// ---------------------------------------------------------------------------
// Shared single-execution helper (wasmi test runtime)
// ---------------------------------------------------------------------------

/// Run one JSON input against a loaded, ABI-verified module and return
/// `(output_json, out_len, memory_used)`. Shared by the `test` fixture loop
/// and the F-04 publish identity assertion so both exercise the identical
/// execution path (instantiate -> allocate -> write input -> `_start` -> read
/// result header -> read output).
fn run_module_once(
    engine: &Engine,
    module: &Module,
    manifest: &Manifest,
    input: &serde_json::Value,
    memory_max: usize,
) -> Result<(serde_json::Value, usize, usize)> {
    let mut store = Store::new(engine, ());
    let linker = Linker::<()>::new(engine);
    let instance_pre = linker
        .instantiate(&mut store, module)
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
        bail!("allocate returned 0 (out of memory)");
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
        bail!("plugin returned zero-length result (error body: {})", err_text);
    }
    let mut out_buf = vec![0u8; out_len];
    memory
        .read(&store, out_ptr, &mut out_buf)
        .map_err(|e| anyhow!("memory.read output failed: {e}"))?;
    let output: serde_json::Value = serde_json::from_slice(&out_buf)
        .with_context(|| "plugin output is not valid JSON")?;

    let memory_used = memory.data(&store).len();
    let effective_mib = manifest
        .memory_max_mib
        .unwrap_or(dvm_plugin_core::HOST_MAX_MEMORY_MIB);
    if memory_used > memory_max {
        bail!(
            "memory {} exceeds memory_max_mib {}",
            memory_used,
            effective_mib
        );
    }
    Ok((output, out_len, memory_used))
}

/// Execute a plugin with a JSON input through the shared wasmi test runtime
/// after the FULL shared validator (digest, imports, tier, schemas, ABI
/// signatures). Returns the plugin's structured answer.
fn execute_plugin_value(
    dir: &Path,
    manifest: &Manifest,
    input: &serde_json::Value,
) -> Result<serde_json::Value> {
    let _info = validate_plugin(dir)?;
    let bytes = artifact_bytes(dir, manifest)?;
    let (engine, module, _, exports) = load_module(&bytes)?;
    verify_abi_signatures(manifest, &exports)?;
    let memory_max = (manifest
        .memory_max_mib
        .unwrap_or(dvm_plugin_core::HOST_MAX_MEMORY_MIB)
        as usize)
        * 1024
        * 1024;
    let (output, _, _) = run_module_once(&engine, &module, manifest, input, memory_max)?;
    Ok(output)
}

// ---------------------------------------------------------------------------
// F-04 service-identity pipeline (WP-M4): publish + verify-identity
// ---------------------------------------------------------------------------

/// Validate publish-time identity inputs. `npub` is exactly 64 hex chars and
/// NOT the all-zero placeholder; at least one `wss://`/`ws://` relay is
/// required; `kind` is in the NIP-90 job-request range 5000-5999.
fn validate_identity_inputs(npub: &str, relays: &[String], kind: u32) -> Result<()> {
    let npub = npub.trim();
    if npub.len() != 64 || !npub.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!(
            "--npub must be exactly 64 hex characters (got {} characters)",
            npub.len()
        );
    }
    if npub.chars().all(|c| c == '0') {
        bail!("--npub is the all-zero placeholder; a real DVM npub is required to publish");
    }
    if relays.is_empty() {
        bail!("at least one --relay is required (a published DVM must be reachable on a relay)");
    }
    for r in relays {
        if !(r.starts_with("wss://") || r.starts_with("ws://")) {
            bail!("--relay '{}' must be a wss:// or ws:// URL", r);
        }
        if r.contains('"') || r.contains('\\') || r.contains('\n') || r.contains('\r') {
            bail!(
                "--relay '{}' contains characters that cannot be embedded in the plugin source; use a plain URL",
                r
            );
        }
    }
    if !(5000..=5999).contains(&kind) {
        bail!(
            "--kind {} is outside the NIP-90 job-request kind range 5000-5999",
            kind
        );
    }
    Ok(())
}

/// Write the SAME identity into the plugin source's single substitution point
/// (`src/service_identity.rs`). This is the step that makes the manifest value
/// the input to the artifact rather than an independent compiled-in constant
/// (F-04 / WP-M2b design §4.2).
fn write_service_identity_rs(dir: &Path, npub: &str, relays: &[String], kind: u32) -> Result<()> {
    let rust_str = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let npub = npub.trim().to_lowercase();
    let relays_lit: Vec<String> = relays.iter().map(|r| rust_str(r)).collect();
    let content = format!(
        "// GENERATED FILE — owned by `dvm-plugin-cli publish`. Do not hand-edit.\n\
         //\n\
         // Rewritten by the publish pipeline from the manifest's `omega.service`\n\
         // block (F-04 single substitution point). The manifest value and the\n\
         // compiled-in value are the same publish-time input.\n\n\
         pub const SERVICE_NPUB: &str = {};\n\
         pub const SERVICE_RELAYS: &[&str] = &[{}];\n\
         pub const SERVICE_KIND: u32 = {};\n",
        rust_str(&npub),
        relays_lit.join(", "),
        kind
    );
    let dest = dir.join("src").join("service_identity.rs");
    fs::write(&dest, content)
        .with_context(|| format!("cannot write {}", dest.display()))?;
    Ok(())
}

/// Mandatory identity-consistency assertion: the manifest's `omega.service`
/// (expected) must equal the pinned artifact's reported `result.service`
/// (reported) on npub, relays, and kind. Any mismatch FAILS the publish.
fn assert_identity_consistent(
    expected: &serde_json::Value,
    reported: &serde_json::Value,
) -> Result<()> {
    let mut problems = Vec::new();
    for field in ["npub", "relays", "kind"] {
        let e = expected.get(field).cloned().unwrap_or(serde_json::Value::Null);
        let r = reported.get(field).cloned().unwrap_or(serde_json::Value::Null);
        if e != r {
            problems.push(format!("{field}: manifest={e} artifact={r}"));
        }
    }
    if !problems.is_empty() {
        bail!(
            "identity-consistency assertion FAILED: {} — the pinned artifact does not report the \
             manifest's omega.service (F-04). Re-run `dvm-plugin-cli publish` to rebuild the \
             identity-bearing artifact.",
            problems.join("; ")
        );
    }
    Ok(())
}

/// No placeholder identity may reach a published artifact: `omega.service.npub`
/// must be a real (non-empty, non-all-zero) npub.
fn assert_not_placeholder(service: &serde_json::Value) -> Result<()> {
    let npub = service.get("npub").and_then(|v| v.as_str()).unwrap_or("");
    if npub.is_empty() || npub.chars().all(|c| c == '0') {
        bail!(
            "omega.service.npub is the all-zero placeholder; no placeholder identity may reach a \
             published artifact (F-04). Run `dvm-plugin-cli publish` with a real npub."
        );
    }
    Ok(())
}

/// Execute the built artifact and return its reported `result.service`.
fn execute_and_report_service(dir: &Path, manifest: &Manifest) -> Result<serde_json::Value> {
    let output = execute_plugin_value(dir, manifest, &serde_json::json!({ "text": "" }))?;
    let service = output.get("service").cloned().ok_or_else(|| {
        anyhow!(
            "plugin output has no 'service' object (the dvm/service-identity capability is \
             required for marketplace plugins)"
        )
    })?;
    Ok(service)
}

/// Publish pipeline (F-04 / WP-M2b design §4.1), ordered and mandatory:
/// 1. operator supplies identity -> 2. manifest write -> 3. source substitution
/// -> 4. build + pin -> 5. mandatory identity-consistency assertion (fails the
/// publish on mismatch) -> 6. placeholder guard.
fn cmd_publish(dir: &Path, npub: &str, relays: &[String], kind: u32) -> Result<()> {
    validate_identity_inputs(npub, relays, kind)?;

    // 1/2. Load the template manifest and write the identity into
    // `omega.service` (the discovery source of truth).
    let mut manifest = load_manifest(dir)?;
    {
        let omega = manifest.omega.as_mut().ok_or_else(|| {
            anyhow!(
                "manifest has no omega delta block; publish requires the white-label template \
                 shape (omega.schema + omega.service)"
            )
        })?;
        omega.service = Some(serde_json::json!({
            "npub": npub.trim().to_lowercase(),
            "relays": relays,
            "kind": kind
        }));
    }
    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)
        .with_context(|| format!("cannot write {}", manifest_path.display()))?;

    // 3. Substitute the SAME identity into the plugin source at the single
    // substitution point.
    write_service_identity_rs(dir, npub, relays, kind)?;

    // 4. Rebuild + pin: the artifact now carries the identity-bearing bytes,
    // and the digest is re-pinned over them.
    cmd_build(dir)?;

    // 5. Mandatory identity-consistency assertion on the pinned artifact.
    let manifest = load_manifest(dir)?;
    let expected = manifest
        .omega
        .as_ref()
        .and_then(|o| o.service.as_ref())
        .ok_or_else(|| anyhow!("omega.service missing after publish write"))?;
    let reported = execute_and_report_service(dir, &manifest)?;
    assert_identity_consistent(expected, &reported)?;

    // 6. Placeholder guard: the artifact reports a real npub.
    assert_not_placeholder(&reported)?;

    let npub = reported.get("npub").and_then(|v| v.as_str()).unwrap_or("");
    println!(
        "publish: OK — {} v{} pinned {}",
        manifest.name, manifest.version, manifest.artifact_digest
    );
    println!(
        "publish: identity consistent (manifest omega.service == artifact-reported service) \
         npub={} kind={} relays={:?}",
        npub,
        reported.get("kind").cloned().unwrap_or_default(),
        reported.get("relays").cloned().unwrap_or_default(),
    );
    Ok(())
}

/// Assertion-only re-verification on an existing build (no writes, no
/// rebuild). Fail-closed: exit 1 on any inconsistency or placeholder.
fn cmd_verify_identity(dir: &Path) -> Result<()> {
    let manifest = load_manifest(dir)?;
    let expected = manifest
        .omega
        .as_ref()
        .and_then(|o| o.service.as_ref())
        .ok_or_else(|| {
            anyhow!("manifest has no omega.service block; not a white-label template plugin")
        })?;
    assert_not_placeholder(expected)?;
    let reported = execute_and_report_service(dir, &manifest)?;
    assert_identity_consistent(expected, &reported)?;
    let npub = reported.get("npub").and_then(|v| v.as_str()).unwrap_or("");
    println!(
        "verify-identity: OK — artifact-reported service identity matches manifest omega.service \
         (npub={})",
        npub
    );
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