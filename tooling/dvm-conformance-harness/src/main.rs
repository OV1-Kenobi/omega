//! dvm-conformance-harness — Omega ABI v0 conformance harness CLI (WP-M5a;
//! plan 15-plan-omega-dvm-marketplace; decision 13, agent track).
//!
//! Machine-callable contract (LRN-2026-130): with `--json`, stdout carries
//! ONLY the JSON report; all diagnostics go to stderr. Without `--json`, a
//! human-readable report is printed.
//!
//! Exit codes:
//!   0 — conformance PASS
//!   1 — conformance FAIL (validation/static contract/probe/expected mismatch)
//!   2 — usage error

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use dvm_conformance_harness::check::run_conformance_check;
use dvm_conformance_harness::runtime::{known_runtimes, runtime_by_name};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "dvm-conformance-harness",
    version,
    about = "Omega ABI v0 conformance harness (WP-M5a): run a template plugin against ANY Omega ABI v0 runtime"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the full conformance check against a plugin directory.
    Check {
        /// Plugin directory (manifest.json + plugin.wasm).
        dir: PathBuf,
        /// Runtime adapter to run the probe against (default: wasmi-reference).
        #[arg(long, default_value = "wasmi-reference")]
        runtime: String,
        /// Probe input JSON (inline). Default: a standard template probe.
        #[arg(long)]
        input: Option<String>,
        /// Probe input JSON file.
        #[arg(long)]
        input_file: Option<PathBuf>,
        /// Expected output JSON file; when supplied, the probe output must
        /// match it exactly (structural JSON equality).
        #[arg(long)]
        expected_file: Option<PathBuf>,
        /// Machine-callable JSON report on stdout.
        #[arg(long)]
        json: bool,
    },
    /// List the runtime adapters this harness can drive.
    ListRuntimes,
}

fn read_json(path: &PathBuf, label: &str) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read {label} file {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("{label} is not valid JSON: {}", path.display()))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::ListRuntimes => {
            println!("{}", known_runtimes().join("\n"));
            Ok(())
        }
        Commands::Check {
            dir,
            runtime,
            input,
            input_file,
            expected_file,
            json,
        } => {
            if input.is_some() && input_file.is_some() {
                bail!("--input and --input-file are mutually exclusive");
            }
            let probe_input: Value = if let Some(text) = input {
                serde_json::from_str(&text).context("--input is not valid JSON")?
            } else if let Some(path) = input_file {
                read_json(&path, "input")?
            } else {
                serde_json::json!({ "text": "omega abi v0 conformance probe" })
            };
            let expected = match expected_file {
                Some(path) => Some(read_json(&path, "expected output")?),
                None => None,
            };

            let manifest = dvm_conformance_harness::check::load_manifest_for(&dir)
                .with_context(|| format!("cannot load manifest in {}", dir.display()))?;
            let mut rt = match runtime_by_name(&runtime, &manifest.abi_alloc, &manifest.abi_entry) {
                Some(rt) => rt,
                None => bail!(
                    "unknown runtime '{runtime}'; known runtimes: {}",
                    known_runtimes().join(", ")
                ),
            };

            let report = run_conformance_check(&dir, rt.as_mut(), &probe_input, expected.as_ref())
                .with_context(|| format!("conformance check failed for {}", dir.display()))?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                Ok(())
            } else {
                println!("plugin     : {}", report.plugin);
                println!("version    : {}", report.version);
                println!("runtime    : {}", report.runtime);
                println!(
                    "validated  : {} (shared validator)",
                    if report.validated { "PASS" } else { "FAIL" }
                );
                let sc = &report.static_contract;
                println!("abi marker : {}", sc.marker.as_deref().unwrap_or("<missing>"));
                println!(
                    "static     : {} (alloc={} entry={} memory={})",
                    if sc.static_contract_ok { "OK" } else { "FAIL" },
                    sc.alloc_signature_ok,
                    sc.entry_signature_ok,
                    sc.memory_export_ok
                );
                println!(
                    "probe      : out_len={} out_ptr={} header={}",
                    report.probe.out_len, report.probe.out_ptr, report.probe.header_hex
                );
                match report.expected_match {
                    Some(true) => println!("expected   : MATCH"),
                    Some(false) => println!("expected   : MISMATCH"),
                    None => println!("expected   : (not supplied)"),
                }
                println!(
                    "verdict    : {}",
                    if report.conformance_pass { "CONFORMANT" } else { "NOT CONFORMANT" }
                );
                if report.conformance_pass {
                    Ok(())
                } else {
                    bail!("conformance check FAILED");
                }
            }
        }
    }
}