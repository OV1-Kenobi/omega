//! dvm-plugin-host — Omega DVM plugin host CLI (WP-M2b).
//!
//! Command surface mirrors the `capability` tool contract:
//!   list / find / inspect / run
//!
//! Machine-callable contract (LRN-2026-130): stdout carries ONLY the payload
//! (the JSON structured answer or envelope); all diagnostics go to stderr.
//!
//! Permission prompt model:
//!   - PureCompute: runs automatically (no prompt).
//!   - Mounts: requires `--approve` (operator approval); otherwise
//!     `operator_denied`.
//!   - Hosts: refused load (`tier_denied`).

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use dvm_plugin_host::{Approval, RunRequest, runtime::LimitsOverride};

#[derive(Parser)]
#[command(
    name = "dvm-plugin-host",
    version,
    about = "Omega DVM plugin host (WP-M2b): list/find/inspect/run against the catalog"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List installed plugins (discovery; never executes).
    List,
    /// Find plugins by tag/name/description substring.
    Find { query: String },
    /// Inspect a plugin (full shared validation + digest re-verification).
    Inspect { plugin: String },
    /// Run a plugin with enforced bounds and permission handling.
    Run {
        plugin: String,
        /// JSON input matching the plugin's input_schema (inline).
        #[arg(long)]
        input: Option<String>,
        /// JSON input file matching the plugin's input_schema (for large
        /// inputs that exceed command-line limits). Mutually exclusive with
        /// --input.
        #[arg(long)]
        input_file: Option<std::path::PathBuf>,
        /// Approve a Mounts-tier run (operator approval prompt).
        #[arg(long)]
        approve: bool,
        /// Explicitly deny (for testing the denial path).
        #[arg(long)]
        deny: bool,
        /// Host-level memory ceiling in MiB (default: manifest value).
        #[arg(long)]
        memory_max_mib: Option<u64>,
        /// Host-level time ceiling in ms (default: manifest value).
        #[arg(long)]
        timeout_ms: Option<u64>,
        /// Explicit fuel budget (instructions) — overrides the derived budget.
        #[arg(long)]
        fuel_budget: Option<u64>,
        /// Optional catalog dir override (CODER_PLUGINS_DIR equivalent).
        #[arg(long)]
        catalog: Option<std::path::PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Commands::Run {
        catalog: Some(c), ..
    } = &cli.command
    {
        std::env::set_var("CODER_PLUGINS_DIR", c);
    }
    match cli.command {
        Commands::List => cmd_list(),
        Commands::Find { query } => cmd_find(&query),
        Commands::Inspect { plugin } => cmd_inspect(&plugin),
        Commands::Run {
            plugin,
            input,
            input_file,
            approve,
            deny,
            memory_max_mib,
            timeout_ms,
            fuel_budget,
            ..
        } => cmd_run(RunArgs {
            plugin,
            input,
            input_file,
            approve,
            deny,
            memory_max_mib,
            timeout_ms,
            fuel_budget,
        }),
    }
}

/// Grouped arguments for `run` (keeps the signature reviewable).
struct RunArgs {
    plugin: String,
    input: Option<String>,
    input_file: Option<std::path::PathBuf>,
    approve: bool,
    deny: bool,
    memory_max_mib: Option<u64>,
    timeout_ms: Option<u64>,
    fuel_budget: Option<u64>,
}

fn cmd_list() -> Result<()> {
    let plugins = dvm_plugin_host::list_plugins()?;
    // Discovery structured answer (03 §2.2).
    let payload = serde_json::json!({
        "plugins": plugins.iter().map(|p| serde_json::json!({
            "name": p.name,
            "version": p.version,
            "description": p.description,
            "capabilities": p.capabilities,
            "tier": p.tier,
            "cost_hint_msats": p.cost_hint_msats,
            "digest_verified": p.digest_verified,
            "loadable": p.loadable,
            "load_error": p.load_error,
            "timeout_ms": p.timeout_ms,
            "memory_max_mib": p.memory_max_mib,
        })).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn cmd_find(query: &str) -> Result<()> {
    let plugins = dvm_plugin_host::find_plugins(query)?;
    let payload = serde_json::json!({
        "query": query,
        "plugins": plugins.iter().map(|p| serde_json::json!({
            "name": p.name,
            "version": p.version,
            "description": p.description,
            "capabilities": p.capabilities,
            "tier": p.tier,
            "cost_hint_msats": p.cost_hint_msats,
            "digest_verified": p.digest_verified,
            "loadable": p.loadable,
            "load_error": p.load_error,
        })).collect::<Vec<_>>()
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn cmd_inspect(plugin: &str) -> Result<()> {
    match dvm_plugin_host::inspect_plugin(plugin) {
        Ok(inspection) => {
            println!("{}", serde_json::to_string_pretty(&inspection)?);
            Ok(())
        }
        Err(e) => {
            eprintln!("inspect: error: {e:#}");
            std::process::exit(1);
        }
    }
}

fn cmd_run(args: RunArgs) -> Result<()> {
    let RunArgs {
        plugin,
        input,
        input_file,
        approve,
        deny,
        memory_max_mib,
        timeout_ms,
        fuel_budget,
    } = args;
    let input_text = match (&input, &input_file) {
        (Some(_), Some(_)) => bail!("--input and --input-file are mutually exclusive"),
        (Some(text), None) => text.clone(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read --input-file {}: {e}", path.display()))?,
        (None, None) => bail!("either --input or --input-file is required"),
    };
    let input_value: serde_json::Value = serde_json::from_str(&input_text)
        .map_err(|e| anyhow::anyhow!("--input is not valid JSON: {e}"))?;
    let approval = if deny {
        Approval::Denied
    } else if approve {
        Approval::Granted
    } else {
        Approval::Auto
    };
    let limits_override = if memory_max_mib.is_some() || timeout_ms.is_some() || fuel_budget.is_some()
    {
        Some(LimitsOverride {
            memory_max_mib,
            timeout_ms,
            fuel_budget,
        })
    } else {
        None
    };
    let req = RunRequest {
        plugin,
        input: input_value,
        approval,
        limits_override,
    };
    match dvm_plugin_host::run_plugin(&req)? {
        dvm_plugin_host::RunOutcome::Success(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        dvm_plugin_host::RunOutcome::Failure(err) => {
            // Structured error envelope on stdout (payload), diagnostics on
            // stderr. Exit 1 signals failure to a machine caller.
            let payload = serde_json::json!({ "ok": false, "error": err });
            println!("{}", serde_json::to_string_pretty(&payload)?);
            eprintln!("run: error: {}: {}", err.code, err.message);
            std::process::exit(1);
        }
    }
}