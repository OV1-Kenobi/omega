//! library_cli — the stdio JSON bridge between the source-summarization MCP
//! server (Node, `scripts/source-summarization-mcp.mjs`) and the LMDB
//! library store that Omega opens in the app process.
//!
//! Each invocation is one short-lived process that opens the same LMDB
//! environment the app uses (LMDB coordinates multi-process access through
//! its own lock file), performs one deterministic operation, prints one JSON
//! line to stdout, and exits. Keeps WP1's T4 reopen promise a single store
//! read while keeping the Node server dependency-free and the store free of
//! IPC code (OMEGA-DELTA-0282).

use std::io::Read;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use prompt_store::{LibraryRecord, LibraryRecordId, LibrarySearchFilters, PromptStore};

const DEFAULT_DB_FILE: &str = "prompts-library-db.0.mdb";

/// JSON request shape for `search` (and the list form used by T5, which
/// omits `query`).
#[derive(Deserialize)]
struct SearchRequest {
    query: Option<String>,
    #[serde(default)]
    filters: LibrarySearchFilters,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize {
    50
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut db_path: Option<std::path::PathBuf> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--db" {
            let path = args
                .get(index + 1)
                .context("--db must be followed by a database path")?;
            db_path = Some(std::path::PathBuf::from(path));
            index += 2;
        } else {
            positionals.push(args[index].clone());
            index += 1;
        }
    }
    let operation = positionals
        .first()
        .context("usage: library_cli [--db <path>] save|get|delete|search|health")?;

    let db_path = db_path.unwrap_or_else(|| paths::prompts_dir().join(DEFAULT_DB_FILE));
    let store = PromptStore::open(db_path.clone()).with_context(|| {
        format!(
            "opening the prompt library at {} (set --db to point elsewhere)",
            db_path.display()
        )
    })?;

    let mut stdin = String::new();
    std::io::stdin()
        .read_to_string(&mut stdin)
        .context("reading the JSON document from stdin")?;

    let outcome: serde_json::Value = match operation.as_str() {
        "save" => {
            let record: LibraryRecord = serde_json::from_str(stdin.trim())
                .context("save expects a LibraryRecord JSON document on stdin")?;
            let record_id = store.save_library_record(record)?;
            json!({"ok": true, "record_id": record_id.to_string()})
        }
        "get" => {
            let record_id = parse_id(positionals.get(1))?;
            match store.get_library_record(record_id)? {
                Some(record) => json!({"ok": true, "record": record}),
                None => json!({"ok": false, "error": "not_found"}),
            }
        }
        "delete" => {
            let record_id = parse_id(positionals.get(1))?;
            let deleted = store.delete_library_record(record_id)?;
            json!({"ok": true, "deleted": deleted})
        }
        "search" => {
            let request: SearchRequest = serde_json::from_str(stdin.trim())
                .context("search expects a SearchRequest JSON document on stdin")?;
            let results = store.search_library(
                request.query.as_deref(),
                &request.filters,
                request.limit,
                request.offset,
            );
            json!({"ok": true, "count": results.len(), "results": results})
        }
        "health" => json!({"ok": true, "store": "open", "db": db_path.to_string_lossy()}),
        other => bail!("unknown operation: {other}"),
    };

    println!("{}", serde_json::to_string(&outcome)?);
    Ok(())
}

fn parse_id(argument: Option<&String>) -> Result<LibraryRecordId> {
    let raw = argument.context("get/delete need a record id")?;
    let uuid = Uuid::parse_str(raw.trim())
        .with_context(|| format!("record id must be a UUID, got: {raw}"))?;
    Ok(LibraryRecordId(uuid))
}
