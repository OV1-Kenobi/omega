//! dvm-plugin-host runtime — wasmtime 36.0.12 executor with enforced bounds.
//!
//! WP-M2b / F-03: memory and time bounds are enforced AT THE ENFORCEMENT POINT
//! (the runtime), not merely inspected:
//!
//! - **Memory**: `StoreLimitsBuilder::memory_size(memory_max_mib)` via
//!   `Store::limiter` with `trap_on_grow_failure(true)` (the per-store
//!   enforcement point). A plugin that grows linear memory beyond the
//!   manifest bound traps with `memory_exceeded`.
//! - **Time (hard kill)**: `Config::epoch_interruption(true)` +
//!   `Store::set_epoch_deadline(1)`; a watchdog thread calls
//!   `Engine::increment_epoch()` after `timeout_ms`. The running instance traps
//!   at the next epoch checkpoint -> `timeout`. This is a hard kill, not a
//!   cooperative yield.
//! - **Time (CPU bound)**: `Config::consume_fuel(true)` +
//!   `Store::set_fuel(budget)`; a CPU-bound loop exhausts the budget and traps
//!   deterministically with "all fuel consumed" -> `timeout`.
//!
//! The ABI call flow mirrors the shared validator/test harness:
//! `allocate(len)` -> write input bytes -> `_start(ptr, len)` -> read the
//! 8-byte result header `[out_ptr, out_len]` -> read output bytes.

use anyhow::Result;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Limits applied at runtime. `memory_max_mib`/`timeout_ms` come from the
/// manifest (the plugin's request); the host may impose stricter ceilings.
#[derive(Debug, Clone)]
pub struct RuntimeLimits {
    pub memory_max_mib: u64,
    pub timeout_ms: u64,
    /// Optional explicit fuel budget (instructions). When `None`, a generous
    /// budget proportional to `timeout_ms` is used (1M instructions/ms).
    pub fuel_budget: Option<u64>,
}

/// Partial host-level ceilings; `None` fields fall back to manifest values.
#[derive(Debug, Clone, Default)]
pub struct LimitsOverride {
    pub memory_max_mib: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub fuel_budget: Option<u64>,
}

impl RuntimeLimits {
    /// Derive a default generous CPU budget from the wall-clock timeout.
    fn effective_fuel_budget(&self) -> u64 {
        self.fuel_budget
            .unwrap_or_else(|| self.timeout_ms.saturating_mul(1_000_000))
    }
}

/// Runtime outcome of one plugin call.
#[derive(Debug)]
pub enum RunFailure {
    /// Memory growth beyond the enforced limit (memory_exceeded).
    MemoryExceeded(String),
    /// Wall-clock hard kill (timeout) or fuel exhaustion (timeout).
    Timeout(String),
    /// Any other trap or ABI-level failure (abi_error).
    AbiError(String),
}

impl RunFailure {
    pub fn code(&self) -> &'static str {
        match self {
            RunFailure::MemoryExceeded(_) => "memory_exceeded",
            RunFailure::Timeout(_) => "timeout",
            RunFailure::AbiError(_) => "abi_error",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            RunFailure::MemoryExceeded(m) | RunFailure::Timeout(m) | RunFailure::AbiError(m) => m,
        }
    }
}

/// Execute one plugin call inside a fresh wasmtime instance with enforced
/// bounds. `module_bytes` MUST already have passed the shared validator
/// (`dvm_plugin_core::validate_plugin`); this function re-instantiates with an
/// EMPTY linker so a validator bug cannot grant ambient capability.
///
/// Returns the plugin's raw output bytes (the structured answer JSON) on
/// success. On failure returns the mapped `RunFailure`.
pub fn execute(
    module_bytes: &[u8],
    input_json: &[u8],
    manifest: &dvm_plugin_core::Manifest,
    limits: &RuntimeLimits,
) -> Result<Vec<u8>, RunFailure> {
    // -- Engine config: fuel + epoch interruption -------------------------
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    let engine = Engine::new(&config).map_err(|e| RunFailure::AbiError(format!("engine: {e}")))?;
    let module = Module::new(&engine, module_bytes)
        .map_err(|e| RunFailure::AbiError(format!("module: {e}")))?;

    // -- Store with per-store limits (the enforcement point) ---------------
    let mem_bytes: usize = (limits.memory_max_mib as usize)
        .checked_mul(1024 * 1024)
        .ok_or_else(|| RunFailure::AbiError("memory_max_mib overflow".into()))?;
    // The limiter lives in the store's data (`T = StoreLimits`), per the
    // wasmtime 36 API: `Store::limiter(|state| &mut state.limits)`.
    let store_limits = StoreLimitsBuilder::new()
        .memory_size(mem_bytes)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(&engine, store_limits);
    store.limiter(|state| state as &mut dyn wasmtime::ResourceLimiter);
    store
        .set_fuel(limits.effective_fuel_budget())
        .map_err(|e| RunFailure::AbiError(format!("set_fuel: {e}")))?;
    // One tick beyond current: the watchdog's increment trips the deadline.
    // (Returns (), not Result, in wasmtime 36.)
    store.set_epoch_deadline(1);

    // -- Watchdog: hard kill at timeout_ms ---------------------------------
    // The watchdog waits on a cancel channel; if the guest finishes first the
    // caller sends the cancel and the watchdog exits without incrementing the
    // epoch. If the guest is still running at `deadline`, the watchdog
    // increments the engine epoch and the running instance traps at its next
    // epoch checkpoint (hard kill).
    let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
    let watchdog_engine = engine.clone();
    let deadline = limits.timeout_ms;
    let watchdog = thread::spawn(move || {
        match cancel_rx.recv_timeout(Duration::from_millis(deadline)) {
            Ok(()) => {}       // guest finished; no kill needed
            Err(_) => watchdog_engine.increment_epoch(), // hard kill
        }
    });

    // Run the guest. Every early-return path must still cancel + join the
    // watchdog; wrap the guest body so the cleanup runs unconditionally.
    let mut guest = || -> Result<Vec<u8>, RunFailure> {
        // -- Instantiate with an EMPTY linker (zero ambient imports) -----------
        // wasmtime 36: `Linker::instantiate` runs the start function inline and
        // returns the started Instance directly.
        let linker = Linker::<StoreLimits>::new(&engine);
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| map_trap(&e, "instantiate"))?;

        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, &manifest.abi_alloc)
            .map_err(|e| RunFailure::AbiError(format!("get alloc: {e}")))?;
        let entry = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, &manifest.abi_entry)
            .map_err(|e| RunFailure::AbiError(format!("get entry: {e}")))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| RunFailure::AbiError("module does not export 'memory'".into()))?;

        // -- Allocate + write input ---------------------------------------------
        let len: i32 = input_json
            .len()
            .try_into()
            .map_err(|_| RunFailure::AbiError("input too large for ABI i32 len".into()))?;
        let ptr = alloc
            .call(&mut store, len)
            .map_err(|t| map_trap(&t, "allocate"))?;
        if ptr == 0 {
            return Err(RunFailure::AbiError(
                "allocate returned 0 (plugin-level out of memory)".into(),
            ));
        }
        memory
            .write(&mut store, ptr as usize, input_json)
            .map_err(|e| RunFailure::AbiError(format!("memory.write: {e}")))?;

        // -- Call _start ---------------------------------------------------------
        // Measure elapsed around the guest execution only (compilation of the
        // module is host-side setup, not guest execution time).
        let started = Instant::now();
        let header_ptr = entry
            .call(&mut store, (ptr, len))
            .map_err(|t| map_trap(&t, "_start"))?;

        // -- Read the 8-byte result header ----------------------------------------
        let mut header = [0u8; 8];
        let header_ptr_usize = header_ptr as usize;
        let mem_size = memory.data_size(&store);
        if header_ptr_usize
            .checked_add(8)
            .map(|end| end > mem_size)
            .unwrap_or(true)
        {
            return Err(RunFailure::AbiError(format!(
                "result header at {header_ptr_usize} exceeds memory size {mem_size}"
            )));
        }
        memory
            .read(&store, header_ptr_usize, &mut header)
            .map_err(|e| RunFailure::AbiError(format!("memory.read header: {e}")))?;
        let out_ptr = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let out_len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;

        // -- Read output -----------------------------------------------------------
        if out_len == 0 {
            // Plugin signalled an execution error; read a bounded error body.
            let mut err_body = [0u8; 512];
            let read_len = err_body.len().min(mem_size.saturating_sub(out_ptr));
            memory.read(&store, out_ptr, &mut err_body[..read_len]).ok();
            let err_text = String::from_utf8_lossy(&err_body[..read_len]);
            return Err(RunFailure::AbiError(format!(
                "plugin returned zero-length result (error body: {err_text})"
            )));
        }
        let end = out_ptr
            .checked_add(out_len)
            .ok_or_else(|| RunFailure::AbiError("output length overflow".into()))?;
        if end > mem_size {
            return Err(RunFailure::AbiError(format!(
                "output [{}..{}) exceeds memory size {mem_size}",
                out_ptr, end
            )));
        }
        let mut out_buf = vec![0u8; out_len];
        memory
            .read(&store, out_ptr, &mut out_buf)
            .map_err(|e| RunFailure::AbiError(format!("memory.read output: {e}")))?;

        let _elapsed = started.elapsed();
        Ok(out_buf)
    };

    let result = guest();
    // Always cancel + join the watchdog: no dangling threads, no leaked
    // increment after a successful run.
    let _ = cancel_tx.send(());
    let _ = watchdog.join();
    result
}

/// Map a wasmtime error to the contract's error taxonomy.
///
/// Strategy: first match the structured `wasmtime_environ::Trap` variant when
/// one is present (fuel exhaustion -> timeout, epoch hard kill -> timeout).
/// Otherwise walk the whole anyhow chain looking for the limiter's memory
/// growth message (the `memory_max_mib` enforcement point), falling back to
/// the message text.
fn map_trap(err: &anyhow::Error, at: &str) -> RunFailure {
    if let Some(trap) = err.downcast_ref::<wasmtime::Trap>() {
        return match trap {
            wasmtime::Trap::OutOfFuel => {
                RunFailure::Timeout(format!("{at}: fuel budget exhausted ({trap})"))
            }
            wasmtime::Trap::Interrupt => {
                RunFailure::Timeout(format!("{at}: epoch deadline (hard kill at timeout_ms) ({trap})"))
            }
            other => RunFailure::AbiError(format!("{at}: trap ({other:?})")),
        };
    }
    // Walk the full cause chain: the limiter's memory-growth bail is attached
    // below the wasm backtrace context.
    let mut chain_text = String::new();
    for cause in err.chain() {
        let text = cause.to_string();
        let lower = text.to_lowercase();
        if lower.contains("forcing trap when growing memory")
            || lower.contains("memory growth failure")
        {
            return RunFailure::MemoryExceeded(format!(
                "{at}: memory.grow beyond memory_max_mib ({text})"
            ));
        }
        if lower.contains("all fuel consumed") {
            return RunFailure::Timeout(format!("{at}: fuel budget exhausted ({text})"));
        }
        if !chain_text.is_empty() {
            chain_text.push_str("; ");
        }
        chain_text.push_str(&text);
    }
    RunFailure::AbiError(format!("{at}: trap ({chain_text})"))
}