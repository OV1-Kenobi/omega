//! The ANY-runtime seam for the Omega ABI v0 conformance harness.
//!
//! A runtime adapter implements the declared host-side calling convention
//! behind this trait. The probe driver (`probe::run_probe`) is
//! runtime-independent: it drives any `AbiRuntime` through the exact same
//! byte-level call sequence and captures the raw output bytes.
//!
//! The shipped reference adapter is `WasmiReferenceRuntime` — a direct
//! implementation of the declared ABI over the wasmi interpreter (the same
//! execution pattern the CLI's F-04 identity assertion uses). It is the
//! reference baseline for byte-level comparison.
//!
//! A future Coder/OpenAgents runtime adapter (when Chris's Windows fix lands
//! and the real runtime is obtained under a capability manifest + founder
//! approval) implements the same trait against the real runtime; the probe,
//! the static contract checks, and the expected-fixture comparison are
//! unchanged.

use anyhow::{Context, Result};
use wasmi::{Engine, Linker, Module, Store};

/// The host-side calling convention any Omega ABI v0 runtime must provide.
///
/// Implementations are constructed with the manifest's exported names so the
/// seam honors `abi_alloc`/`abi_entry` rather than hardcoding them.
pub trait AbiRuntime {
    fn name(&self) -> &'static str;

    /// Load a Wasm module and prepare an instance (start function included).
    fn load(&mut self, wasm: &[u8]) -> Result<()>;

    /// Call the plugin's `allocate(size)` export. Returns the pointer or 0 on
    /// out-of-memory (the caller treats 0 as a probe failure).
    fn allocate(&mut self, size: u32) -> Result<u32>;

    /// Write bytes into the instance's linear memory at `ptr`.
    fn write_memory(&mut self, ptr: u32, bytes: &[u8]) -> Result<()>;

    /// Read `len` bytes from the instance's linear memory at `ptr`.
    fn read_memory(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>>;

    /// Call the plugin's `_start(ptr, len)` export. Returns the result-header
    /// pointer (`[out_ptr: i32, out_len: i32]` little-endian).
    fn start(&mut self, input_ptr: u32, input_len: u32) -> Result<u32>;
}

/// Reference adapter: the declared Omega ABI v0 calling convention over wasmi.
///
/// Mirrors `dvm-plugin-cli`'s proven `run_module_once` execution path
/// (instantiate -> allocate -> write input -> `_start` -> read header -> read
/// output) so the baseline is byte-identical to the F-04 assertion runtime.
pub struct WasmiReferenceRuntime {
    alloc_name: String,
    entry_name: String,
    store: Option<Store<()>>,
    instance: Option<wasmi::Instance>,
}

impl WasmiReferenceRuntime {
    pub fn new(alloc_name: &str, entry_name: &str) -> Self {
        Self {
            alloc_name: alloc_name.to_string(),
            entry_name: entry_name.to_string(),
            store: None,
            instance: None,
        }
    }
}

impl AbiRuntime for WasmiReferenceRuntime {
    fn name(&self) -> &'static str {
        "wasmi-reference"
    }

    fn load(&mut self, wasm: &[u8]) -> Result<()> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm).context("wasm module failed validation")?;
        let linker = Linker::<()>::new(&engine);
        let mut store = Store::new(&engine, ());
        let instance_pre = linker
            .instantiate(&mut store, &module)
            .context("instantiate failed")?;
        let instance = instance_pre.start(&mut store).context("start failed")?;
        self.store = Some(store);
        self.instance = Some(instance);
        Ok(())
    }

    fn allocate(&mut self, size: u32) -> Result<u32> {
        let store = self
            .store
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("runtime not loaded"))?;
        let instance = self
            .instance
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("runtime not loaded"))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut *store, &self.alloc_name)
            .with_context(|| format!("cannot resolve alloc export '{}'", self.alloc_name))?;
        Ok(alloc.call(&mut *store, size as i32)? as u32)
    }

    fn write_memory(&mut self, ptr: u32, bytes: &[u8]) -> Result<()> {
        let store = self
            .store
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("runtime not loaded"))?;
        let instance = self
            .instance
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("runtime not loaded"))?;
        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| anyhow::anyhow!("module does not export 'memory'"))?;
        memory
            .write(&mut *store, ptr as usize, bytes)
            .map_err(|e| anyhow::anyhow!("memory.write failed: {e}"))?;
        Ok(())
    }

    fn read_memory(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>> {
        let store = self
            .store
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("runtime not loaded"))?;
        let instance = self
            .instance
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("runtime not loaded"))?;
        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| anyhow::anyhow!("module does not export 'memory'"))?;
        let mut buf = vec![0u8; len as usize];
        memory
            .read(&mut *store, ptr as usize, &mut buf)
            .map_err(|e| anyhow::anyhow!("memory.read failed: {e}"))?;
        Ok(buf)
    }

    fn start(&mut self, input_ptr: u32, input_len: u32) -> Result<u32> {
        let store = self
            .store
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("runtime not loaded"))?;
        let instance = self
            .instance
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("runtime not loaded"))?;
        let entry = instance
            .get_typed_func::<(i32, i32), i32>(&mut *store, &self.entry_name)
            .with_context(|| format!("cannot resolve entry export '{}'", self.entry_name))?;
        Ok(entry.call(&mut *store, (input_ptr as i32, input_len as i32))? as u32)
    }
}

/// Resolve a runtime adapter by name. Only the reference adapter ships today;
/// a Coder-runtime adapter is the named follow-on (see README.md).
pub fn runtime_by_name(name: &str, alloc_name: &str, entry_name: &str) -> Option<Box<dyn AbiRuntime>> {
    match name {
        "wasmi" | "wasmi-reference" => Some(Box::new(WasmiReferenceRuntime::new(
            alloc_name,
            entry_name,
        ))),
        _ => None,
    }
}

/// Names of the shipped runtime adapters.
pub fn known_runtimes() -> Vec<&'static str> {
    vec!["wasmi-reference"]
}