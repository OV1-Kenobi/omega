//! Byte-level behavioral probe: drives ANY `AbiRuntime` through the declared
//! Omega ABI v0 call sequence and captures the raw output bytes.

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::runtime::AbiRuntime;

/// The 8-byte result header convention: `[out_ptr: i32, out_len: i32]`
/// little-endian. A header with `out_len == 0` signals an execution error.
pub const RESULT_HEADER_BYTES: usize = 8;

/// The bounded error-body read when `out_len == 0` (mirrors the CLI).
pub const MAX_ERROR_BODY_BYTES: usize = 512;

#[derive(Debug, Clone, Serialize)]
pub struct ProbeOutput {
    pub input_bytes: usize,
    pub alloc_ptr: u32,
    pub header_ptr: u32,
    pub header_hex: String,
    pub out_ptr: u32,
    pub out_len: u32,
    pub output_bytes: usize,
    pub output_json: serde_json::Value,
}

/// Run the exact ABI v0 call sequence on any runtime:
/// allocate(input_len) -> write input -> _start(ptr, len) -> read 8-byte
/// header -> read [out_ptr, out_len) -> parse output JSON.
pub fn run_probe(
    runtime: &mut dyn AbiRuntime,
    input: &serde_json::Value,
) -> Result<ProbeOutput> {
    let input_bytes = serde_json::to_vec(input).context("serialize probe input")?;
    let len = input_bytes.len() as u32;

    let alloc_ptr = runtime.allocate(len)?;
    if alloc_ptr == 0 {
        bail!("allocate returned 0 (out of memory)");
    }
    runtime
        .write_memory(alloc_ptr, &input_bytes)
        .context("write probe input")?;

    let header_ptr = runtime.start(alloc_ptr, len).context("_start trapped")?;
    let header = runtime
        .read_memory(header_ptr, RESULT_HEADER_BYTES as u32)
        .context("read result header")?;
    let out_ptr = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let out_len = u32::from_le_bytes(header[4..8].try_into().unwrap());

    if out_len == 0 {
        let err_len = out_len.min(MAX_ERROR_BODY_BYTES as u32);
        let err_body = if err_len > 0 {
            String::from_utf8_lossy(&runtime.read_memory(out_ptr, err_len)?).into_owned()
        } else {
            String::new()
        };
        bail!("plugin returned zero-length result (execution error; body: {err_body})");
    }

    let output_bytes = runtime.read_memory(out_ptr, out_len).context("read output")?;
    let output_json: serde_json::Value =
        serde_json::from_slice(&output_bytes).context("plugin output is not valid JSON")?;

    Ok(ProbeOutput {
        input_bytes: input_bytes.len(),
        alloc_ptr,
        header_ptr,
        header_hex: header.iter().map(|b| format!("{b:02x}")).collect(),
        out_ptr,
        out_len,
        output_bytes: output_bytes.len(),
        output_json,
    })
}