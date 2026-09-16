//! Omega ABI v0 conformance harness (decision 13, agent track).
//!
//! Runs a template plugin against ANY runtime that implements the DECLARED
//! Omega Plugin ABI v0 calling convention, so byte-level conformance can be
//! verified the moment a working Coder/OpenAgents runtime exists.
//!
//! The declared ABI v0 (WP-M1 01-manifest-schema.md, authoritative per founder
//! decision 2b):
//!   - `allocate(size: i32) -> i32`  — bump allocator, returns a pointer to
//!     `size` zero-initialized bytes, or 0 on out-of-memory.
//!   - `_start(ptr: i32, len: i32) -> i32` — reads the JSON input at
//!     `[ptr, ptr+len)`, computes, writes the JSON output, and returns a
//!     pointer to an 8-byte result header `[out_ptr: i32, out_len: i32]` in
//!     linear memory. A header with `out_len == 0` signals an execution error.
//!   - exported `memory`.
//!   - manifest marker `omega.sdk.abi == "omega-plugin-abi-v0"`.
//!
//! The harness is runtime-agnostic by construction:
//!   - `abi::check_static_contract` verifies the runtime-independent parts of
//!     the ABI contract (exports, exact signatures, memory, marker) on any
//!     artifact, using the SHARED validator (`dvm-plugin-core`) so it cannot
//!     disagree with the CLI/host.
//!   - `runtime::AbiRuntime` is the ANY-runtime seam. The shipped
//!     `WasmiReferenceRuntime` implements the declared calling convention and
//!     is the reference baseline. A Coder-runtime adapter implements the same
//!     seam against the real runtime (a named follow-on requiring the real
//!     runtime + capability manifest + founder approval — see README.md).
//!   - `probe::run_probe` drives ANY `AbiRuntime` through the exact same
//!     byte-level call sequence and captures the raw output bytes, so the
//!     reference baseline and a future real-runtime run can be compared
//!     byte-for-byte.
//!
//! Status: RV-M1-01 remains CARRIED (not closed) — this harness is the agent
//! track's instrument, not the closure. Closure is by real-runtime proof or
//! explicit founder declaration only (LRN-2026-153).

pub mod abi;
pub mod check;
pub mod probe;
pub mod runtime;