# dvm-conformance-harness

Omega ABI v0 conformance harness (WP-M5a; plan `15-plan-omega-dvm-marketplace`;
founder decision 13, **agent track**).

Runs a template plugin against **ANY runtime that implements the declared
Omega Plugin ABI v0**, so byte-level conformance can be verified the moment a
working Coder/OpenAgents runtime exists.

**Status: RV-M1-01 CARRIED (not closed).** This harness is the agent track's
instrument, not the closure. The shipped `wasmi-reference` adapter is the
reference baseline. Closure is by real-runtime proof (a Coder-runtime adapter
driven through this harness) or explicit founder declaration only
(LRN-2026-153). The upstream runtime is **NOT fetched** in this WP — see
"Chris-runtime requirements" below.

## The declared ABI v0 (the contract this harness verifies)

Per WP-M1 (`01-manifest-schema.md`) and authoritative per founder decision 2b:

- `allocate(size: i32) -> i32` — bump allocator; returns a pointer to `size`
  zero-initialized bytes, or `0` on out-of-memory.
- `_start(ptr: i32, len: i32) -> i32` — reads the JSON input at
  `[ptr, ptr+len)`, computes, writes the JSON output, and returns a pointer to
  an 8-byte result header `[out_ptr: i32, out_len: i32]` in linear memory. A
  header with `out_len == 0` signals an execution error.
- Exported `memory`.
- Manifest marker `omega.sdk.abi == "omega-plugin-abi-v0"`.

## Build (offline, pinned toolchain)

The crate is standalone (detached from the Omega workspace, same pattern as
`dvm-plugin-cli`/`dvm-plugin-core`/`dvm-plugin-host`). All dependencies are
pinned in `Cargo.lock` and vendored in the local cargo cache; **no new
third-party dependency** was introduced (wasmi, serde, serde_json, anyhow,
clap, sha2/hex via `dvm-plugin-core` are all already used by the tooling).

```powershell
cargo build --release --locked --offline
```

Rust 1.95.0 is pinned by the Omega repo's `rust-toolchain.toml` (the crate
builds under the worktree, which inherits the pin).

## Usage

```
dvm-conformance-harness check <plugin-dir> [--runtime wasmi-reference] [--input <json> | --input-file <f>] [--expected-file <f>] [--json]
dvm-conformance-harness list-runtimes
```

`check` does, in order:

1. **Shared validation** — `dvm-plugin-core::validate_plugin` (the exact gate
   the CLI and the Omega host enforce; tool/host/harness cannot disagree —
   WP-M2 condition CH-01/F-02).
2. **Static ABI contract** — the `omega.sdk.abi` marker and the exact ABI
   signatures (`(i32)->i32` / `(i32,i32)->i32`) + exported memory, enforced by
   the shared validator's `verify_abi_signatures`.
3. **Byte-level probe** — drives the selected runtime through the exact ABI
   call sequence (`allocate` -> write input -> `_start` -> read 8-byte header
   -> read `[out_ptr, out_len)`), captures the raw output bytes, and parses
   the output JSON.
4. **Expected-fixture comparison** (when `--expected-file` is supplied) —
   structural JSON equality on the probe output.

Exit codes: `0` = CONFORMANT, `1` = conformance FAIL, `2` = usage error.
With `--json`, stdout carries ONLY the machine-callable report (LRN-2026-130);
all diagnostics go to stderr.

### Reference baseline example

```powershell
# Demo plugin (published with a real identity through F-04):
dvm-conformance-harness check ..\..\plugins\dvm\demo_video_transcription
# => verdict: CONFORMANT (wasmi-reference)

# White-label seed, machine-callable report:
dvm-conformance-harness check ..\..\plugins\dvm\white-label-seed --json
```

## The ANY-runtime seam (how a Coder runtime plugs in)

`src/runtime.rs` defines the runtime seam:

```rust
pub trait AbiRuntime {
    fn name(&self) -> &'static str;
    fn load(&mut self, wasm: &[u8]) -> Result<()>;
    fn allocate(&mut self, size: u32) -> Result<u32>;
    fn write_memory(&mut self, ptr: u32, bytes: &[u8]) -> Result<()>;
    fn read_memory(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>>;
    fn start(&mut self, input_ptr: u32, input_len: u32) -> Result<u32>;
}
```

The probe driver (`src/probe.rs`) is runtime-independent: it drives ANY
`AbiRuntime` through the exact same byte-level call sequence. The shipped
`WasmiReferenceRuntime` implements the declared calling convention over wasmi
(mirroring the CLI's F-04 assertion execution path) and is the **reference
baseline**. A real-runtime adapter implements the same seam against the real
runtime; the probe, static contract checks, and expected-fixture comparison
are unchanged.

## Chris-runtime requirements (what the real runtime must provide)

When Chris's Windows Coder/OpenAgents runtime fix lands, the founder track
(routing the working build to the harness — decision 13) needs the following
from the real runtime before byte-level conformance can be verified:

1. **A loadable build for Windows** — the working `coder-cli` (or equivalent
   host binary) that can load a `.wasm` module. The Windows build must be the
   exact artifact Chris confirms as the intended runtime.
2. **Host-side call capability over the declared ABI** — the runtime must
   expose, in-process or via a thin adapter, the ability to: instantiate a
   module, call `allocate(size)`, write into the instance's linear memory,
   call `_start(ptr, len)`, and read linear memory. This is exactly the
   `AbiRuntime` seam; an adapter (Node, Rust, or CLI-wrapping) that maps the
   runtime's real API onto it is the only new code needed.
3. **No ambient sandbox downgrade** — the real runtime's plugin sandbox must
   not grant filesystem/network/host imports to PureCompute plugins (the
   declared tier contract). Byte-level ABI conformance is verified with the
   same template fixture (`fixtures/white-label-seed`), so a capability
   difference between runtimes shows up as a probe or output mismatch.
4. **A capability manifest + founder approval BEFORE the runtime is fetched
   or activated** (WP-M2b §11 carry, WP-M4 review condition 8). The upstream
   fetch is a NEW third-party component; it is NOT authorized by this WP.
   Recorded as the named follow-on: "fetch upstream Coder/OpenAgents runtime
   under an approved capability manifest + founder approval, then add a
   `coder` runtime adapter to this harness and run the byte-level comparison
   against the `wasmi-reference` baseline."

### Follow-on (recorded, NOT executed — per the brief and decision 13)

- **Fetch upstream runtime**: NOT done in WP-M5a. Requires the capability
  manifest + founder approval. Owner: Engineering-Lead (founder track via
  Chris; agent track prepares this harness, which is done).
- **Add `coder` runtime adapter**: after the fetch, implement `AbiRuntime` for
  the real runtime and re-run `check` against both plugins; the expected
  output must match the reference baseline byte-for-byte (JSON structural
  equality at minimum, raw output bytes recorded in both reports).

## Files

- `src/lib.rs` — crate docs (ABI contract + status)
- `src/abi.rs` — runtime-independent static ABI contract checks
- `src/runtime.rs` — the `AbiRuntime` seam + `WasmiReferenceRuntime`
- `src/probe.rs` — the byte-level probe driver
- `src/check.rs` — full conformance check (validate -> static -> probe -> expected)
- `src/main.rs` — CLI
- `tests/conformance.rs` — 4 integration tests
- `fixtures/white-label-seed/` — byte-identical copy of the seed
  `manifest.json` + `plugin.wasm` (self-contained test fixtures)