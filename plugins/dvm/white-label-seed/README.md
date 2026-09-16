# White-Label DVM Plugin Template (Omega Marketplace)

A duplicate-able, spec-compliant DVM plugin template for the Omega marketplace.
It is the WP-M4 white-label template: others duplicate it, change the capability
and the service identity, and publish their own DVM listing.

- **Spec:** `openagents.plugin/v0` (OpenAgents plugin spec) + the documented
  Omega delta layer (`omega` block)
- **ABI:** Omega Plugin ABI v0 — `allocate(size: i32) -> i32`,
  `_start(ptr: i32, len: i32) -> i32` returning a pointer to an
  `[out_ptr: i32, out_len: i32]` result header
- **Tier:** PureCompute (no filesystem, no network, no ambient imports)
- **Build target:** `wasm32-unknown-unknown`, **Rust 1.95.0 pinned** by the
  `rust-toolchain.toml` in this directory (F-14)

---

## What a duplicator changes (the supported edit surface)

A duplicate is created with `dvm-plugin-cli init <name>` (or by copying this
directory). Before publishing, change exactly these things:

1. **Capability name** — the plugin id, directory name, and the `capability`
   tool's namespace. Set it at `init` time (`dvm-plugin-cli init <name>`); the
   name must be lowercase ASCII alphanumeric plus `_`. If you copy the
   directory instead, change `manifest.json` → `name` **and** `Cargo.toml` →
   `package.name` to the same value.
2. **Tools / capability tags** — `manifest.json` → `omega.capabilities`
   (e.g. `text/stats`, `video/summarize`). These tags drive discovery and the
   `capability` tool's `find`. Keep the `<domain>/<action>` lowercase-hyphen
   convention.
3. **Pricing** — `manifest.json` → `omega.cost_hint_msats` (0 = free hint;
   never a commitment; the WP-M3 L-402 gate is the real payment path).
4. **Description** — `manifest.json` → `description` (used verbatim in
   catalog discovery and the DVM service listing).
5. **Service identity (publish-time, pipeline-owned)** — the DVM `npub`
   (hex, public, never a secret), `relays` (Nostr relay URLs), and `kind`
   (NIP-90 job-request kind, default 5900). This is done by the publish
   pipeline, NOT by hand-editing the manifest alone:

   ```sh
   dvm-plugin-cli publish <dir> --npub <64-hex> --relay wss://relay.example [--relay wss://...] [--kind 5900]
   ```

   `publish` writes the identity into `manifest.json` → `omega.service`, rewrites
   `src/service_identity.rs` (the template's **single substitution point**) with
   the SAME identity, rebuilds and re-pins the artifact digest, and runs the
   mandatory identity-consistency assertion: the pinned artifact's reported
   `result.service` must equal the manifest's `omega.service`, or publish fails.
   `dvm-plugin-cli verify-identity <dir>` re-runs the assertion on an existing
   build (e.g. after a manifest edit).

6. **Input/output schemas and plugin logic** — `src/lib.rs` (the `run`
   function) and `manifest.json` → `input_schema` / `output_schema`. Keep the
   ABI exports (`allocate`, `_start`, `memory`) untouched.

## What must NOT change (the hard edges)

- **Permission tier** — keep the plugin **PureCompute**: `mounts: []`,
  `hosts: []`, zero imports, no WASI, no network. The host refuses anything
  else; a `Hosts` declaration is blocked by Omega policy and `Mounts` requires
  operator approval with no filesystem preopens. Do not raise the tier to get
  ambient access — there is none.
- **No secrets** — the manifest, the Wasm, and the service identity contain
  only PUBLIC data. `omega.service.npub` is a public Nostr key, never a secret.
  Never put credentials, API keys, or private keys in the manifest, the
  artifact, or the listing. If a capability needs a secret, the secret lives
  on the operator's machine behind an approved mechanism — never in the
  published artifact.
- **ABI v0** — do not change `abi_entry` (`_start`), `abi_alloc`
  (`allocate`), the exported `memory`, or the result-header convention. The
  host's shared validator enforces the exact signatures and the ABI policy
  gate (`omega.sdk.abi = "omega-plugin-abi-v0"`) refuses anything else.
- **`omega.sdk`** — leave `lang`/`target`/`abi` as the template declares them;
  the host's loadability depends on the ABI marker.
- **Digest pinning** — `artifact_digest` is written by `build`, never by hand.
  The digest pins the exact artifact bytes; tampering refuses load.

## Build / pin / inspect / test / install

```sh
dvm-plugin-cli build plugins/dvm/white-label-seed
dvm-plugin-cli inspect plugins/dvm/white-label-seed
dvm-plugin-cli test plugins/dvm/white-label-seed
dvm-plugin-cli install plugins/dvm/white-label-seed
dvm-plugin-cli list
```

`build` compiles the Wasm artifact and writes the SHA-256 digest into
`manifest.json` (`artifact_digest`). The catalog is `~/.openagents/plugins`
(spec-native) or `CODER_PLUGINS_DIR`.

## Layout

```
white-label-seed/
├── manifest.json         # openagents.plugin/v0 + omega delta layer
├── Cargo.toml            # standalone crate (detached from Omega workspace)
├── rust-toolchain.toml   # F-14 pin: Rust 1.95.0 + wasm32-unknown-unknown
├── src/lib.rs            # no_std + alloc, bump allocator, ABI exports
├── src/service_identity.rs # GENERATED by publish — single substitution point (F-04)
└── tests/fixtures/*.json # CLI `test` fixtures
```

## Toolchain and reproducibility

- `rust-toolchain.toml` pins Rust **1.95.0** so duplicators build under the
  same compiler as the Omega repo (F-14). Digests are reproducible for the
  same source + toolchain.
- `cargo build --locked` enforces the committed `Cargo.lock`; a fresh scaffold
  generates its lockfile offline from the local cargo cache before the locked
  build.
- `rustup target add wasm32-unknown-unknown` is an install-time network op on
  a fresh machine (documented F-08); the Rust build itself is fully offline.