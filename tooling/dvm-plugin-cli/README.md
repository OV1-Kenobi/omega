# dvm-plugin-cli

Omega DVM plugin authoring tool: `init / build / inspect / test / install / list`,
plus the WP-M4 F-04 service-identity pipeline: `publish / verify-identity`.

Command surface mirrors `coder-cli plugin` per the OpenAgents plugin spec
(https://openagents.com/docs/plugins). The tool is the WP-M1/WP-M2/WP-M4
toolchain for authoring, pinning, inspecting, testing, installing, and
publishing DVM marketplace plugins on `feat/dvm-marketplace`.

## Build

Offline build (all dependencies are pinned in `Cargo.lock` and vendored in the
local cargo cache):

```powershell
cargo build --release --locked --offline
```

> **Install-time egress (F-08, documented):** `dvm-plugin-cli build` runs
> `rustup target add wasm32-unknown-unknown` once per machine. On a fresh
> machine this performs a network download of the target component; afterwards
> it is a no-op. The Rust build itself is fully offline.

## Usage

```
dvm-plugin-cli init <name>              Scaffold a new plugin from the white-label seed template
dvm-plugin-cli build <dir>              Build the Wasm artifact and pin the SHA-256 digest into manifest.json
dvm-plugin-cli inspect <dir>            Full shared validation (digest, imports, exports/ABI, tier, schemas)
dvm-plugin-cli test <dir>               Run test fixtures against the compiled artifact
dvm-plugin-cli install <dir>            Install into the catalog (full validation required)
dvm-plugin-cli list                     List installed plugins, re-verifying digests (F-10)
dvm-plugin-cli publish <dir> --npub <64-hex> --relay wss://... [--relay ...] [--kind 5900]
                                        F-04 publish pipeline: identity substitution + rebuild + pin
                                        + mandatory identity-consistency assertion (fails on mismatch)
dvm-plugin-cli verify-identity <dir>    Re-run the identity-consistency assertion on an existing build
```

The catalog is `~/.openagents/plugins` or the directory set in
`CODER_PLUGINS_DIR`.

## Publish (F-04 service identity)

The WP-M2b security finding F-04 requires that the identity the marketplace
advertises (manifest `omega.service`) and the identity the plugin reports in
its own output (`result.service`) are the same value, produced from ONE
publish-time input, with the digest pinned over the identity-bearing artifact.

`publish` implements that (WP-M2b design Option A):

1. Validate the identity inputs (`--npub` = exactly 64 hex chars, non-placeholder;
   `--relay` = wss:// or ws://, at least one; `--kind` = 5000-5999, default 5900).
2. Write the identity into `manifest.json` → `omega.service`.
3. Rewrite `src/service_identity.rs` (the template's **single substitution
   point**) with the SAME identity — the manifest value becomes the input to
   the artifact, not an independent compiled-in constant.
4. Rebuild + re-pin the digest (`build`) so the pinned bytes carry the identity.
5. Run the **mandatory identity-consistency assertion**: execute the pinned
   artifact and require `result.service == omega.service` (npub, relays, kind).
   Any mismatch **fails the publish**.
6. Placeholder guard: an all-zero/empty npub never reaches a published artifact.

`verify-identity <dir>` re-runs steps 5-6 on an existing build without writing
anything — the fail-closed re-verification hook for the Security-Agent gate and
for detecting manifest/artifact drift.

## Hardening (WP-M2 security review conditions)

| Finding | Status |
|---|---|
| F-01 path traversal in `artifact_path` | Fixed — `confine_artifact_path` rejects absolute paths, `..`, subdirectories |
| F-02 install skips validation | Fixed — `install` runs the same `dvm_plugin_core::validate_plugin` as `inspect` |
| F-04 service identity contradiction | Fixed (WP-M4) — `publish`/`verify-identity` single-substitution-point + mandatory consistency assertion |
| F-05 ABI signatures not verified | Fixed — exact `(i32)->i32` / `(i32,i32)->i32` signatures enforced |
| F-07 no JSON-schema validation | Fixed — fixture input/output validated against manifest schemas |
| F-08 `--locked` not enforced | Fixed — `build` uses `--locked`; fresh scaffolds get an offline lockfile first |
| F-10 list does not re-verify digests | Fixed — `list` re-verifies and surfaces failures |
| F-11 non-ASCII init names | Fixed — `init` rejects non-ASCII plugin names |
| F-14 build reproducibility | Fixed (WP-M4) — `init` scaffolds ship `rust-toolchain.toml` pinning Rust 1.95.0 |

The validator logic lives in `../dvm-plugin-core` and is shared **by
construction** with the Omega plugin host (`../dvm-plugin-host`): the tool and
the host cannot disagree (WP-M2 condition CH-01/F-02).

## Files

- `src/main.rs` — CLI command implementations (incl. the F-04 publish pipeline)
- `src/template_lib.rs` — white-label seed template source embedded by `init`
  (keep in sync with `plugins/dvm/white-label-seed/src/lib.rs`)
- `../dvm-plugin-core/` — shared manifest model, validator, catalog reader