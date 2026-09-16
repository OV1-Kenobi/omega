# dvm-plugin-cli

Omega DVM plugin authoring tool: `init / build / inspect / test / install / list`.

Command surface mirrors `coder-cli plugin` per the OpenAgents plugin spec
(https://openagents.com/docs/plugins). The tool is the WP-M1/WP-M2 toolchain for
authoring, pinning, inspecting, testing, and installing DVM marketplace plugins
on `feat/dvm-marketplace`.

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
dvm-plugin-cli init <name>          Scaffold a new plugin from the white-label seed template
dvm-plugin-cli build <dir>          Build the Wasm artifact and pin the SHA-256 digest into manifest.json
dvm-plugin-cli inspect <dir>        Full shared validation (digest, imports, exports/ABI, tier, schemas)
dvm-plugin-cli test <dir>           Run test fixtures against the compiled artifact
dvm-plugin-cli install <dir>        Install into the catalog (full validation required)
dvm-plugin-cli list                 List installed plugins, re-verifying digests (F-10)
```

The catalog is `~/.openagents/plugins` or the directory set in
`CODER_PLUGINS_DIR`.

## Hardening (WP-M2, security review conditions)

| Finding | Status |
|---|---|
| F-01 path traversal in `artifact_path` | Fixed — `confine_artifact_path` rejects absolute paths, `..`, subdirectories |
| F-02 install skips validation | Fixed — `install` runs the same `dvm_plugin_core::validate_plugin` as `inspect` |
| F-05 ABI signatures not verified | Fixed — exact `(i32)->i32` / `(i32,i32)->i32` signatures enforced |
| F-07 no JSON-schema validation | Fixed — fixture input/output validated against manifest schemas |
| F-08 `--locked` not enforced | Fixed — `build` uses `--locked`; fresh scaffolds get an offline lockfile first |
| F-10 list does not re-verify digests | Fixed — `list` re-verifies and surfaces failures |
| F-11 non-ASCII init names | Fixed — `init` rejects non-ASCII plugin names |

The validator logic lives in `../dvm-plugin-core` and is shared **by
construction** with the Omega plugin host (`../dvm-plugin-host`): the tool and
the host cannot disagree (WP-M2 condition CH-01/F-02).

## Files

- `src/main.rs` — CLI command implementations
- `src/template_lib.rs` — white-label seed template source embedded by `init`
- `../dvm-plugin-core/` — shared manifest model, validator, catalog reader