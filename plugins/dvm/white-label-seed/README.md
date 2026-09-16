# white-label-seed

Minimal spec-compliant DVM plugin for the Omega marketplace — the white-label
template seed (WP-M1).

- **Spec:** `openagents.plugin/v0` (OpenAgents plugin spec)
- **ABI:** Omega Plugin ABI v0 — `allocate(size: i32) -> i32`,
  `_start(ptr: i32, len: i32) -> i32` returning a pointer to an
  `[out_ptr: i32, out_len: i32]` result header
- **Tier:** PureCompute (no fs, no network, no ambient imports)
- **Build target:** `wasm32-unknown-unknown` (Rust 1.95.0, no_std + alloc)

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
(spec-native).

## Layout

```
white-label-seed/
├── manifest.json        # openagents.plugin/v0 + omega delta layer
├── Cargo.toml           # standalone crate (detached from Omega workspace)
├── src/lib.rs           # no_std + alloc, bump allocator, ABI exports
└── tests/fixtures/*.json # CLI `test` fixtures
```