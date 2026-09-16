# demo_video_transcription — DVM Plugin (white-label template duplicate)

Created by `dvm-plugin-cli init` from the Omega white-label DVM template for
WP-M5a of `15-plan-omega-dvm-marketplace`: the demo plugin published with a
REAL (non-placeholder) service identity through the F-04 pipeline, so the
two-machine L-402 demo exercises the identity-consistency property end to end.

This is a **gateable video-transcription capability plugin**: the artifact
carries the `video/transcription` capability tag and the DVM service identity
that the marketplace listing advertises, and returns a deterministic
PureCompute result envelope (text stats + `result.service`) when machine B's
host runs it. The actual video-transcription computation runs on machine B
through the L-402-gated capability adapter (source-summarization in the WP-M5a
paddock; the video-transcription adapter lands at M5b once the model is
confirmed cached and the founder authorizes live runs — CALL-CONTRACT.md §5).

## What to change before publishing

1. **Capability name** — already set at `init` (this directory + manifest name).
   To rename, change `manifest.json` -> `name` AND `Cargo.toml` -> `package.name`.
2. **Tools / capability tags** — `manifest.json` -> `omega.capabilities`
   (e.g. `text/stats`). Tags drive discovery and the `capability` tool's `find`.
3. **Pricing** — `manifest.json` -> `omega.cost_hint_msats` (0 = free hint;
   never a commitment; the L-402 gate is the real payment path).
4. **Description** — `manifest.json` -> `description` (used verbatim in the
   catalog and the DVM service listing).
5. **Service identity** — publish-time, pipeline-owned:

   ```sh
   dvm-plugin-cli publish <dir> --npub <64-hex> --relay wss://relay.example [--relay wss://...] [--kind 5900]
   ```

   `publish` writes the identity into `manifest.json` -> `omega.service`,
   rewrites `src/service_identity.rs` (the single substitution point) with the
   SAME identity, rebuilds + re-pins the digest, and runs the mandatory
   identity-consistency assertion (artifact-reported identity == manifest
   identity; mismatch fails publish). `dvm-plugin-cli verify-identity <dir>`
   re-runs the assertion on an existing build.

6. **Plugin logic + schemas** — `src/lib.rs` (`run`) and `manifest.json`
   `input_schema`/`output_schema`. Keep the ABI exports untouched.

## What must NOT change

- **Permission tier** — stay PureCompute: `mounts: []`, `hosts: []`, zero
  imports, no WASI, no network. The host refuses anything else.
- **No secrets** — manifest, Wasm, and service identity contain PUBLIC data
  only. Never put credentials or keys in the artifact or the listing.
- **ABI v0** — do not change `abi_entry`/`abi_alloc`/`memory`/result-header
  convention; the host's shared validator and ABI policy gate enforce it.
- **`omega.sdk`** — leave `lang`/`target`/`abi` as the template declares them.
- **Digest pinning** — `artifact_digest` is written by `build`, never by hand.

## Build / pin / inspect / test / install

```sh
dvm-plugin-cli build <dir>
dvm-plugin-cli inspect <dir>
dvm-plugin-cli test <dir>
dvm-plugin-cli install <dir>
dvm-plugin-cli list
```

Toolchain: Rust 1.95.0 pinned by `rust-toolchain.toml` (F-14); builds are
offline with `--locked`.
