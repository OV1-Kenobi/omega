# sovereign-wallet — supervised Node 24/Effect wallet sidecar (WP-3)

Supervised wallet/identity worker for Omega's Sovereign Agents (Phase 2 wallet
wiring, work package 3). Owns the Wavelength `waved` wallet engine on
**signet only**, exposes a typed loopback protocol to the Rust supervisor
(`crates/sovereign_wallet`), and is **flag-gated OFF by default**
(`OMEGA_SOVEREIGN_WALLET=1` enables the Rust supervisor).

See `PROTOCOL.md` for the loopback contract and `waved-artifact.manifest.json`
for the pinned waved artifact (Q2 supply chain).

## Layout

```
src/protocol.ts       frame types + wavecli-style error envelope
src/wavelength.ts     waved child supervision + typed REST client (verified API shapes)
src/main.ts           Effect-composed runtime: env gate, ACLs, lock, idempotency, stdio loop
src/http.ts           loopback HTTP projections (bearer token, constant-time, limits)
src/lock.ts           sidecar lock, waved pid/lock, stale reaping, tree termination
src/idempotency.ts    idempotency ledger (node:sqlite; no preimage persistence)
src/redact.ts         named secret redaction (SEC-2026-046)
src/acl.ts            owner-only Windows ACL posture (SEC-2026-045)
scripts/check-invariants.mjs   adapted S1-S12 invariant suite (SEC-2026-051)
scripts/operator.mjs           operator-exercise CLI (Q3; WP-5 replaces with the dashboard)
test/                 unit + end-to-end protocol tests (fake waved fixture)
```

## Build, test, invariants

```powershell
npm install            # pinned: effect 3.22.1; dev: typescript 5.8.3, @types/node 24.13.3
npm run build          # tsc -> dist/main.js
npm test               # build + node --test (unit + protocol round-trip vs fake waved)
npm run invariants     # adapted S1-S12 suite
```

Runtime dependencies: `effect` (3 packages total) — well under the S8 budget
of 22. No JWT, no @sentry, no telemetry egress (S2/S3).

## Running

The sidecar is launched by the Rust supervisor (`crates/sovereign_wallet`)
with these env vars:

| Var | Meaning |
|---|---|
| `OMEGA_SOVEREIGN_WALLET_DATA_ROOT` | sidecar data root (required) |
| `OMEGA_SOVEREIGN_WALLET_NETWORK` | `signet` or `regtest`; `mainnet`/unset refused |
| `OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN` | 32-byte hex per-launch bearer token |
| `OMEGA_SOVEREIGN_WALLET_WAVED_BIN` | path to the pinned waved artifact |
| `OMEGA_SOVEREIGN_WALLET_GENERATION` | supervisor generation (default 1) |

Operator exercise (until WP-5 wires the dashboard):

```powershell
$env:OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN = "<32-byte hex>"
$env:OMEGA_SOVEREIGN_WALLET_WAVED_BIN = "<path to waved.exe>"
node scripts/operator.mjs <data-root> status
node scripts/operator.mjs <data-root> create-wallet "<password>"
node scripts/operator.mjs <data-root> unlock "<password>"
node scripts/operator.mjs <data-root> balance
node scripts/operator.mjs <data-root> make-invoice 10000 "demo"
node scripts/operator.mjs <data-root> activity
node scripts/operator.mjs <data-root> shutdown
```

## Wavelength integration notes (verified surface)

- `waved` (wavewalletrpc+swapruntime build) is the wallet engine; REST
  gateway `127.0.0.1:10031` (documented default), TLS+macaroon on signet,
  `admin.macaroon` under `<datadir>/data/signet/`.
- Signet endpoints auto-resolve (`signet.wavelength.lightning.finance:443`,
  `swap.signet.wavelength.lightning.finance:443`, Esplora
  `https://mempool-signet.testnet.lightningcluster.com/api`) — verified in
  the repo docs at v0.1.2-rc3 (`docs/signet.md`).
- The runtime wallet-API probe (`Status`) is mandatory: a `wavewalletrpc`-only
  build silently stubs `WalletService` (Unimplemented); the sidecar fails
  closed on that answer.