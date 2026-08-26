# Sovereign Wallet Sidecar — Loopback Protocol Contract

Schema: `openagents.omega.sovereign-wallet.v1` · Protocol version: `1` · Service version: `0.1.0`
Authority: WP-1 system design §2 (`02-wp1-system-design.md`); security conditions SEC-2026-045..053.

## 1. Transport

The sidecar speaks **newline-framed JSON over stdio** to its supervising Rust
process (`crates/sovereign_wallet`). One JSON object per line; frames are
bounded at **64 KiB** (`MAX_FRAME_BYTES`). stderr is free-form diagnostic
output, redacted, and never parsed as protocol. The stdio pipe is the
operator channel; **create/unlock/lock are unreachable from any agent
surface** by construction (the loopback HTTP surface registers only read
projections; the WP-6 L-402 gateway registers only its own routes).

## 2. Frame envelope

```jsonc
// request (host -> sidecar)
{ "schema": "openagents.omega.sovereign-wallet.v1", "kind": "request",
  "id": "1", "generation": 1, "method": "balance", "params": { } }
// response
{ "schema": "...", "kind": "response", "id": "1", "generation": 1,
  "ok": true, "result": { ... } }
// error response
{ "schema": "...", "kind": "response", "id": "1", "generation": 1,
  "ok": false, "error": { "code": "WALLET_LOCKED", "message": "...",
  "details": "", "retryable": false, "remediation": "run unlock" } }
// event (sidecar -> host, reserved)
{ "schema": "...", "kind": "event", "id": "0", "generation": 1,
  "method": "wallet_state_changed", "params": { "walletState": "ready" } }
```

`id` is the supervisor-owned monotonically increasing request id; the sidecar
echoes it. `generation` is the supervisor's generation; a frame with a stale
generation is refused with `STALE_GENERATION` (generation fencing, effectd
pattern).

## 3. Methods

| Method | Direction | Kind | Purpose | Agent-reachable? |
|---|---|---|---|---|
| `initialize` | host→sidecar | handshake | schema/version/capabilities/generation/data_root/network/waved state | no |
| `health` | host→sidecar | read | liveness + wallet state + waved connectivity (5 s cadence) | no |
| `status` | host→sidecar | read | full read-only status projection | yes (read-only) |
| `balance` | host→sidecar | read | unified balance in sats (WalletService.Balance) | yes (read-only) |
| `create-wallet` | host→sidecar | operator | creates the Wavelength wallet; returns the show-once aezeed | **no — operator only** |
| `unlock` | host→sidecar | operator | unlocks with the vault-held password (vault is WP-4; WP-3 accepts the operator-supplied password and never persists it) | **no — operator only** |
| `lock` | host→sidecar | operator | locks the wallet surface (vault idle-lock seam, WP-4) | no |
| `make-invoice` | host→sidecar | spend-adjacent | mints a signet BOLT11 via WalletService.Recv; prefix guard | yes, but gated by mandate in WP-5 |
| `pay-invoice` | host→sidecar | spend | PrepareSend + Send; returns preimage when settled | yes, but **only after MandateStore authorization (WP-5, Rust side)** |
| `activity` | host→sidecar | read | merged activity feed (WalletService.List ACTIVITY view) | yes (read-only) |
| `identity-status` | host→sidecar | read | WP-4 stub: vault state, derived npub, recovery state (never key material) | yes (read-only projection) |
| `shutdown` | host→sidecar | control | graceful stop (waved first, then exit) | no |

## 4. Error envelope (wavecli-style, stable codes)

| Code | Meaning | retryable |
|---|---|---|
| `INVALID_ARGS` | malformed request | no |
| `WALLET_NOT_CREATED` | no wallet exists yet | no |
| `WALLET_LOCKED` | wallet surface locked | no |
| `WALLET_SYNCING` | not ready to spend | yes |
| `NOT_FOUND` | unknown id/resource | no |
| `METHOD_NOT_FOUND` | unknown method | no |
| `CONFIRMATION_REQUIRED` | fund-moving action needs explicit approval | no |
| `INSUFFICIENT_BALANCE` | balance too low | no |
| `INVOICE_EXPIRED` | invoice/swap expired | yes (re-mint) |
| `CANCELED` | interrupted while waiting on settlement | no |
| `DEADLINE_EXCEEDED` / `ABORTED` / `WAIT_TIMEOUT` | fund-moving RPC may have been accepted | **false** (wavecli rule) |
| `MAINNET_REFUSED` | mainnet config/invoice refused | no |
| `PAYMENT_HASH_MISMATCH` | preimage does not hash to payment hash (WP-6) | no |
| `CREDENTIAL_CONSUMED` | L-402 token already redeemed (WP-6) | no |
| `STALE_GENERATION` | generation mismatch | no |
| `ALREADY_RUNNING` | data-root lock held | no |
| `WAVED_BINARY_MISSING` | no pinned waved artifact configured | no |
| `WAVED_WALLET_API_UNAVAILABLE` | waved build lacks WalletService (probe failed) | no |
| `INCOMPATIBLE_VERSION` | schema/version mismatch | no |
| `INTERNAL` | anything else | yes |

gRPC status codes from the waved REST gateway map onto this table
(`INVALID_ARGUMENT`→`INVALID_ARGS`, `FAILED_PRECONDITION`→wallet-lifecycle
codes by message, `DEADLINE_EXCEEDED`→`DEADLINE_EXCEEDED`,
`UNIMPLEMENTED`→`WAVED_WALLET_API_UNAVAILABLE`, …).

## 5. Idempotency and timeouts

- **Idempotency keys**: every mutating method (`create-wallet`, `unlock`,
  `make-invoice`, `pay-invoice`) takes a client-supplied `idempotencyKey`
  (UUID). Processed keys persist in `<data_root>/run/idempotency.db`
  (`node:sqlite`); a duplicate key returns the stored result.
- **SEC-2026-047**: the `pay-invoice` result cache stores the result
  **without the preimage** (re-derivation is the activity feed); a duplicate
  key replay is preimage-free. No preimage is ever written to a store or log.
- **Timeouts**: read methods 30 s; `pay-invoice` 180 s (swap legs are
  long-lived); `health` 5 s; shutdown grace 2 s.

## 6. Loopback auth (SEC-2026-053)

- **Control plane**: no network — the stdio pipe is the boundary.
- **HTTP surface** (read projections `/v1/status`, `/v1/balance`):
  binds `127.0.0.1` IPv4 only on a dynamically allocated port reported in
  `initialize`/`status`; every request carries
  `Authorization: Bearer <OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN>` (32 random
  bytes, per launch, held only by the process pair). Comparison is
  constant-time (`timingSafeEqual` over SHA-256 digests); the token is never
  echoed; a missing/malformed token disables the surface (fail-closed, named
  state); body limit 64 KiB; request/header timeouts enforced; wrong token →
  401 before any projection logic.
- **waved's own RPC**: TLS + macaroon kept on signet; the REST client sends
  the `macaroon` header read from
  `<data_root>/wavelength/data/<network>/admin.macaroon`. `--rpc.notls` /
  `--rpc.no-macaroons` are never passed outside regtest. `--allow-mainnet` is
  never passed.

## 7. Network posture (D4, SEC-2026-050)

- `OMEGA_SOVEREIGN_WALLET_NETWORK` must be `signet` or `regtest`; `mainnet`
  or an unset value is refused at startup with `MAINNET_REFUSED`/`INVALID_ARGS`
  (an unset network never defaults to mainnet).
- waved is launched with `--network=signet` (or regtest) and the sidecar
  **asserts waved's ACTUAL runtime network** via `WalletService.Status`
  (`status.network`) at startup and on every health check; a mismatch — and
  especially `mainnet` — kills waved and refuses the sidecar. `initialize`
  reports the probed runtime network, never the env value alone.
- Invoice guard: `make-invoice` on signet must produce an `lntbs`-prefixed
  BOLT11 (testnet `lntb`, regtest `lnbcrt` accepted; mainnet `lnbc` refused on
  mint AND pay).

## 8. Data root

`<paths::data_dir()>/sovereign-wallet/` (design §1.6): `vault/` (WP-4),
`wavelength/` (waved data incl. `admin.macaroon`), `l402/` (WP-6), `run/`
(sidecar.lock, waved.pid, idempotency.db, wallet-state.json marker), `logs/`.
Owner-only ACLs on the whole root (SEC-2026-045), sidecar exclusive lock
(`ALREADY_RUNNING`), stale-waved reaping + single-waved enforcement +
Windows process-tree termination (SEC-2026-049).

## 9. Residual risks (documented)

- Plaintext loopback HTTP with a per-launch bearer token is accepted for this
  phase (SEC-2026-058): passive loopback sniffing needs administrative
  rights; active MITM needs the token. Local TLS (RV-7) is a hardening item
  before any non-loopback or mainnet surface.
- `lock` is a sidecar-enforced boundary in WP-3 (waved has no documented
  remote lock RPC); WP-4 wires the vault idle-lock here.
- waved graceful shutdown on Windows is TerminateProcess + tree kill
  (no documented graceful-stop RPC); SQLite-backed waved state is
  crash-recoverable and the `run/waved.pid` + stale reaping covers orphans.