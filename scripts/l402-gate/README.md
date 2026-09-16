# L-402 MCP Capability Gate (`scripts/l402-gate/`)

Reusable, capability-parameterized L-402 gate for gating ANY MCP capability
behind an LN sats payment — challenge issuance (402 + invoice), proof
redemption, receipt signing, single-winner, fail-closed, replay resistance,
no-burn-on-outage.

**Plan:** 15-plan-omega-dvm-marketplace, WP-M3.
**Reference provenance (READ-ONLY):** `C:\Users\ov1kn\omega-worktrees\wp6-public-l402`
branch `feat/source-summarization-wp6-public` @ `85408d385f` (zero modifications).
**Status:** PADDOCK-GRADE. Live payments are NOT ready (see PAID-surface record below).

---

## 1. What this is

The verified wp6 public source-summarization L-402 transport, generalized into a
component. The only new abstraction is the **executor seam**
(`{ tools, callTool(name, args) }`) replacing the 50KB V1 MCP core. The verified
policy flow is preserved:

- HTTPS-only at the public edge; `plaintextLoopbackPaddock` mode binds loopback only
- explicit entitlement store — construction fails without one (no silent default)
- server-side client-id derivation secret (raw header is never identity)
- per-client request rate limit, bounded challenge issuance, optional free-allowance quota
- allowlist rejection BEFORE the payment gate (unexposed tool names mint no challenge)
- capability-match on the proof (a token minted for another capability is not payment)
- receipt signing BEFORE redemption (signer outage → 503, proof stays replayable, no-burn)
- single-winner redemption immediately before execution (exactly one caller per proof)
- receipt attached to `structuredContent.l402_receipt`, verified against the pinned npub
- content-free operation log and challenge/entitlement store

A new capability = a new adapter object + pricing. Zero changes to the gate core.

## 2. Capability parameterization contract

```js
const gate = createCapabilityGateServer({
  capability: "source-summarization",       // wire family marker; must match the proof
  version: "0.1.0",                          // capability version string
  tools: [ { name, description, inputSchema } ],  // exposed on tools/list (filtered)
  pricing: { summarize_source: 21, ask_source: 5, export_source_analysis: 1 },  // sats per tool
  executor: { tools, async callTool(name, args) },  // the protected computation surface
  serviceNpub,                               // pinned durable service identity (required)
  receiptSignerClient,                       // authenticated named-pipe client (receipt.mjs)
  entitlementStore,                          // explicit challenge/entitlement store (required)
  clientIdDerivationSecret,                  // HMAC key for deriveOpaqueClientId (required)
  authority,                                 // payment authority (paddock: synthetic)
  plaintextLoopbackPaddock: true,            // paddock mode; TLS material in production
  clock, operationLog, receiptValiditySeconds, abuseControls, // optional tuning
});
```

## 3. File map

| File | Role |
|---|---|
| `l402-core.mjs` | Synthetic L-402 policy + authority boundary (generalized from `source-summarization-l402.mjs`) |
| `signer.mjs` | BIP-340 Schnorr + npub + DPAPI/in-memory credential store (verbatim reuse) |
| `receipt.mjs` | Receipt contract, verification, authenticated named-pipe client (renames only) |
| `receipt-signer.mjs` | Off-serving receipt/artifact signer service (renames only) |
| `gate-server.mjs` | **Generalized gate** — `createCapabilityGateServer` + executor seam |
| `capabilities/source-summarization.mjs` | **New adapter** — deterministic offline executor for the three public tools |
| `capabilities/source-summarization.test.mjs` | Adapter tests |
| `gate-server.test.mjs` | Paddock end-to-end + invariant tests (ported from the wp6 suite) |
| `l402-core.test.mjs`, `signer.test.mjs`, `receipt.test.mjs`, `receipt-signer.test.mjs` | Ported wp6 suites |
| `INTEGRATION-POINTS.md` | LNbits authority seam, VPS boundary, WP-M5 gate |
| `CALL-CONTRACT.md` | Telegram → Hermes → gated capability |

Not copied (per the design record): `source-summarization-mcp.mjs` (V1 core —
replaced by the adapter), `source-summarization-store-sqlite.mjs` (durable store
is a staging concern; paddock uses the in-memory store),
`source-summarization-p12.mjs` (separate capability surface),
`source-summarization-mdk-authority.mjs` (live authority — WP-M5 integration point).

## 4. Paddock posture

- Synthetic payment authority (in-process, deterministic, no sats, no credentials).
- Mock invoice backend: `SYNTHETIC-INVOICE-1:<hex>` in the 402 `WWW-Authenticate` header.
- In-memory entitlement store; in-memory operation log; named-pipe signer in-process.
- No live payments, no VPS, no secrets, no cloud egress. All tests run on 127.0.0.1.

## 5. PAID surface — NOT READY (recorded)

Live LN payments require, per the wp6 precedent (SEC-2026-024/033/036):

1. **Founder gate** (decision 3a, WP-M5) authorizing real micro-payments.
2. **E1 evidence items:**
   - invoice-origin integrity (no invoice substitution / payment redirection from a compromised serving path),
   - credential-store unreachability from the serving process,
   - wrong-preimage failure case on the live path,
   - post-round-trip log hygiene,
   - receipt-signing custody (off-serving, authenticated request path, no key in the serving process),
   - install-gate evidence for the LNbits/MDK client dependency.
3. LNbits/MDK authority seam implementation (see `INTEGRATION-POINTS.md`).

Known residuals (documented, match wp6): L402 proofs are one-shot bearer
credentials, not bound to requesting-client identity (SEC-2026-037 — revisit
only with an authenticated identity layer). A replayed redeemed proof mints one
discarded receipt signature before denial (SEC-2026-042 — Info, no remediation).

## 6. Verification

```powershell
# from scripts/l402-gate/
node --test
# expected: 64 tests pass, 0 fail (dependency-free; no node_modules required)
```

Reference regression: the wp6 suites re-run unchanged in the reference worktree
(see the WP-M3 gate report for results; the reference worktree is read-only).