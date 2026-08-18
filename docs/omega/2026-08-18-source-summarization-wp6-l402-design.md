# Source-Summarization WP6 — Public L-402 MCP Design Note

- Date: 2026-08-18
- Author: Livingry Services (Michael Ovsen, founder; engineering team of the Livingry Company OS)
- Branch: `feat/source-summarization-wp6-public` (fork: github.com/OV1-Kenobi/omega)
- Status: IMPLEMENTED AND TESTED LOCALLY (paddock grade). Nothing in this note or the branch is deployed, exposed, or operating live. Live provider behavior (MoneyDevKit hosted node, Zeus NWC, bLIP-26 conformance) is Requires Verification until staging.
- Evidence labels: **Verified Fact** (supported by the code/tests in this branch or the referenced PR), **Requires Verification** (live/vendor state, to be confirmed at staging), **Strategic Opinion** (engineering judgment).

## 1. What this is

The source-summarization capability from PR 315 (URL/content ingestion → grounded summary → follow-up Q&A → signed artifacts) extended into a **public, pay-per-use MCP tier**: an HTTP(S) MCP endpoint behind an **L-402 payment gate**, intended to ship as the first functional L-402 MCP bundled in the first plugin listed in the OpenAgents Plugin Store. This note explains what was built, why, and how — and lists the OpenAgents-mechanics questions we need answered so we conform to the store's real model instead of inventing our own.

## 2. Why

We want to seed the marketplace with a working pay-per-use MCP: a capability an agent can pay for per-use via Lightning, get scoped access to, and receive a receipt for — established as the first workflow in the store. Design constraints from the start: the public endpoint must never hold receiving keys; operator-side records must never reveal what was summarized (content-free by construction); user history, where kept, is encrypted and user-only; everything is denominated in sats.

## 3. How — architecture (as implemented in this branch)

1. **Public HTTP(S) MCP transport adapter** (Node; `scripts/source-summarization-public-http-server.mjs`): serves the PR-315 tool contract over HTTP(S) MCP with a public tool allowlist; HTTPS-only at the edge; bounded, redacted errors; readiness surface. The local stdio path of PR 315 is untouched (V1 local surface preserved as the operator's no-cost personal path).
2. **Keyless L-402 gate** (`scripts/source-summarization-l402.mjs`): protected tool calls return HTTP 402 with an L402 challenge + Lightning invoice; the caller pays and retries with `Authorization: L402 <macaroon>:<preimage>`; verification is **stateless** — `sha256(preimage) == paymentHash` — no wallet custody, no database lookup on the serving path. The serving plane holds only the authority **public key**; a compromised serving path cannot mint challenges or substitute payment destinations (origin binding: the authority-signed envelope commits the invoice's payment hash).
3. **Payment-authority seam** (`scripts/source-summarization-mdk-authority.mjs`): a typed authority interface (`issueChallenge` / `publicKeyPem`) implemented two ways — a deterministic synthetic authority for tests, and a **MoneyDevKit adapter** that mints real BOLT11 invoices via the installed `@moneydevkit/core` SDK (`MoneyDevKitNode.invoices.create(amountSats, expirySecs)` → `{ invoice, paymentHash, scid, expiresAt }`). The real SDK is reached only through a dynamic-import factory behind a secret-store contract; the serving plane never imports it. The MDK node (self-custodial, access token + mnemonic) runs in a **sidecar plane** under its own OS identity, with credentials in the OS-protected store (DPAPI-class custody on the operator's Windows host). Payment proof arrives payer-side as the L402 preimage; node settlement events are reconciliation-only.
4. **Off-serving receipt signer** (`scripts/source-summarization-receipt-signer.mjs`): receipts are signed by a separate process reachable over an authenticated local IPC channel (named pipe), holding the signing key in the OS-protected store — never in the serving process. Receipts carry payment/entitlement facts only (amount in sats, payment-hash digest, opaque client id, service identity, validity window) — never request content. Valid-signature and tampered-receipt tests exist.
5. **One-shot entitlements + content-free records** (`scripts/source-summarization-l402.mjs`, `scripts/source-summarization-store-sqlite.mjs`): redemption is single-winner (durable via SQLite `UNIQUE(payment_hash)` inside a `BEGIN IMMEDIATE` transaction — proven across two real processes); per-client rate limits, challenge-issuance bounds, and a free-allowance quota keyed on opaque pseudonymous identifiers; operator records store counts, sats, timestamps, opaque ids, statuses only — no URLs, titles, content, raw invoices, preimages, or credentials anywhere (closed-DDL schema + throwing allowlist, tested).
6. **Durable stores** (`better-sqlite3`, `scripts/source-summarization-store-sqlite.mjs`): challenge/entitlement store and P12 ciphertext store, WAL + synchronous FULL, additive idempotent migrations, restart survival, offline-copy backup posture.
7. **P12 user-only history ledger** (`scripts/source-summarization-p12.mjs`): opt-in; ciphertext-only at rest (AEAD, per-user random salt, key derived client-side with a strong KDF for the agent-caller path); the operator stores and serves ciphertext only and holds no key material; decryption without user-held key material fails; AAD binds the operator-readable metadata.
8. **NWC export** (`scripts/source-summarization-backend-config.mjs`): operator-configurable Nostr Wallet Connect connection + export threshold (default 100,000 sats), operator-gated (never autonomous), sats-only, content-free records. Wallet-side QR connection flow (e.g., Zeus) per NIP-47.
9. **Configurable backend surface**: MDK hosted node/LSP as the launch quick-start default; user-configured Lightning nodes as the upgrade path for all users; typed validation; credential discipline (names/classes only in records; no values in repo, logs, or projections).
10. **Sats standard**: invoices, receipts, ledgers, thresholds, catalog — sats only; no fiat surface in V1.

## 4. Test and verification posture

- **97/97 tests green** across 10 suites (paddock L-402/receipt/signer/P12/backend-config/HTTP server + V1 MCP/signer + durable stores + MDK adapter), all deterministic and offline (loopback only, no live calls, no credentials).
- Negative paths tested: wrong/malformed/replayed/expired proofs fail closed with no side effects; tampered envelopes and receipts fail verification; content-bearing fields are rejected at the module boundary and impossible by schema; two-process concurrent redemption yields exactly one winner; restart preserves redeemed state; migrations are idempotent and roll back atomically.
- The serving plane's module graph is structurally asserted to contain no static import of the provider SDK and no reachable real-SDK path from tests.

## 5. Security posture (summary)

- **Keyless serving invariant**: invoices + preimage verification only; no receiving keys, signing keys, wallet state, NWC strings, node credentials, or P12 keys reachable from the serving process (structural + test evidence).
- **Origin binding**: invoice payment hash committed in the authority-signed envelope; serving path cannot substitute destinations.
- **Content-free everywhere**: closed schemas, throwing allowlists, redaction of provider error text, secret-pattern scans clean.
- **Custody**: credentials in OS-protected stores (DPAPI-class) under dedicated service identities; signer and MDK sidecar each under their own identity; named-pipe ACLs; no secrets in the repo.
- **Dependency discipline**: exactly two runtime dependencies, exact-pinned, committed lockfile (registry-only), integrity verified at the install gate, native binaries pinned/hashed.
- Live behaviors not yet verified (staging): real MDK invoice round trip and bLIP-26-shaped 402 conformance; Zeus NWC in-app behavior; Funnel/TLS round trip; real sats movement.

## 6. Status and staging plan

Implementation and local verification complete. Remaining before exposure: operator provisioning (Tailscale Funnel for public ingress with hidden IP + automatic TLS; MDK account; Windows service identities), staging evidence collection (keyless property, real L-402 round trip, single-winner under real counters, content-free audit, P12 at rest, NWC export below/above thresholds), security re-verification, and staged exposure — alpha (free beta allowance) then paid — each behind an explicit authorization. Nothing is deployed, exposed, or spent yet.

## 7. Open questions for the OpenAgents team (what we need to conform, not guess)

1. **Plugin Store entry model**: exact fields for a plugin entry (identity, theme, description, bundled MCPs, pricing)? We drafted a provisional model with the URL-summarization MCP as the first bundled capability — please correct to the canonical shape.
2. **Catalog/discovery records and receipts**: a canonical schema for capability records and payment/usage receipts we should conform to? We deliberately committed to none until confirmed.
3. **Marketplace billing conventions for agent-pays L-402**: budgets (we use NWC/NIP-47), receipt expectations, failure/refund semantics.
4. **MCP distribution in a plugin**: for a plugin bundling a remote HTTP(S) MCP, what does the store expect (stdio vs remote, endpoint registration, health/readiness)?
5. **NIP-90/DVM**: required before listing, or deferrable?
6. **PR 315 acceptance**: any architectural concerns in the keyless authority seam, the sidecar boundary, or the P12 client-side-encryption approach that would block upstream acceptance?
7. **Path to first listing**: what do you need from us (docs, demo, test agent, pricing proposal) and what does the review/approval process look like?

No commitment to any schema is made by us until we agree; we'd rather be corrected than conform to an invented model.
