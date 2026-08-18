# Source-Summarization WP6 — Public L-402 MCP Design Note

- Date: 2026-08-18
- Author: Livingry Services / Ov1 (Livingry engineering team)
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
5. **One-shot entitlements + content-free records** (`scripts/source-summarization-l402.mjs`, `scripts/source-summarization-store-sqlite.mjs`): redemption is single-winner — in-memory synchronous check-and-set on the Node event loop for the paddock/serving plane (process-lifetime), and durable cross-process single-winner on the staging-durable plane via the injected SQLite store (`UNIQUE(payment_hash)` inside a `BEGIN IMMEDIATE` transaction — proven across two real processes). The server never silently defaults a store: the entitlement store is an explicit construction choice (in-memory for the paddock/tests; SQLite injected by the staging harness). Per-client rate limits, challenge-issuance bounds, and a free-allowance quota keyed on opaque pseudonymous identifiers; operator records store counts, sats, timestamps, opaque ids, statuses only — no URLs, titles, content, raw invoices, preimages, or credentials anywhere (closed-DDL schema + throwing allowlist, tested).
6. **Storage planes — which holds what** (`better-sqlite3`, `scripts/source-summarization-store-sqlite.mjs`): two explicit planes, never a silent in-memory default. The paddock/serving plane holds in-memory process-lifetime state: the challenge/entitlement store is injected explicitly (in-memory in the paddock/tests; operation log always in-memory), and the P12 ciphertext store is in-memory by its own module manifest ("a deployment store is a separate, later component"). The staging-durable plane is the injected SQLite store — challenge/entitlement store with WAL + synchronous FULL, additive idempotent migrations, restart survival, offline-copy backup posture; it is composed in by the tests/staging harness, never defaulted by the server, and its durable properties are staging evidence, not paddock behavior.
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

## 7. Second capability — media transcription & discussion MCP (video/audio review)

The source-summarization product is a **two-capability bundle**, both behind the same L-402 gate family on the public tier:

1. **Source summarization** (this branch, PR 315 lineage) — text/URL/content ingestion, grounded summary, follow-up Q&A, signed artifacts. Capability #1 (`capability_id: "source-summarization"`).
2. **Media transcription & discussion** (designed; groundwork validated) — uploads, authorized YouTube URLs, and direct media URLs become a timestamped transcript, faithful summary, grounded discussion, exports, and optional still frames, via a fully local engine (faster-whisper; no cloud transcription). Capability #2 (`capability_id: "media-transcription-discussion"`, server id `media-summarization`; tools `transcribe_media`/`summarize_media`/`ask_media`/`export_transcript`/`extract_media_frames`/job tools; duration-band sats pricing). Sequencing set by the operator: local first at no cost in Omega, then L-402-gated on the public tier after its own staging evidence — same rails, no new payment system.

Design notes for the second capability:
- **Local-first sequencing:** delivered to the operator's Omega agent at no cost first (founder-uses-at-no-cost principle); the public L-402 surface activates only after its own staging evidence.
- **Public-tier content contract:** caller-provided transcript/text for the public surface where transcription is not server-side; media acquisition egress is allowlist-bounded (YouTube + direct media URLs, SSRF controls, no DRM/cookie/PO-token bypass — honest `host_blocked` errors). [Requires Verification: exact public tool contract fixed at implementation.]
- **Same rails:** keyless L-402 gate family, one-shot entitlements (job-bound for media), content-free records (P10-media record set), receipts, P12, NWC, sats — no new payment architecture.
- **Plugin framing:** the plugin bundles both MCP capabilities under one entry (FP-2 amendment).

## 7a. Identity model — per-capability service identities with unique receiving wallets

**[Verified Fact — this fork's proposal]** The operator's identity proposal `docs/omega/2026-08-15-artifact-provenance-and-identity-boundaries.md` (branch `docs/identity-artifacts-services-proposal`) establishes the artifact-vs-actor boundary: artifacts (skills, plugin packages, local MCP instances) are identified by content digest + publisher signature and hold **no** durable key; actors that operate services, collect L-402, accrue reputation, or receive payment **do** hold durable Nostr identities (rules 6–9; the table's "Remote, paid MCP service → Service-operator pubkey → Yes when public and durable").

**Adopted model (consistent with that proposal):**
- **Each capability is its own remote paid MCP service actor** — `source-summarization` and `media-transcription-discussion` each get their **own durable service identity (npub)** and their **own unique receiving wallet binding**. Earnings, usage, and performance reputation are tracked **per capability** (per-capability sats-earned ledger views; per-capability NWC export configuration; per-capability receipts and discovery-catalog records). Payment challenges and receipts bind to the per-capability service identity (proposal rule 9).
- **The plugin package itself stays artifact-identified** (digest + version + signed manifest) — no plugin key. Reputation never transfers to arbitrary forks or redeployments (rule 8).
- **One capability registry** (`capability_id` → `{ service identity (npub), receiving wallet binding, server_id, tool allowlist, price schedule, receipt fields }`) is the single source of truth; both capabilities register there; the shared keyless L-402 gate, content-free records, P12, and sats rails are never duplicated.
- **Wallet custody:** each capability's receiving wallet is provisioned on the operator's backend (MDK path; per-wallet attribution Requires Verification against the live platform — a question for the OpenAgents team), keys never on the serving path; NWC export operator-configurable per capability.
- **Issue 312 alignment:** the operator's proposal was never submitted upstream (PR gap 311→313); it is being submitted as PR 312 and the OpenAgents team's confirmation of the capability-identity/wallet model is requested in section 8 (Q5). [Requires Verification: OpenAgents' canonical identity/wallet model for per-capability services.]

Status: **design-level decision recorded 2026-08-18 — not yet implemented in this branch.** The capability registry and per-capability identity/wallet wiring land with the WP16/implementation work, pending the OpenAgents team's confirmation of the model.

## 8. Open questions for the OpenAgents team (what we need to conform, not guess)

1. **Plugin Store entry model**: exact fields for a plugin entry (identity, theme, description, bundled MCPs, pricing)? We drafted a provisional model with the URL-summarization MCP as the first bundled capability and media review as the second — please correct to the canonical shape.
2. **Capability identity & wallet model (ties to PR 312)**: does the store expect each remote paid MCP capability to carry its **own durable Nostr service identity and receiving wallet** (per-capability earnings, usage, and reputation tracking), or a single operator identity with capability-scoped records? We submitted our proposal (`docs/omega/2026-08-15-artifact-provenance-and-identity-boundaries.md`, PR 312) — please confirm alignment with OpenAgents' model, and whether per-capability wallet attribution is expected or supported.
3. **Catalog/discovery records and receipts**: a canonical schema for capability records and payment/usage receipts we should conform to? We deliberately committed to none until confirmed.
4. **Marketplace billing conventions for agent-pays L-402**: budgets (we use NWC/NIP-47), receipt expectations, failure/refund semantics.
5. **MCP distribution in a plugin**: for a plugin bundling remote HTTP(S) MCPs, what does the store expect (stdio vs remote, endpoint registration, health/readiness)?
6. **NIP-90/DVM**: required before listing, or deferrable?
7. **User dashboard — branding/theme/layout**: what branding assets, theme, and layout should a merchant/user dashboard (earnings, usage, receipts, capabilities, wallet/export config) use for first drafts on a Windows machine — is there a canonical brand kit, design-system reference, or Figma?
8. **Database/storage conventions**: what does the store use for catalog/discovery records, receipts, and usage — canonical schemas we must conform to, and who owns/stores them (merchant vs store)?
9. **PR 315 acceptance**: any architectural concerns in the keyless authority seam, the sidecar boundary, or the P12 client-side-encryption approach that would block upstream acceptance?
10. **Path to first listing**: what do you need from us (docs, demo, test agent, pricing proposal) and what does the review/approval process look like?

No commitment to any schema is made by us until we agree; we'd rather be corrected than conform to an invented model.
