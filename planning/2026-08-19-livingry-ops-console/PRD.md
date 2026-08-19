# PRD — Livingry Ops Console (v1)

- **Product:** Livingry Ops Console — the local operator surface for the Sovereign MCP platform on the founder's Omega fork
- **Date:** 2026-08-19
- **Owner:** Michael Ovsen (OV1 / Livingry Services)
- **Status:** DRAFT for founder review — approving this PRD authorizes implementation on the founder's fork only
- **Executor-agnostic:** written for any capable engineering agent (Sarah, or a Livingry roster session) with no session context assumed
- **Planning folder (this document + companions):** `C:\Users\ov1kn\Documents\Livingry Services\Livingry-Company-OS\planning\2026-08-19-livingry-ops-console\`

## 1. Mission

The backend for two **Sovereign MCPs** — self-custodial, L-402-gated, identity-bound paid MCP capabilities — exists and is tested on this fork, but **there is no front end**. The founder cannot load a wallet, check a balance, send a payment, set agent budgets, configure overflow (NWC export thresholds), connect ZeusLN, choose relays, view work records, or create plugins — the features cannot even be *locally tested*. This PRD defines the **Livingry Ops Console**: a local-first operator console that makes every one of those flows functional on the founder's Windows machine, without touching upstream.

**Central design decision (stated plainly):** the Console v1 is a **local web console served by a Node process** (localhost-bound), *not* a GPUI-native panel inside Omega. Rationale: (a) all Sovereign-MCP infrastructure is Node — the Console reuses it directly; (b) a GPUI dashboard is a multi-week Rust surface that blocks all testing behind it; (c) "my fork, my rules" — nothing requires upstream-plausible UI patterns yet. A GPUI-native surface is a later phase (§6), after the flows work.

## 2. Where things stand (all Verified Fact unless labeled)

**Repo:** `github.com/OV1-Kenobi/omega` (fork of OpenAgentsInc/omega). **Working branch:** `feat/source-summarization-wp6-public` @ `84de76862c` (pushed to the fork). **Worktree:** `C:\Users\ov1kn\omega-worktrees\wp6-public-l402`. The omega main checkout (`C:\Users\ov1kn\omega`) additionally carries the **Khala theme** commit `9f748cac9f` (detached HEAD, one additive file — `crates/theme/src/fallback_themes.rs`; `omega.exe` built with it; theme picking is Omega's built-in settings feature).

**Implemented and green (102/102 tests, `node --test scripts/` in the worktree):**

1. `scripts/source-summarization-mcp.mjs` — V1 local stdio MCP: URL/content → grounded summary → Q&A → signed artifacts; wired to the founder's Omega via `library_cli` (LMDB library).
2. `scripts/source-summarization-l402.mjs` — L-402 gate core: challenge/entitlement records, **HMAC-derived opaque client ids**, rate/quota/challenge bounds.
3. `scripts/source-summarization-public-http-server.mjs` — public HTTP(S) MCP server: keyless serving plane; **requires an explicit entitlement store + client-id derivation secret** (fail-closed); **sign → redeem → execute** ordering (signer outage never burns a paid entitlement).
4. `scripts/source-summarization-receipt.mjs` + `receipt-signer.mjs` — off-serving receipt signer (named pipe, DPAPI-custody pattern); content-free receipts.
5. `scripts/source-summarization-store-sqlite.mjs` — durable stores (better-sqlite3, pinned): challenge/entitlement (single-winner redemption), P12 ciphertext store, counters.
6. `scripts/source-summarization-mdk-authority.mjs` — MoneyDevKit adapter: BOLT11 invoices via `MoneyDevKitNode.invoices.create(amountSats, expirySecs)`; settlement peek (reconciliation-only); SDK behind dynamic import + secret-store contract.
7. `scripts/source-summarization-p12.mjs` — user-only encrypted history ledger (AES-256-GCM, per-user salt, AAD-bound metadata, client-side keys).
8. `scripts/source-summarization-backend-config.mjs` — backend/NWC configuration surface: typed states, masked credentials, **NWC export threshold logic (default 100,000 sats)**.

**Designed, not built:** Capability #2 — Media Transcription & Discussion MCP (`media-transcription-discussion`; WP15 design ratified: tools `transcribe_media`/`summarize_media`/`ask_media`/`export_transcript`/`extract_media_frames`/job tools; duration-band sats pricing; local transcription engine validated separately).

**Design decisions in force (recorded, binding):** per-capability durable Nostr service identities + **unique receiving wallet per MCP** (capability registry: capability_id → identity, wallet binding, tool allowlist, price schedule, receipt fields); keyless serving invariant (serving plane never holds receiving keys); operator records content-free (P10); stateless public tier with P12 ciphertext as sole persistence (P11); user-only history ledger (P12); **sats-only** (Bitcoin/Lightning only, no fiat); MDK hosted node = quick-start default backend, user-configured LN nodes = upgrade path; ZeusLN connects as wallet-side via NWC (NIP-47) QR flow; Tailscale Funnel = staging ingress plan; founder runs his own Nostr relay.

**Honest backend-gap confirmation (the founder's suspicion is correct):** the following do **not** exist anywhere yet — wallet **balance** and **pay** wiring (the MDK adapter only creates invoices/peeks settlement); an NWC **client** (only config/masking/threshold logic exists); **relay selection** persistence; a **plugin registry** or any plugin persistence; the **identity/wallet registry** (per-capability model is design-level only); any **service supervisor** (nothing starts/stops the servers); and the entire front end. The Console work packages close these gaps.

## 3. Users

v1: the founder/operator only (single local user). Multi-user, multi-tenant: out of scope.

## 4. Functional requirements — MUST (v1)

- **M1 — Console shell.** A Node console-server binds to `127.0.0.1` (localhost ONLY) with a random per-boot access token in the URL; serves the console UI (static HTML/JS, styled with the Khala token set: `#3b82f6` accent, `#05070d/#0b1220/#141f36/#182640` surfaces, `#eef3ff` text); nav sections per M2–M10. No remote binding, ever.
- **M2 — Service control.** Start/stop/status for: (a) the local stdio MCP (with a generated Omega settings-registration snippet the founder pastes once); (b) the public HTTP MCP server in **paddock mode** (in-memory store + synthetic authority — no credentials needed) and, when credentials exist, **staging mode** (SQLite stores + MDK authority). Health readout per service.
- **M3 — Capability panel.** Per-capability status cards: `source-summarization` (implemented), `media-transcription-discussion` (designed). Identity/wallet fields shown from the registry (M9), with explicit "not yet provisioned" states.
- **M4 — Wallet operations (MDK).** Account/connection status (credential *names* only, never values); node balance; create a test invoice; **send a payment manually** (pay a BOLT11 the founder pastes); settlement peek. All wallet ops fail honest (typed error, no fake data) when MDK credentials are absent. Credentials enter through a "Connect MDK account" flow that stores them via the DPAPI-custody pattern already used by the signer — never in the repo, logs, or console state.
- **M5 — ZeusLN / NWC connect + overflow settings.** Paste (or type) a `nostr+walletconnect://` URI into a protected store (masked on display, rotatable); connection test; **per-capability NWC export threshold** configuration (the "overflow settings"), default 100,000 sats, persisted, operator-gated.
- **M6 — Relay chooser.** Add/remove/enable Nostr relays (default: the founder's own relay + selected public relays), persisted in console state, with the note that relay selection currently governs NWC/nostr traffic guidance (live NWC client = decision point D2).
- **M7 — Work records.** Usage and earnings views over the durable stores: per-capability counts, sats, coarse timestamps, opaque client ids, statuses; a receipts browser. **Content-free only** — no URLs, titles, or content anywhere (P10; the stores structurally cannot produce them).
- **M8 — Agent budgets.** Local spend-ledger view (what was spent, per capability/agent-label) + guided flow for creating **budget-capped NWC connections in Zeus** (enforcement honestly lives in Zeus's budget caps — the console displays and advises, it does not pretend to enforce).
- **M9 — Capability/identity/wallet registry.** CRUD for the capability registry (capability_id → service identity label, wallet binding label, tool allowlist, price schedule stub, receipt fields), persisted in console state; feeds M3/M5/M7. This is the local implementation of the per-capability identity model (canonical Nostr npubs per capability provision at staging).
- **M10 — Plugin scaffolding.** "Create new plugin": scaffold from template (manifest, bundled-MCP registration, capability record) into a chosen folder, listed in a local plugin registry. Template generation only — no marketplace, no publishing.
- **M11 — Theme section.** Documents/links Omega's built-in theme picker (Khala is compiled into the local build); the console itself is styled with Khala tokens. No theme engine of its own.

## 5. SHOULD (v1 if cheap, else v1.1)

- P12 ledger viewer (in-browser decrypt with user-held key — pure client-side, matching the P12 module's contract).
- Staging-evidence launcher (run the existing E-series harness patterns from a button; paddock mode only).
- Funnel readiness checklist page (guidance text only — the console itself opens no public ingress).

## 6. COULD / WON'T

- **Could (later phases):** GPUI-native console panel inside Omega; full agent-budget enforcement proxy; media capability #2 console surface (once WP16 builds it); multi-profile.
- **Won't (v1):** any public/internet binding; multi-user auth; fiat anything; cloud services; upstream PRs or schema commitments; store-any-content records; modifying Omega's Rust core (the console is Node-side; the Khala theme commit is the only omega-tree change and it is already done).

## 7. Non-functional requirements

1. Windows-first (PowerShell-compatible commands); Node v20.17.0 runtime; reuse pinned `better-sqlite3` — **no new dependencies without a pinned, security-reviewed install gate** (existing policy; any new dependency = stop-and-review point).
2. Localhost-only binding + per-boot token; no exceptions.
3. Secrets: DPAPI-custody pattern; names/classes in all records and UI; never in repo, logs, or state files; rotation supported.
4. Fail-closed and fail-honest everywhere: absent credentials/config produce typed errors, never simulated data.
5. Content-free records discipline preserved (P10/P11/P12) — the console adds no content-bearing field anywhere.
6. Bitcoin-only: sats-denominated everything; no fiat display, no conversion.
7. The existing 102/102 test battery stays green after every work package; console code gets its own tests.
8. No upstream action of any kind (this is the founder's fork; still: no upstream PRs, no pushes beyond the fork, no schema commitments — upstream receipt/catalog formats remain UNVERIFIED).

## 8. Data model (console state, `console.db`, SQLite)

`settings` (key/value: port, token-ttl, thresholds defaults) · `relays` (url, enabled, label) · `capabilities` (capability_id, display name, identity label, wallet binding label, tool allowlist JSON, price schedule stub JSON, status) · `nwc_connections` (label, masked URI, capability scope, threshold sats, created/rotated) · `plugins` (name, path, manifest digest, created) · `spend_ledger_view` (read-only projection over entitlement/redemption stores — no new content-bearing data).

## 9. Acceptance criteria (each independently verifiable)

1. Console reachable only via `http://127.0.0.1:<port>/?token=<boot-token>`; remote request refused.
2. Founder can start/stop both services from the console and see live health.
3. With MDK credentials connected: balance displays; a test invoice is created; a pasted invoice is paid; without credentials: every wallet control shows a typed not-connected state.
4. A Zeus NWC URI can be entered, is masked on display, can be rotated; per-capability overflow thresholds save and persist across restart.
5. Relays can be added/removed/enabled and persist.
6. The records view shows per-capability usage/earnings from real store contents (content-free fields only) after running a paddock round trip.
7. The capability registry CRUDs both capabilities; the plugin scaffolder generates a valid template folder registered in the plugin list.
8. Full existing battery: 102/102 + new console tests green.
9. Zero secrets in the repo/logs; secret-pattern scan clean on every diff.

## 10. Open / UNVERIFIED (do not invent answers)

Upstream receipt/catalog schemas; the canonical OpenAgents capability-identity/wallet model (align to the identity proposal, live as upstream **PR #314**); MDK live platform behavior behind the founder's login; Zeus NWC in-app behavior; which web token set the live site renders (branding sourced from repo code — Khala — not the rendered site); LN Enable MCP server's current live capabilities, budget semantics, custodial posture, and API fit (see Addendum A3).

## Addendum A — Backend Fallback & Quick-Start Alternatives (founder-decided 2026-08-19)

**A1 — Sovereign fallback backend (DECIDED).** If MDK's live platform does not support the deployment pattern this program needs (per-capability wallet attribution, invoice/pay surface, the keyless seam), the fallback is **not a search for another vendor** — it is the founder's already-running self-hosted stack: **PhoenixD node + Nostrcheck relay + LNbits, on the existing Lunanode VPS**. This is the more sovereign solution and is certain to work (it is already operational). Design note [Strategic Opinion]: LNbits maps naturally onto the per-capability identity/wallet model — one LNbits wallet per capability gives native per-capability earnings separation and API-driven invoice/pay, which is precisely the registry shape (M9); PhoenixD provides the channel/liquidity layer, and the founder's own relay covers the nostr/NWC side. This fallback is the top of the already-recorded upgrade ladder (own LN node → self-hosted LNbits → hosted) — no design change is required to adopt it; it is an adapter swap at the same `issueChallenge`/`publicKeyPem` seam.

**A2 — Sequencing rationale (DECIDED).** The initial goal is to make the path easy for others following the route being scouted: minimal-infra quick-start first, functional v1, and only then the VPS infra work. The sovereign stack is the destination for the operator; the quick-start is the trailhead for everyone else. Postponing the VPS migration until the easier setup is functional is deliberate, not an oversight.

**A3 — LN Enable MCP server as a Quick-Start option (OPEN for adoption).** The founder is willing to consider the **Lightning Enable MCP server** as the L-402 gateway for the Quick Start pathway (alternative to MDK). Prior record [Verified Fact, wp8 research]: Lightning Enable is an established L402 reference implementation (challenges endpoint, `Authorization: L402 <macaroon>:<preimage>`, NWC wallet integration, budget configuration). Adoption shape: it would be a **third implementation of the existing payment-authority adapter seam** (alongside the synthetic paddock authority and the MDK adapter) — no serving-plane or gate changes. **UNVERIFIED until checked:** its current live capabilities (invoice-creation surface, budget semantics, custodial posture, current API), and whether its model fits the keyless-serving invariant. A bounded read-only research check (WP-C9 in the implementation plan; no credentials, no signup) is the prerequisite before committing.

**A4 — Effect on the risk register.** The risk "MDK live behavior UNVERIFIED" is downgraded in consequence: a validated sovereign fallback exists and is running, so platform risk to the *program* is low even if MDK proves unsuitable; the risk reduces to *quick-start convenience*, not viability.

**A5 — Backend ladder (confirmed three-tier framing).** **MDK = primary quick-start default** (already integrated, tested at paddock grade) · **LN Enable MCP = alternate quick-start under evaluation** (WP-C9) · **PhoenixD + Nostrcheck + LNbits = sovereign destination** after v1 is functional (per A2). Decision point D3 in the implementation plan governs selection.

## 11. Approval gates

Founder approves this PRD → implementation proceeds work-package by work-package on a **new branch** (`feat/ops-console`) off `feat/source-summarization-wp6-public`; each WP lands as one small commit; no merge/push without founder go; live-payment testing (real sats) only on explicit founder instruction.
