# Implementation Plan — Livingry Ops Console

- **Date:** 2026-08-19
- **Owner:** Michael Ovsen (founder); executor: any capable engineering agent (Sarah or a Livingry roster session)
- **Companion PRD (requirements authority):** `C:\Users\ov1kn\Documents\Livingry Services\Livingry-Company-OS\planning\2026-08-19-livingry-ops-console\PRD.md` (incl. Addendum A — backend ladder, founder-decided)
- **Status:** READY FOR EXECUTION on the founder's fork (new branch `feat/ops-console` off `feat/source-summarization-wp6-public`)

## 1. Read-first list (for the executing agent, in order)

1. The PRD (same folder — including Addendum A: backend fallback ladder, D3).
2. `C:\Users\ov1kn\omega-worktrees\wp6-public-l402\docs\omega\2026-08-18-source-summarization-wp6-l402-design.md` (architecture + invariants).
3. `C:\Users\ov1kn\omega-worktrees\wp6-public-l402\docs\omega\2026-08-15-artifact-provenance-and-identity-boundaries.md` (identity model).
4. The eight modules in `C:\Users\ov1kn\omega-worktrees\wp6-public-l402\scripts\` (read each before wiring anything against it).
5. `C:\Users\ov1kn\Documents\Livingry Services\Livingry-Company-OS\AGENTS.md` (operating standards — claim labels, secrets discipline, Windows rules). If executing outside the Livingry OS, the binding subset is: label claims (Verified Fact / Requires Verification / Strategic Opinion / UNVERIFIED); never log/store secret values or request content; fail honest over simulated data; Windows/PowerShell commands.

## 2. Ground rules (binding on the executor)

- New branch `feat/ops-console` off `feat/source-summarization-wp6-public`; **one concern per work package, one commit per WP**; verify state before/after every git/file operation; rollback = `git revert <sha>`.
- Windows/PowerShell commands only; Node stdlib + the two already-pinned dependencies (`better-sqlite3`, `@moneydevkit/core`) — **any third new dependency is a STOP-and-review point** (install-gate policy: pinned version + integrity + lifecycle-script enumeration before install).
- Never: modify Omega's Rust tree (the Khala theme commit `9f748cac9f` is separate and done), weaken the 102/102 battery, bind anything non-localhost, log/store secret values or request content, push beyond the fork, or open upstream PRs.
- Claim discipline as in §1.5; fail-honest over simulated data; one uncertainty stays one note, not an invented decision.
- If a work package exceeds one concern or one verification loop, decompose it before starting (no giant batches; stop-and-rescope on stall — after two failed attempts on the same item, branch: smaller scope, different approach, or escalate to the founder).

## 3. Work packages (each: goal, files, verification)

**WP-C0 — Console skeleton (branch + server + shell).** New `scripts/console/` (server.mjs + static/). Localhost-only HTTP server, per-boot token, static shell with Khala-styled nav (`#3b82f6` accent, `#05070d/#0b1220/#141f36/#182640` surfaces, `#eef3ff` text). *Verify:* server test (remote refused, token required); battery green. *Commit 1.*

**WP-C1 — Service control.** Start/stop/status for local stdio MCP + public server (paddock mode: explicit in-memory store + synthetic authority + fixed derivation secret; staging mode: SQLite stores + MDK authority when credentials exist). Omega settings-snippet generator. *Verify:* lifecycle tests (spawn/health/stop); battery green. *Commit 2.*

**WP-C2 — Console state + relays.** `console.db` (better-sqlite3, additive migrations); settings + relay CRUD + persistence. *Verify:* restart-survival test; battery green. *Commit 3.*

**WP-C3 — Wallet operations (MDK wiring — closes the biggest backend gap).** Wire balance (`getBalance`), create-invoice, **pay** (paste BOLT11 → `MoneyDevKitNode.pay`), settlement peek through the existing MDK adapter + a console-side DPAPI secret store (credential *names* only in state; values via the signer-custody pattern). "Connect MDK account" flow. *Verify:* unit tests with fixture node (no live calls); manual matrix with real credentials = founder-gated live step. *Commit 4.*

**WP-C4 — NWC/Zeus + overflow settings.** NWC URI entry → protected store (masked, rotatable); per-capability export-threshold CRUD persisted; URI format validation. **Decision point D2:** live NWC client (minimal NIP-47) — recommended v1 = validation + storage + thresholds only, live client deferred (new dependency surface; needs its own install-gate review). *Verify:* threshold persistence + masking tests. *Commit 5.*

**WP-C5 — Work records + receipts browser.** Read-only views over the SQLite stores; per-capability earnings; receipts list. Content-free fields only. *Verify:* view tests against seeded stores; battery green. *Commit 6.*

**WP-C6 — Agent budgets view.** Spend-ledger projection + Zeus budget-cap guidance flow (honest note: enforcement lives in Zeus). *Verify:* projection test. *Commit 7.*

**WP-C7 — Capability registry + plugin scaffolder.** Registry CRUD (identity/wallet labels, tool allowlist, price stub); plugin template generator + local plugin list. *Verify:* scaffold generates valid manifest; registry persistence test. *Commit 8.*

**WP-C8 — Polish + theme section + docs.** Console UI to final Khala tokens; theme section (pointer to Omega's built-in picker); README for the console (how to launch, the founder's 2-minute tour). *Verify:* manual smoke per PRD §9. *Commit 9.*

**WP-C9 — LN Enable capability check (Addendum A3; read-only research, no credentials, no signup).** Bounded research on the Lightning Enable MCP server's current live state: invoice-creation surface, budget semantics, custodial posture, current API, fit with the keyless-serving invariant. Output: a findings note (labeled, UNVERIFIED where unconfirmed) feeding decision D3. Runs in parallel from the start; never blocks C0–C8. *No commit required (research artifact); one note file.*

## 4. Sequencing

C0 → C1 → C2 → (C3 ∥ C5) → C4 → C6 → C7 → C8. **WP-C9 runs read-only in parallel from the start.** C3's live-credential testing and any real-sats payment test are founder-gated moments, not blocking the chain.

## 5. Verification strategy

Per-WP unit tests + the full battery after every WP (must stay 102/102 + new); console smoke script (boot token → nav renders → services controllable); final manual acceptance matrix per PRD §9 executed by the founder.

## 6. Risks & honest limits

- MDK live behavior UNVERIFIED — **downgraded in consequence (Addendum A4):** the sovereign fallback (PhoenixD + Nostrcheck + LNbits on the founder's Lunanode VPS) is already running and certain to work, so platform risk to the program is low; MDK risk is quick-start convenience only.
- Zeus NWC behavior UNVERIFIED (D2 defers the live client to its own reviewed WP).
- DPAPI-under-console custody is a new pattern (follow the signer precedent; Security review before staging).
- Scope creep into GPUI is explicitly forbidden in v1.
- The 42 pre-existing `omega_deltas` test failures are a separate baseline — untouched, not caused by, and not fixed by this work.
- If MDK proves unsuitable: adapter swap at the `issueChallenge`/`publicKeyPem` seam to the LNbits/PhoenixD stack (A1) — no console redesign needed; LNbits gives one wallet per capability natively.

## 7. Definition of done

The founder, from the console alone, on his machine, can: control both MCP services, connect MDK, see balance, send a payment, connect Zeus via NWC, set overflow thresholds per capability, choose relays, view per-capability work records and receipts, inspect the capability registry, and scaffold a new plugin — with zero content-bearing records and zero secrets on disk in the clear.

## 8. Addendum A — Backend ladder & decision point D3 (founder-decided 2026-08-19)

Confirmed three-tier framing (founder, 2026-08-19):

1. **MDK = primary quick-start default** — already integrated and green at paddock grade (WP-C3 wires the live surface).
2. **LN Enable MCP = alternate quick-start, OPEN** — WP-C9's read-only research is the prerequisite; adoption would be a third implementation of the payment-authority adapter seam (no serving-plane changes).
3. **PhoenixD + Nostrcheck relay + LNbits (existing Lunanode VPS) = sovereign destination** — deliberate sequencing: quick-start functional first (making the scouted path easy for others), VPS migration after v1 (A2). The founder is certain this stack can be made to work; it is already operational.

**Decision point D3 (quick-start gateway selection):** MDK (default) vs LN Enable MCP (pending WP-C9) vs LNbits-first (sovereign-early). Recommendation [Strategic Opinion]: keep MDK default; run WP-C9 in parallel; decide D3 when WP-C9's findings land or when MDK live testing (founder-gated) reveals friction. The sovereign migration is a post-v1 milestone either way.

**Rollback discipline throughout:** one commit per WP; `git revert <sha>` per WP; the branch never merges to any shared branch without founder go.
