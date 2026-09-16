# Call Contract — Telegram → Hermes → gated capability

**Plan:** 15-plan-omega-dvm-marketplace, WP-M3.
**Status:** Documented call contract. The gate is callable NOW in paddock; the
Hermes harness wiring and live payment are WP-M5 / Hermes Phase 2 items under
their respective founder gates.

---

## 1. The call chain

```
Founder (Telegram)
   └─> Hermes Chief of Staff (Company OS harness; Telegram input, WS5)
         └─> gated capability via the L-402 gate (this component)
               ├─ 402 + LN invoice  (challenge)
               ├─ founder pays      (live: LN wallet; paddock: mock settle)
               ├─ redeem proof
               └─ capability executes → signed artifact + signed receipt
```

Hermes decides a gated capability (e.g., source-summarization) is needed for a
founder request, calls the gate over MCP, holds the L402 proof after payment,
and returns the signed artifact + receipt to the Telegram conversation.

## 2. Wire contract at the gate (the part this component owns)

Base: `POST <mcpPath>` (default `/mcp`) with a single JSON-RPC 2.0 object.
Batches are rejected (`-32600`). Transport: HTTPS at the public edge;
`plaintextLoopbackPaddock` loopback-only in tests.

1. **tools/call** without `Authorization`
   → `402` + `WWW-Authenticate: L402 macaroon="...", invoice="SYNTHETIC-INVOICE-1:<hex>"`
   (paddock) / `invoice="<BOLT11>"` (live at WP-M5). Error body is bounded and
   content-free.
2. **Pay**: paddock — the synthetic authority settles the challenge id and the
   caller learns the preimage. Live — the founder pays the LN invoice and the
   payer learns the preimage from the Lightning network (never from the operator).
3. **tools/call** with `Authorization: L402 <macaroon>:<preimage>`
   → single-winner redemption, capability executes, response `200` with the
   tool result and `structuredContent.l402_receipt` (content-free, signed by
   the off-serving signer, verifiable against the pinned service npub).

Failure mapping (all bounded, content-free): malformed auth `400 -32002`;
invalid/foreign token `400 -32003`; expired/wrong-preimage/no-auth → fresh
`402` (no second grant on replay); signer outage `503 -32007` (proof stays
replayable — no-burn); rate/challenge/quota bounds `429 -32009/-32011/-32010`.

## 3. Hermes-side responsibilities (documented; wiring is a later item)

- Hold the L402 proof **per user session** — the proof is a one-shot bearer
  credential (SEC-2026-037): after redemption it cannot be reused, so Hermes
  re-challenges on the next gated call.
- Never log or render the macaroon, preimage, or invoice.
- Surface the payment step to the founder in the Telegram thread (invoice
  string / payment link), then retry the call with the proof.
- Treat the signed receipt as the delivered-payment record; verify its
  signature against the service npub before trusting the artifact.

## 4. Paddock demo path (how to exercise it today)

The paddock e2e in `gate-server.test.mjs` is the reference implementation of
the caller side: `payFor()` requests the challenge, settles with the synthetic
authority (`SYNTHETIC-INVOICE-1`), and retries with the L402 header. A Hermes
harness integration at WP-M5 reuses this exact flow with the LNbits-backed
authority (see `INTEGRATION-POINTS.md`).

## 5. Gating notes for future capabilities

A new gated capability (video-transcription, video-production) needs: a tool
contract + pricing + an executor adapter implementing
`{ tools, callTool(name, args) }`. The gate, receipt, signer, and policy flow
are unchanged. Video-transcription was deferred from this WP because its
worker can trigger a model download (cloud egress) and is non-deterministic;
it becomes a first-class adapter at WP-M5 once the founder authorizes live runs
and the model is confirmed cached (design record section 5).

## 6. Out of scope here

- Live Telegram message handling (Hermes WS5, live in Phase 2).
- Live payments / LN wallet flow (WP-M5 founder gate, decision 3a).
- VPS-hosted public TLS edge (WP-M5 founder gate, decision 4a).