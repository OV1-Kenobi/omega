# Integration Points — LNbits authority seam and the VPS boundary

**Plan:** 15-plan-omega-dvm-marketplace, WP-M3.
**Status:** Documented integration point only. NOT implemented, NOT live.
Live payments arrive at **WP-M5** under the founder gate (decision 3a) with the
E1 evidence items from the wp6 precedent (SEC-2026-024/033/036).

---

## 1. The authority seam (what the gate consumes)

The gate never talks to Lightning directly. It consumes one narrow seam:

```js
authority = {
  issueChallenge({ capability, version, amountSats, serviceIdentity, clientId }),
  // -> { challenge, macaroon, invoice }
  publicKeyPem,
}
```

and verifies proofs with `verifyL402Proof({ authorization, authorityPublicKeyPem, clock })`.

In paddock, the injected authority is `createSyntheticPaymentAuthority` from
`l402-core.mjs` (in-process, deterministic, `SYNTHETIC-INVOICE-1:<hex>`).

## 2. LNbits authority implementation (WP-M5, founder gate)

The wp6 reference contains the live-authority shape this seam must implement:
`source-summarization-mdk-authority.mjs` (NOT copied into this tree — it
requires the `@moneydevkit/core` dependency and an install gate). The WP-M5
work item is:

1. Implement the same seam against the founder's LNbits instance (founder
   infra; never touched from this worktree or this plan's paddock runs).
2. Replace the synthetic authority at construction with the LNbits-backed
   authority. The gate core is unchanged — the authority is injected.
3. Provider/dependency integration rule (LRN-2026-051): verify the real API
   surface from the INSTALLED `@moneydevkit/core` at the exact pinned version;
   record verified call shapes with module line references; keep the SDK and
   any credential-reading code behind the typed seam the serving plane already
   consumes; add structural tests (no static import of the provider package in
   serving-plane modules; real-SDK factory unreachable from tests).
4. Mint challenges with REAL BOLT11 invoices; the mock `SYNTHETIC-INVOICE-1:`
   prefix disappears from the 402 `WWW-Authenticate` header.

## 3. VPS boundary (plan against, never touch)

- The public TLS edge (production `createCapabilityGateServer` with `tls`
  material) binds the VPS public interface. The L402 `Authorization` header
  never crosses a plaintext listener; paddock mode refuses non-loopback hosts.
- The off-serving receipt signer (`receipt-signer.mjs`) stays on the operator
  plane, reachable only over the authenticated local named pipe — never exposed
  on the VPS public interface.
- The serving process never loads a signing key. Receipt/artifact signatures
  come from the off-serving signer; verification is pure public-key math
  against the pinned service npub.
- The founder's VPS is NOT part of this plan's execution surface. WP-M3 is
  paddock-grade; WP-M5 (under founder decision 4a) is the first VPS-touching
  work item and requires the founder gate + deployment authorization.

## 4. Live-at-WP-M5 checklist (recorded, not executed)

- [ ] Founder gate: decision 3a (real micro-payments at demo) — AUTHORIZATION REQUIRED.
- [ ] E1 evidence items per SEC-2026-024/033/036 (invoice-origin integrity,
      credential-store unreachability, wrong-preimage case, log hygiene,
      receipt-signing custody, install-gate evidence for the LNbits/MDK client dependency).
- [ ] LNbits/MDK authority implementing the seam above; verified call shapes recorded.
- [ ] Durable entitlement store (SQLite store is a staging concern; the paddock
      uses the in-memory store).
- [ ] VPS boundary decision (4a) and deployment authorization for any VPS touch.
- [ ] Receipt-signing custody hardening on the production channel (OS-level
      peer-identity verification of the named-pipe client is NOT available in
      the Node standard library — flagged in `receipt-signer.mjs` as a
      Security/DevOps verification item before any exposure).