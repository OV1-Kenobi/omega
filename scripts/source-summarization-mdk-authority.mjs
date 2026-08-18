#!/usr/bin/env node

// MDK payment authority adapter for the WP6 public tier (plan ECP-2026-08-18-
// OMEGA-WP6-MDK-STORE section 6.1/6.4 Layer 3). Implements the SAME authority
// seam as the synthetic paddock authority in source-summarization-l402.mjs
// (issueChallenge + publicKeyPem) so the serving plane changes zero lines:
// the composition layer injects this authority at staging and the paddock
// authority in tests.
//
// ARCHITECTURE (keyless serving invariant, SEC-2026-033 origin binding):
//   - The MoneyDevKitNode (self-custodial, MNEMONIC + ACCESS_TOKEN under the
//     sidecar's DPAPI scope per SEC-2026-038) lives in the SIDECAR plane,
//     never in the serving process. The serving plane receives only
//     publicKeyPem (verification).
//   - issueChallenge mints a BOLT11 invoice via node.invoices.create(amountSats)
//     and binds the node-returned payment_hash into the authority-signed
//     envelope: a compromised serving path cannot substitute a payment
//     destination or alter the committed hash without breaking verification.
//   - The invoice string crosses to the caller in the 402 and is NEVER stored
//     operator-side (P10 strict-ledger discipline).
//   - Preimage custody stays payer-side. The node's settlement events are
//     reconciliation-only (plan rule b); peekSettlement() observes without
//     ACKing; payment verification never depends on it.
//
// SDK IMPORT GATE (plan 6.4 stop condition 4): this module has NO static
// import of @moneydevkit/core. The node instance is injected; the real SDK is
// constructed only by createMdkNodeFromConfig() via dynamic import, which
// staging wiring calls and tests never reach (structural test asserts the
// absence of a static SDK import).
//
// Error discipline (plan rule c): every provider failure surfaces as a typed
// code with provider error text redacted before any log or response.
//
// Capability manifest (agent-and-skill-security-policy section 2; plan 6.2.4):
//   - Files/dirs: none (node instance injected by the sidecar wiring).
//   - Network: the MDK control plane / WS channel of @moneydevkit/lightning-js
//     runtime belongs to the SIDECAR process only (SDK runtime); this module
//     itself opens no socket.
//   - Accounts/credentials: none held here. ACCESS_TOKEN/MNEMONIC live in the
//     sidecar's DPAPI scope; only their NAMES pass through configuration.
//   - Persistence/looping: none.
//   - Boundaries: sidecar (node) <-> authority (this module) <-> serving plane
//     (public key only).
//   - Failure: typed fail-closed codes; sidecar unavailable -> no challenge
//     issuance -> no paid calls (health surfaces readiness).
//   - Pinning: @moneydevkit/core exact-pinned in scripts\package.json with the
//     committed lockfile; re-review triggers per the install gate.
//   - Owner: founder/operator.

import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as edSign,
} from "node:crypto";

// The same canonicalization + signing contract as the paddock authority, so
// tokens verify with the identical verifyChallengeToken() logic already used
// by the serving plane (it needs only the authority public key).
function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number in canonical data");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
  if (isObject(value)) {
    const entries = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new Error("unsupported value in canonical data");
}

function sha256Hex(value) {
  return createHash("sha256").update(typeof value === "string" ? Buffer.from(value) : value).digest("hex");
}

// Allowlisted args for issueChallenge: a content-bearing field (url, title,
// content, excerpt, payout string, ...) must be REJECTED, never silently
// carried toward the provider (plan 6.2.5(e) content-free sidecar API).
const ISSUE_CHALLENGE_ARG_FIELDS = ["capability", "version", "amountSats", "serviceIdentity", "clientId"];
const ISSUE_CHALLENGE_REQUIRED = ["capability", "version", "amountSats", "serviceIdentity"];

export const MDK_AUTHORITY_ENVELOPE_VERSION = "l402-mdk-v1";

// A redaction marker for provider error text: the message may carry provider
// internals; only the typed code and a safe description cross the boundary.
function providerError(code, safeDescription) {
  const error = new Error(`${code}: ${safeDescription}`);
  error.code = code;
  error.provider = true;
  return error;
}

// ---------------------------------------------------------------------------
// Authority factory (injected node; fixtures in tests, MoneyDevKitNode in the
// sidecar wiring)
// ---------------------------------------------------------------------------

export function createMdkPaymentAuthority({
  node,
  ed25519KeyPair,
  clock = () => new Date(),
  validitySeconds = 15 * 60,
  idFactory = () => randomUUID(),
} = {}) {
  if (!isObject(node) || typeof node.invoices?.create !== "function") {
    throw new Error("createMdkPaymentAuthority requires a node with invoices.create()");
  }
  const keyPair = ed25519KeyPair ?? generateKeyPairSync("ed25519");

  function authoritySign(payload) {
    return edSign(null, Buffer.from(canonicalize(payload)), keyPair.privateKey);
  }

  function issueChallenge(options) {
    // Validate the CALLER's options object keys - a content-bearing field must
    // be rejected, never silently dropped by destructuring.
    if (!isObject(options)) throw new Error("issueChallenge requires an options object");
    for (const key of Object.keys(options)) {
      if (!ISSUE_CHALLENGE_ARG_FIELDS.includes(key)) {
        throw new Error(`issueChallenge received a non-allowlisted field: ${key}`);
      }
    }
    const { capability, version, amountSats, serviceIdentity, clientId = null } = options;
    for (const field of ISSUE_CHALLENGE_REQUIRED) {
      const value = { capability, version, amountSats, serviceIdentity }[field];
      if (typeof value !== "string" || value.trim() === "") {
        if (field === "amountSats") break; // amountSats is numeric; validated below
        throw new Error(`${field} is required`);
      }
    }
    if (typeof capability !== "string" || capability.trim() === "") throw new Error("capability is required");
    if (typeof version !== "string" || version.trim() === "") throw new Error("version is required");
    if (!Number.isInteger(amountSats) || amountSats <= 0) throw new Error("amountSats must be a positive integer");
    if (typeof serviceIdentity !== "string" || serviceIdentity.trim() === "") throw new Error("serviceIdentity is required");

    const issuedAt = new Date(clock().getTime());
    const expiresAt = new Date(issuedAt.getTime() + validitySeconds * 1000);
    const challengeId = idFactory();

    let mdkInvoice;
    try {
      // sats in, bolt11 + payment hash out (MoneyDevKitNode.invoices.create).
      mdkInvoice = node.invoices.create(amountSats, validitySeconds);
    } catch (error) {
      throw providerError("mdk_invoice_creation_failed", "the payment provider could not mint an invoice");
    }
    if (!isObject(mdkInvoice) || typeof mdkInvoice.invoice !== "string" || !/^[0-9a-f]{64}$/.test(mdkInvoice.paymentHash ?? "")) {
      throw providerError("mdk_invoice_malformed", "the payment provider returned a malformed invoice");
    }

    const payload = {
      challenge_id: challengeId,
      capability,
      version,
      amount_sats: amountSats,
      payment_hash: mdkInvoice.paymentHash,
      service_identity: serviceIdentity,
      client_id: clientId,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
    };
    const signature = authoritySign(payload);
    const token = Buffer.from(
      JSON.stringify({
        l402_synthetic: "1", // same signed-envelope family the serving-plane verifier accepts
        l402_mdk: MDK_AUTHORITY_ENVELOPE_VERSION,
        payload,
        signature: signature.toString("base64"),
      }),
    ).toString("base64");

    return {
      challenge: {
        challenge_id: challengeId,
        payment_hash: mdkInvoice.paymentHash,
        amount_sats: amountSats,
        capability,
        version,
        client_id: clientId,
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        status: "issued",
        redeemed_at: null,
      },
      macaroon: token,
      invoice: mdkInvoice.invoice,
    };
  }

  // Reconciliation-only observation (plan rule b). Never ACKs; returns whether
  // the node has seen a received-payment event for this hash. Payment
  // verification never depends on this - the L402 preimage check does.
  function peekSettlement(paymentHash) {
    if (typeof paymentHash !== "string" || !/^[0-9a-f]{64}$/.test(paymentHash)) {
      return { settled: false, error: null };
    }
    try {
      if (typeof node.receivePayments !== "function") return { settled: false, error: null };
      const events = node.receivePayments() ?? [];
      const settled = Array.isArray(events) && events.some((event) => event && event.paymentHash === paymentHash);
      return { settled, error: null };
    } catch {
      return { settled: false, error: "settlement_observation_failed" };
    }
  }

  return {
    issueChallenge,
    peekSettlement,
    publicKeyPem: keyPair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    // Helper used by tests to prove the origin binding: the hash committed in
    // the envelope equals the node-returned hash (E2 payer-side check analog).
    hashOfEnvelope(macaroon) {
      const decoded = JSON.parse(Buffer.from(macaroon, "base64").toString("utf8"));
      return decoded.payload?.payment_hash ?? null;
    },
  };
}

// ---------------------------------------------------------------------------
// Staging wiring only: constructs the real MoneyDevKitNode from configuration
// NAMES (values are injected by the operator surface at runtime, never stored
// in this module, never in tests). Dynamic import keeps the real SDK out of
// the test graph (structural test asserts no static import).
// ---------------------------------------------------------------------------

export async function createMdkNodeFromConfig({ accessTokenName, mnemonicName, nodeOptions = {}, store = null }) {
  if (typeof accessTokenName !== "string" || accessTokenName === "") throw new Error("accessTokenName is required");
  if (typeof mnemonicName !== "string" || mnemonicName === "") throw new Error("mnemonicName is required");
  if (store === null || typeof store.getSecretValue !== "function") {
    throw new Error("createMdkNodeFromConfig requires a secret store (DPAPI scope of the sidecar identity)");
  }
  const accessToken = store.getSecretValue(accessTokenName);
  const mnemonic = store.getSecretValue(mnemonicName);
  if (typeof accessToken !== "string" || accessToken === "" || typeof mnemonic !== "string" || mnemonic === "") {
    throw new Error("sidecar credentials are not provisioned");
  }
  const core = await import("@moneydevkit/core");
  const { MoneyDevKitNode } = core;
  if (typeof MoneyDevKitNode !== "function") throw new Error("@moneydevkit/core did not export MoneyDevKitNode");
  return new MoneyDevKitNode({ accessToken, mnemonic, nodeOptions });
}

// sha256Hex re-exported for fixture parity with the paddock authority's tests.
export { sha256Hex };
