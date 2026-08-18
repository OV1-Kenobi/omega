#!/usr/bin/env node

// Adapter tests for source-summarization-mdk-authority.mjs (plan ECP-2026-08-
// 18-OMEGA-WP6-MDK-STORE acceptance criterion 6; stop condition 4: no live
// calls, no static SDK import in the module under test). Deterministic,
// offline, fixture node only. The fixture mirrors the real
// MoneyDevKitNode.invoices.create surface (invoice, paymentHash, scid,
// expiresAt) so the adapter contract is the same one staging wires.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createMdkPaymentAuthority, createMdkNodeFromConfig, MDK_AUTHORITY_ENVELOPE_VERSION } from "./source-summarization-mdk-authority.mjs";
import { verifyChallengeToken } from "./source-summarization-l402.mjs";

// A fixture node satisfying exactly the surface this authority consumes:
// invoices.create(amountSats, expirySecs) -> { invoice, paymentHash, scid,
// expiresAt } and reconciliation events for peekSettlement.
function fixtureNode({ paymentHash = "c".repeat(64), invoice = "lnbc21n1fixture", events = [] } = {}) {
  return {
    invoices: {
      create(amountSats, expirySecs) {
        return {
          invoice,
          paymentHash,
          scid: "fixture-scid",
          expiresAt: new Date(Date.now() + (expirySecs ?? 900) * 1000),
        };
      },
    },
    receivePayments() {
      return events;
    },
  };
}

const VALID_ARGS = {
  capability: "summarize",
  version: "1.0.0",
  amountSats: 21,
  serviceIdentity: "Livingry-ops",
  clientId: "client-a",
};

test("envelope signs the node-returned payment hash and verifies with the serving-plane verifier", () => {
  const node = fixtureNode({ paymentHash: "c".repeat(64), invoice: "lnbc21n1fixture" });
  const authority = createMdkPaymentAuthority({ node });
  const result = authority.issueChallenge(VALID_ARGS);

  // Origin binding: the hash committed in the envelope is the node's hash.
  assert.equal(authority.hashOfEnvelope(result.macaroon), "c".repeat(64));
  // The invoice returned to the caller is the node's invoice (never minted
  // by the serving plane).
  assert.equal(result.invoice, "lnbc21n1fixture");
  // The exact same verifier the serving plane uses accepts the token with
  // only the authority public key.
  const verification = verifyChallengeToken(result.macaroon, authority.publicKeyPem);
  assert.equal(verification.ok, true);
  assert.equal(verification.payload.payment_hash, "c".repeat(64));
  assert.equal(verification.payload.amount_sats, 21);
  assert.equal(verification.payload.capability, "summarize");
  assert.equal(verification.payload.challenge_id, result.challenge.challenge_id);
  // The challenge record returned for the store is content-free and matches
  // the envelope.
  assert.deepEqual(result.challenge, {
    challenge_id: verification.payload.challenge_id,
    payment_hash: "c".repeat(64),
    amount_sats: 21,
    capability: "summarize",
    version: "1.0.0",
    client_id: "client-a",
    issued_at: verification.payload.issued_at,
    expires_at: verification.payload.expires_at,
    status: "issued",
    redeemed_at: null,
  });
});

test("a tampered envelope (altered amount or hash) fails verification", () => {
  const node = fixtureNode();
  const authority = createMdkPaymentAuthority({ node });
  const result = authority.issueChallenge(VALID_ARGS);
  const decoded = JSON.parse(Buffer.from(result.macaroon, "base64").toString("utf8"));
  decoded.payload.amount_sats = 9999;
  const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64");
  const verification = verifyChallengeToken(tampered, authority.publicKeyPem);
  assert.equal(verification.ok, false);
  assert.equal(verification.reason, "invalid_payment_token");
});

test("content-bearing fields entering issueChallenge are rejected", () => {
  const authority = createMdkPaymentAuthority({ node: fixtureNode() });
  assert.throws(
    () => authority.issueChallenge({ ...VALID_ARGS, url: "https://example.com" }),
    /non-allowlisted field: url/,
  );
  assert.throws(
    () => authority.issueChallenge({ ...VALID_ARGS, content: "secret content" }),
    /non-allowlisted field: content/,
  );
  assert.throws(
    () => authority.issueChallenge({ ...VALID_ARGS, payoutDestination: "lnbc1..." }),
    /non-allowlisted field: payoutDestination/,
  );
});

test("invalid arguments are rejected before any provider call", () => {
  let createCalls = 0;
  const node = {
    invoices: {
      create() {
        createCalls += 1;
        return { invoice: "x", paymentHash: "d".repeat(64), scid: "s", expiresAt: new Date() };
      },
    },
  };
  const authority = createMdkPaymentAuthority({ node });
  assert.throws(() => authority.issueChallenge({ ...VALID_ARGS, amountSats: 0 }), /positive integer/);
  assert.throws(() => authority.issueChallenge({ ...VALID_ARGS, amountSats: 1.5 }), /positive integer/);
  assert.throws(() => authority.issueChallenge({ ...VALID_ARGS, capability: "" }), /capability is required/);
  assert.throws(() => authority.issueChallenge({ ...VALID_ARGS, serviceIdentity: "" }), /serviceIdentity is required/);
  assert.equal(createCalls, 0, "provider must not be called with invalid arguments");
});

test("provider failure surfaces as a typed redacted error, never raw provider text", () => {
  const node = {
    invoices: {
      create() {
        throw new Error("super secret provider internal detail with invoice=lnbc1...");
      },
    },
  };
  const authority = createMdkPaymentAuthority({ node });
  let caught;
  try {
    authority.issueChallenge(VALID_ARGS);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught);
  assert.equal(caught.code, "mdk_invoice_creation_failed");
  assert.equal(caught.message.includes("super secret provider internal detail"), false, "provider text must be redacted");
  assert.equal(caught.message.includes("lnbc1"), false);
});

test("malformed provider response fails closed with a typed code", () => {
  const authority = createMdkPaymentAuthority({ node: fixtureNode({ paymentHash: "not-a-hash" }) });
  let caught;
  try {
    authority.issueChallenge(VALID_ARGS);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught);
  assert.equal(caught.code, "mdk_invoice_malformed");
});

test("peekSettlement observes reconciliation events without ACKing", () => {
  const settledNode = fixtureNode({ events: [{ paymentHash: "c".repeat(64) }] });
  const authority = createMdkPaymentAuthority({ node: settledNode });
  assert.deepEqual(authority.peekSettlement("c".repeat(64)), { settled: true, error: null });
  assert.deepEqual(authority.peekSettlement("e".repeat(64)), { settled: false, error: null });
  assert.deepEqual(authority.peekSettlement("garbage"), { settled: false, error: null });
});

test("the module under test has no static import of the real SDK (stop condition 4)", () => {
  const source = readFileSync(new URL("./source-summarization-mdk-authority.mjs", import.meta.url), "utf8");
  assert.equal(source.includes('from "@moneydevkit/core"'), false, "static SDK import must not exist");
  assert.equal(source.includes('import("@moneydevkit/core")'), true, "dynamic import must be the only SDK entry");
});

test("createMdkNodeFromConfig enforces the secret-store contract before any import", async () => {
  await assert.rejects(() => createMdkNodeFromConfig({ accessTokenName: "", mnemonicName: "m" }), /accessTokenName is required/);
  await assert.rejects(
    () => createMdkNodeFromConfig({ accessTokenName: "a", mnemonicName: "m" }),
    /requires a secret store/,
  );
  await assert.rejects(
    () => createMdkNodeFromConfig({ accessTokenName: "a", mnemonicName: "m", store: { getSecretValue: () => "" } }),
    /credentials are not provisioned/,
  );
});
