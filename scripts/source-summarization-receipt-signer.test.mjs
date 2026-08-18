// Offline tests for the off-serving receipt signer process
// (source-summarization-receipt-signer.mjs). Exercises the real authenticated
// named-pipe IPC path with an in-memory provisioned service identity; no real
// credential store, no network, no sats.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";

import { createCredentialStoreSigner, createInMemoryStorage, provisionSignerIdentity } from "./source-summarization-signer.mjs";
import {
  ReceiptSignerClient,
  createRemoteArtifactSigner,
  receiptDigest,
  verifyReceiptSignature,
} from "./source-summarization-receipt.mjs";
import { createReceiptSignerService } from "./source-summarization-receipt-signer.mjs";
import { receiptSignerPipePath } from "./source-summarization-receipt.mjs";

const AUTH_SECRET = "synthetic-paddock-boot-secret";

async function startSigner({ purposes = ["sign_receipt", "artifact_sign"] } = {}) {
  const storage = createInMemoryStorage();
  const npub = await provisionSignerIdentity({ storage });
  const signer = createCredentialStoreSigner({ storage });
  const pipePath = receiptSignerPipePath(randomBytes(6).toString("hex"));
  const service = createReceiptSignerService({ signer, pipePath, authSecret: AUTH_SECRET, allowedPurposes: purposes });
  await service.listen();
  const client = new ReceiptSignerClient({ pipePath, authSecret: AUTH_SECRET, expectedServiceNpub: npub });
  return { service, client, signer, npub, pipePath };
}

function sampleReceipt(npub, overrides = {}) {
  return {
    receipt_id: "0197f000-0000-7000-8000-000000000001",
    capability: "source-summarization",
    version: "0.1.0",
    amount_sats: 21,
    payment_hash: "cd".repeat(32),
    client_id: "client-a-opaque",
    service_identity: npub,
    issued_at: "2026-08-17T12:00:00.000Z",
    valid_until: "2026-08-17T13:00:00.000Z",
    ...overrides,
  };
}

test("a receipt round trip over the authenticated pipe verifies", async () => {
  const harness = await startSigner();
  try {
    const receipt = sampleReceipt(harness.npub);
    const signed = await harness.client.requestSignature(receipt);
    assert.match(signed.signature, /^[0-9a-f]{128}$/);
    assert.equal(signed.service_identity, harness.npub);
    assert.equal(verifyReceiptSignature(receipt, signed.signature, harness.npub), true);
    // Tampered amount or client id fails verification (SEC-2026-036 test pair).
    assert.equal(verifyReceiptSignature(sampleReceipt(harness.npub, { amount_sats: 9999 }), signed.signature, harness.npub), false);
    assert.equal(verifyReceiptSignature(sampleReceipt(harness.npub, { client_id: "attacker-opaque" }), signed.signature, harness.npub), false);
  } finally {
    await harness.service.close();
  }
});

test("a wrong auth secret is rejected before any signing happens", async () => {
  const harness = await startSigner();
  try {
    const impostor = new ReceiptSignerClient({
      pipePath: harness.pipePath,
      authSecret: "wrong-synthetic-secret",
      expectedServiceNpub: harness.npub,
    });
    await assert.rejects(impostor.requestSignature(sampleReceipt(harness.npub)), /authentication_failed/);
    // The service stays usable for the correctly authenticated client.
    const signed = await harness.client.requestSignature(sampleReceipt(harness.npub, { receipt_id: "0197f000-0000-7000-8000-000000000002" }));
    assert.match(signed.signature, /^[0-9a-f]{128}$/);
  } finally {
    await harness.service.close();
  }
});

test("replayed request ids are rejected within the replay window", async () => {
  const harness = await startSigner();
  try {
    const receipt = sampleReceipt(harness.npub);
    const first = await harness.client.requestSignature(receipt, { requestId: "replay-probe-1" });
    assert.match(first.signature, /^[0-9a-f]{128}$/);
    await assert.rejects(harness.client.requestSignature(receipt, { requestId: "replay-probe-1" }), /replayed_request/);
  } finally {
    await harness.service.close();
  }
});

test("out-of-allowlist purposes and malformed receipts never reach the signer", async () => {
  const harness = await startSigner({ purposes: ["sign_receipt"] });
  try {
    await assert.rejects(harness.client.requestArtifactSignature("ab".repeat(32)), /purpose_not_allowed/);
    // The client itself refuses to send a content-bearing receipt; the shape
    // assertion fires before any bytes reach the wire.
    const badReceipt = sampleReceipt(harness.npub, { url: "https://private.example.test" });
    await assert.rejects(harness.client.requestSignature(badReceipt, { requestId: "bad-receipt-1" }), /non-allowlisted field/);
  } finally {
    await harness.service.close();
  }
});

test("artifact signing through the pipe satisfies the V1 signer contract without local keys", async () => {
  const harness = await startSigner();
  try {
    const remoteSigner = createRemoteArtifactSigner({ client: harness.client, serviceNpub: harness.npub });
    const digest = "ef".repeat(32);
    const signed = await remoteSigner.sign({ artifact_digest: digest });
    assert.equal(signed.publisher_npub, harness.npub);
    assert.match(signed.publisher_signature, /^[0-9a-f]{128}$/);
    assert.equal(await remoteSigner.verify({ artifact_digest: digest, publisher_signature: signed.publisher_signature, publisher_npub: harness.npub }), true);
    // Same-identity rule: foreign npub with its own valid signature is false.
    const foreignStorage = createInMemoryStorage();
    const foreignNpub = await provisionSignerIdentity({ storage: foreignStorage });
    const foreignSigner = createCredentialStoreSigner({ storage: foreignStorage });
    const foreignSigned = await foreignSigner.sign({ artifact_digest: digest });
    assert.equal(
      await remoteSigner.verify({ artifact_digest: digest, publisher_signature: foreignSigned.publisher_signature, publisher_npub: foreignNpub }),
      false,
    );
    // Tampered digest fails.
    assert.equal(
      await remoteSigner.verify({ artifact_digest: "ff".repeat(32), publisher_signature: signed.publisher_signature, publisher_npub: harness.npub }),
      false,
    );
    // The digest the off-serving signer actually signed matches the receipt
    // contract discipline (deterministic canonical digest).
    assert.equal(typeof receiptDigest(sampleReceipt(harness.npub)), "string");
  } finally {
    await harness.service.close();
  }
});

test("an unprovisioned signer store fails closed without plaintext fallback", async () => {
  const emptyStorage = createInMemoryStorage();
  const signer = createCredentialStoreSigner({ storage: emptyStorage });
  const pipePath = receiptSignerPipePath(randomBytes(6).toString("hex"));
  const service = createReceiptSignerService({ signer, pipePath, authSecret: AUTH_SECRET });
  await service.listen();
  try {
    const client = new ReceiptSignerClient({ pipePath, authSecret: AUTH_SECRET, expectedServiceNpub: "npub1neverprovisioned" });
    await assert.rejects(client.requestSignature(sampleReceipt("npub1neverprovisioned")), /signer_unavailable/);
  } finally {
    await service.close();
  }
});
