// Offline tests for the canonical receipt contract, public signature
// verification, and the serving-plane signer client shape
// (source-summarization-receipt.mjs).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  RECEIPT_FIELDS,
  ReceiptSignerClient,
  receiptDigest,
  receiptSignerPipePath,
  verifyReceiptSignature,
} from "./source-summarization-receipt.mjs";
import { createCredentialStoreSigner, createInMemoryStorage, deriveNpub, provisionSignerIdentity } from "./source-summarization-signer.mjs";

const SCRIPT_PATH = new URL("./source-summarization-receipt.mjs", import.meta.url);

async function provisionedSigner() {
  const storage = createInMemoryStorage();
  const npub = await provisionSignerIdentity({ storage });
  return { signer: createCredentialStoreSigner({ storage }), npub };
}

function sampleReceipt(overrides = {}) {
  return {
    receipt_id: "0197f000-0000-7000-8000-000000000001",
    capability: "source-summarization",
    version: "0.1.0",
    amount_sats: 21,
    payment_hash: "ab".repeat(32),
    client_id: "client-a-opaque",
    service_identity: "PLACEHOLDER_NPUB",
    issued_at: "2026-08-17T12:00:00.000Z",
    valid_until: "2026-08-17T13:00:00.000Z",
    ...overrides,
  };
}

test("receipt shape is the exhaustive content-free field list", () => {
  assert.deepEqual([...RECEIPT_FIELDS].sort(), [
    "amount_sats",
    "capability",
    "client_id",
    "issued_at",
    "payment_hash",
    "receipt_id",
    "service_identity",
    "valid_until",
    "version",
  ]);
  const receipt = sampleReceipt();
  receiptDigest(receipt);
  assert.throws(() => receiptDigest({ ...receipt, url: "https://private.example.test" }), /non-allowlisted field/);
  assert.throws(() => receiptDigest({ ...receipt, title: "Private title" }), /non-allowlisted field/);
  assert.throws(() => receiptDigest({ ...receipt, preimage: "0".repeat(64) }), /non-allowlisted field/);
  assert.throws(() => receiptDigest({ ...receipt, amount_sats: 0 }), /positive integer/);
  assert.throws(() => receiptDigest({ ...receipt, payment_hash: "nothex" }), /sha-256 hex digest/);
});

test("receipt digest is deterministic and changes when any fact changes", () => {
  const receipt = sampleReceipt();
  assert.equal(receiptDigest(receipt), receiptDigest(sampleReceipt()));
  assert.notEqual(receiptDigest(receipt), receiptDigest(sampleReceipt({ amount_sats: 22 })));
  assert.notEqual(receiptDigest(receipt), receiptDigest(sampleReceipt({ client_id: "client-b-opaque" })));
});

test("signature verification passes for a valid receipt and fails for tampered facts", async () => {
  const { signer, npub } = await provisionedSigner();
  const receipt = sampleReceipt({ service_identity: npub });
  const signed = await signer.sign({ artifact_digest: receiptDigest(receipt) });
  assert.equal(verifyReceiptSignature(receipt, signed.publisher_signature, npub), true);
  assert.equal(verifyReceiptSignature(sampleReceipt({ ...receipt, amount_sats: 1000 }), signed.publisher_signature, npub), false);
  assert.equal(verifyReceiptSignature(sampleReceipt({ ...receipt, client_id: "attacker-opaque" }), signed.publisher_signature, npub), false);
  assert.equal(verifyReceiptSignature(receipt, "0".repeat(128), npub), false);
  // A receipt claiming a foreign service identity never verifies against the
  // pinned npub, even with the original signature.
  assert.equal(verifyReceiptSignature(sampleReceipt({ service_identity: deriveNpub(Buffer.alloc(32, 7)) }), signed.publisher_signature, npub), false);
});

test("the signer client constructor enforces its required boundary inputs", () => {
  assert.throws(() => new ReceiptSignerClient({}), /pipePath is required/);
  assert.throws(() => new ReceiptSignerClient({ pipePath: receiptSignerPipePath("x") }), /authSecret is required/);
  assert.throws(
    () => new ReceiptSignerClient({ pipePath: receiptSignerPipePath("x"), authSecret: "synthetic-boot-secret" }),
    /expectedServiceNpub is required/,
  );
  const client = new ReceiptSignerClient({
    pipePath: receiptSignerPipePath("x"),
    authSecret: "synthetic-boot-secret",
    expectedServiceNpub: "npub1synthetic",
  });
  assert.equal(typeof client.requestSignature, "function");
  assert.equal(typeof client.requestArtifactSignature, "function");
});

test("the receipt module never references key-store or credential functions", () => {
  const source = readFileSync(SCRIPT_PATH, "utf8");
  assert.equal(source.includes("createCredentialStoreSigner"), false);
  assert.equal(source.includes("createDpapiFileStorage"), false);
  assert.equal(source.includes("provisionSignerIdentity"), false);
  assert.equal(source.includes("defaultStorageDir"), false);
  // Client-only network surface: a named-pipe connect, no TCP/DNS/http.
  assert.doesNotMatch(source, /from ["']node:(?:http|https|dns)(?:["'])/);
  assert.doesNotMatch(source, /\bfetch\s*\(/);
});
