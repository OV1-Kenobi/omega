// Offline paddock tests for the Public HTTP(S) MCP Transport Adapter
// (source-summarization-public-http-server.mjs). Everything here runs on
// 127.0.0.1 with a synthetic payment authority, an in-process off-serving
// receipt signer over a real named pipe, and an in-memory provisioned service
// identity. No TLS certificate material exists in this repository, so the
// TLS branch is exercised at construction level (refusal without material);
// the full-TLS round trip is staging evidence, not claimed here.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { createCredentialStoreSigner, createInMemoryStorage, provisionSignerIdentity } from "./source-summarization-signer.mjs";
import { ReceiptSignerClient, createRemoteArtifactSigner, receiptSignerPipePath, verifyReceiptSignature } from "./source-summarization-receipt.mjs";
import { createReceiptSignerService } from "./source-summarization-receipt-signer.mjs";
import { createSyntheticPaymentAuthority } from "./source-summarization-l402.mjs";
import {
  PUBLIC_TOOL_ALLOWLIST,
  createOperationLog,
  createPublicSourceSummarizationServer,
  createRejectingLibraryBridge,
} from "./source-summarization-public-http-server.mjs";

const SCRIPT_PATH = new URL("./source-summarization-public-http-server.mjs", import.meta.url);
const FIXED_CLOCK = () => new Date("2026-08-17T12:00:00.000Z");
const BOOT_SECRET = "synthetic-paddock-boot-secret";

async function startPaddock({ clock = FIXED_CLOCK, abuseControls } = {}) {
  const storage = createInMemoryStorage();
  const npub = await provisionSignerIdentity({ storage });
  const signerService = createReceiptSignerService({
    signer: createCredentialStoreSigner({ storage }),
    pipePath: receiptSignerPipePath(randomBytes(6).toString("hex")),
    authSecret: BOOT_SECRET,
    allowedPurposes: ["sign_receipt", "artifact_sign"],
  });
  await signerService.listen();
  const client = new ReceiptSignerClient({ pipePath: signerService.pipePath, authSecret: BOOT_SECRET, expectedServiceNpub: npub });
  const authority = createSyntheticPaymentAuthority({ clock, serviceIdentity: npub });
  const bridge = createRejectingLibraryBridge();
  const server = createPublicSourceSummarizationServer({
    plaintextLoopbackPaddock: true,
    serviceNpub: npub,
    signer: createRemoteArtifactSigner({ client, serviceNpub: npub }),
    receiptSignerClient: client,
    authority,
    bridge,
    clock,
    ...(abuseControls === undefined ? {} : { abuseControls }),
  });
  const address = await server.listen(0, "127.0.0.1");
  return { server, signerService, client, bridge, npub, authority, base: `http://127.0.0.1:${address.port}` };
}

async function post(base, body, headers = {}) {
  const response = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  const json = await response.json();
  return { status: response.status, headers: response.headers, json };
}

// Synthetic external agent: requests the tool, receives the 402 challenge,
// "pays" by settling with the authority, and returns the L402 proof parts.
async function payFor(base, authority, body) {
  const challenged = await post(base, body);
  assert.equal(challenged.status, 402);
  const challengeHeader = challenged.headers.get("www-authenticate");
  assert.match(challengeHeader, /^L402 macaroon="[^"]+", invoice="SYNTHETIC-INVOICE-1:[0-9a-f]+"$/);
  const macaroon = challengeHeader.match(/macaroon="([^"]+)"/)[1];
  const token = JSON.parse(Buffer.from(macaroon, "base64").toString("utf8"));
  const preimageHex = authority.settle(token.payload.challenge_id);
  return { macaroon, preimageHex, token, invoice: challengeHeader.match(/invoice="([^"]+)"/)[1] };
}

function stripSignature(receipt) {
  const { signature, ...rest } = receipt;
  void signature;
  return rest;
}

const SUMMARIZE_BODY = {
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: {
    name: "summarize_source",
    arguments: {
      url: "https://private.example.test/paddock-source",
      content: "PRIVATE_PADDOCK_SOURCE_CONTENT alpha fact.",
      source_title: "PRIVATE_PADDOCK_TITLE",
      summary: "Synthetic paddock summary.",
      key_points: ["Synthetic paddock point."],
    },
  },
};

test("construction enforces HTTPS-only at the public edge", () => {
  assert.throws(() => createPublicSourceSummarizationServer({ serviceNpub: "npub1synthetic" }), /tls_required/);
  assert.throws(
    () => createPublicSourceSummarizationServer({ serviceNpub: "npub1synthetic", plaintextLoopbackPaddock: true, host: "0.0.0.0" }),
    /refuses to bind a non-loopback host/,
  );
});

test("the paddock loopback server serves health and the filtered tool list without payment", async () => {
  const harness = await startPaddock();
  try {
    const health = await fetch(`${harness.base}/health`);
    const healthBody = await health.json();
    assert.equal(health.status, 200);
    assert.equal(healthBody.configuration_class, "paddock-loopback");
    assert.equal(healthBody.transport, "paddock-plaintext-loopback");
    assert.deepEqual(healthBody.public_tools, PUBLIC_TOOL_ALLOWLIST);
    assert.equal(JSON.stringify(healthBody).includes("PRIVATE"), false);

    const listed = await post(harness.base, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(listed.status, 200);
    assert.deepEqual(
      listed.json.result.tools.map((tool) => tool.name),
      PUBLIC_TOOL_ALLOWLIST,
    );
    const initialized = await post(harness.base, { jsonrpc: "2.0", id: 2, method: "initialize", params: {} });
    assert.equal(initialized.json.result.protocolVersion, "2025-11-25");
    const ping = await post(harness.base, { jsonrpc: "2.0", id: 3, method: "ping" });
    assert.deepEqual(ping.json.result, {});
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("full L402 round trip: 402 challenge shape, pay, retry, signed artifact and verified receipt", async () => {
  const harness = await startPaddock();
  try {
    const { macaroon, preimageHex, token } = await payFor(harness.base, harness.authority, SUMMARIZE_BODY);
    assert.equal(token.payload.amount_sats, 21);
    const granted = await post(harness.base, SUMMARIZE_BODY, { Authorization: `L402 ${macaroon}:${preimageHex}` });
    assert.equal(granted.status, 200);
    assert.equal(granted.json.result.isError, undefined);
    const artifact = JSON.parse(granted.json.result.content[0].text);
    assert.match(artifact.integrity.publisher_signature, /^[0-9a-f]{128}$/);
    assert.equal(artifact.integrity.publisher_npub, harness.npub);
    const receipt = granted.json.result.structuredContent.l402_receipt;
    assert.equal(receipt.amount_sats, 21);
    assert.equal(receipt.service_identity, harness.npub);
    assert.equal(verifyReceiptSignature(stripSignature(receipt), receipt.signature, harness.npub), true);
    // Tampered receipt facts fail verification (receipt-signing custody test pair).
    assert.equal(verifyReceiptSignature({ ...stripSignature(receipt), amount_sats: 9999 }, receipt.signature, harness.npub), false);
    assert.equal(verifyReceiptSignature({ ...stripSignature(receipt), client_id: "attacker-opaque" }, receipt.signature, harness.npub), false);
    // No library operation occurred.
    assert.equal(harness.bridge.rejectionCount(), 0);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("missing, malformed, and wrong proofs fail closed without side effects", async () => {
  const harness = await startPaddock();
  try {
    // No Authorization header: 402 challenge, no entitlement.
    const missing = await post(harness.base, SUMMARIZE_BODY);
    assert.equal(missing.status, 402);
    assert.match(missing.headers.get("www-authenticate"), /^L402 macaroon=/);

    // Malformed Authorization header: 400, bounded error, no challenge echo.
    const malformed = await post(harness.base, SUMMARIZE_BODY, { Authorization: "Bearer something" });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.json.error.code, -32002);
    const malformedTwo = await post(harness.base, SUMMARIZE_BODY, { Authorization: "L402 macaroon-only" });
    assert.equal(malformedTwo.status, 400);

    // Wrong preimage: 402 re-challenge, no entitlement, no receipt, and no
    // request-content or proof material anywhere in the error body.
    const { macaroon } = await payFor(harness.base, harness.authority, SUMMARIZE_BODY);
    const wrong = await post(harness.base, SUMMARIZE_BODY, { Authorization: `L402 ${macaroon}:${"1".repeat(64)}` });
    assert.equal(wrong.status, 402);
    assert.match(wrong.headers.get("www-authenticate"), /^L402 macaroon=/);
    assert.equal(JSON.stringify(wrong.json).includes("PRIVATE_PADDOCK"), false);

    const store = harness.server.entitlementStore;
    assert.equal(store.listRecords().every((record) => record.status !== "redeemed"), true);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("a valid proof is one-shot: replay gets a fresh challenge and no second grant", async () => {
  const harness = await startPaddock();
  try {
    const { macaroon, preimageHex } = await payFor(harness.base, harness.authority, SUMMARIZE_BODY);
    const first = await post(harness.base, SUMMARIZE_BODY, { Authorization: `L402 ${macaroon}:${preimageHex}` });
    assert.equal(first.status, 200);
    const replay = await post(harness.base, SUMMARIZE_BODY, { Authorization: `L402 ${macaroon}:${preimageHex}` });
    assert.equal(replay.status, 402);
    assert.match(replay.headers.get("www-authenticate"), /^L402 macaroon=/);
    const redeemed = harness.server.entitlementStore.listRecords().filter((record) => record.status === "redeemed");
    assert.equal(redeemed.length, 1);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("library tools and record-id exports are rejected before dispatch; the bridge is never reached", async () => {
  const harness = await startPaddock();
  try {
    for (const name of ["save_source_analysis", "get_saved_analysis", "list_saved_analyses"]) {
      const rejected = await post(harness.base, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: {} } });
      assert.equal(rejected.status, 200);
      const error = JSON.parse(rejected.json.result.content[0].text).error;
      assert.equal(error.code, "tool_not_available_on_public_transport");
    }
    const recordExport = await post(harness.base, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "export_source_analysis", arguments: { record_id: "0197f000-0000-7000-8000-00000000dead" } },
    });
    assert.equal(JSON.parse(recordExport.json.result.content[0].text).error.code, "tool_not_available_on_public_transport");
    const unknown = await post(harness.base, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "not_a_tool", arguments: {} } });
    assert.equal(JSON.parse(unknown.json.result.content[0].text).error.code, "unknown_tool");
    assert.equal(harness.bridge.rejectionCount(), 0);
    // No challenge was ever issued for these calls: they were rejected before
    // the payment gate, so the store stayed empty.
    assert.equal(harness.server.entitlementStore.listRecords().length, 0);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("a valid proof minted for a different capability does not pay for this service", async () => {
  const harness = await startPaddock();
  try {
    const foreign = harness.authority.issueChallenge({
      capability: "some-other-capability",
      version: "0.1.0",
      amountSats: 21,
      serviceIdentity: harness.npub,
    });
    const preimageHex = harness.authority.settle(foreign.challenge.challenge_id);
    const cross = await post(harness.base, SUMMARIZE_BODY, { Authorization: `L402 ${foreign.macaroon}:${preimageHex}` });
    assert.equal(cross.status, 400);
    assert.equal(cross.json.error.code, -32003);
    assert.equal(harness.server.entitlementStore.listRecords().length, 0);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("per-client request rate limiting enforces, resets, and stays content-free", async () => {
  let nowMs = Date.parse("2026-08-17T12:00:00.000Z");
  const clock = () => new Date(nowMs);
  const harness = await startPaddock({
    clock,
    abuseControls: { requestWindowMs: 60_000, maxRequestsPerWindow: 3, challengeWindowMs: 60_000, maxChallengesPerWindow: 10, freeAllowance: null },
  });
  try {
    const headers = { "x-opaque-client-id": "client-a" };
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await post(harness.base, SUMMARIZE_BODY, headers);
      assert.equal(response.status, 402);
      assert.match(response.headers.get("www-authenticate"), /^L402 macaroon=/);
    }
    const limited = await post(harness.base, SUMMARIZE_BODY, headers);
    assert.equal(limited.status, 429);
    assert.equal(limited.json.error.code, -32009);
    assert.equal(Number.isInteger(limited.json.error.data.retry_after_seconds), true);
    assert.match(limited.headers.get("retry-after"), /^\d+$/);
    // Over the request limit NO challenge is minted: no invoice material.
    assert.equal(limited.headers.get("www-authenticate"), null);
    // Cross-client isolation: client B is unaffected by A's exhaustion.
    const clientB = await post(harness.base, SUMMARIZE_BODY, { "x-opaque-client-id": "client-b" });
    assert.equal(clientB.status, 402);
    // Window rollover resets the budget.
    nowMs += 60_001;
    const reset = await post(harness.base, SUMMARIZE_BODY, headers);
    assert.equal(reset.status, 402);
    // The 429 body and the operation log stay content-free.
    assert.equal(JSON.stringify(limited.json).includes("PRIVATE_PADDOCK"), false);
    assert.equal(JSON.stringify(limited.json).includes("private.example.test"), false);
    const log = JSON.stringify(harness.server.operationLog.list());
    assert.equal(log.includes("PRIVATE_PADDOCK"), false);
    assert.equal(log.includes("private.example.test"), false);
    assert.equal(log.includes("rate_limited"), true);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("challenge issuance is bounded per client and the bound emits no challenge", async () => {
  const clock = () => new Date("2026-08-17T12:00:00.000Z");
  const harness = await startPaddock({
    clock,
    abuseControls: { requestWindowMs: 60_000, maxRequestsPerWindow: 100, challengeWindowMs: 60_000, maxChallengesPerWindow: 2, freeAllowance: null },
  });
  try {
    const headers = { "x-opaque-client-id": "client-a" };
    const first = await post(harness.base, SUMMARIZE_BODY, headers);
    assert.equal(first.status, 402);
    assert.match(first.headers.get("www-authenticate"), /^L402 macaroon=/);
    const second = await post(harness.base, SUMMARIZE_BODY, headers);
    assert.equal(second.status, 402);
    assert.match(second.headers.get("www-authenticate"), /^L402 macaroon=/);
    const bounded = await post(harness.base, SUMMARIZE_BODY, headers);
    assert.equal(bounded.status, 429);
    assert.equal(bounded.json.error.code, -32011);
    assert.equal(Number.isInteger(bounded.json.error.data.retry_after_seconds), true);
    assert.equal(bounded.headers.get("www-authenticate"), null);
    // Exactly two challenges were recorded for this client, never more.
    assert.equal(harness.server.entitlementStore.listRecords().length, 2);
    // Cross-client isolation: client B still receives a fresh challenge.
    const clientB = await post(harness.base, SUMMARIZE_BODY, { "x-opaque-client-id": "client-b" });
    assert.equal(clientB.status, 402);
    assert.match(clientB.headers.get("www-authenticate"), /^L402 macaroon=/);
    const log = JSON.stringify(harness.server.operationLog.list());
    assert.equal(log.includes("challenge_limit_reached"), true);
    assert.equal(log.includes("PRIVATE_PADDOCK"), false);
    assert.equal(log.includes("SYNTHETIC-INVOICE"), false);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("free-allowance quota enforces honestly without burning the paid proof", async () => {
  let nowMs = Date.parse("2026-08-17T12:00:00.000Z");
  const clock = () => new Date(nowMs);
  const harness = await startPaddock({
    clock,
    abuseControls: {
      requestWindowMs: 60_000,
      maxRequestsPerWindow: 100,
      challengeWindowMs: 60_000,
      maxChallengesPerWindow: 10,
      freeAllowance: { windowMs: 60_000, operationsPerWindow: 1 },
    },
  });
  try {
    const headers = { "x-opaque-client-id": "client-a" };
    // First paid call consumes the single-operation quota and succeeds.
    const first = await payFor(harness.base, harness.authority, SUMMARIZE_BODY);
    const granted = await post(harness.base, SUMMARIZE_BODY, { ...headers, Authorization: `L402 ${first.macaroon}:${first.preimageHex}` });
    assert.equal(granted.status, 200);

    // Second paid call: quota exhausted BEFORE redemption, so the fresh paid
    // proof is NOT burned and the error is honest, redacted, content-free.
    const second = await payFor(harness.base, harness.authority, SUMMARIZE_BODY);
    const exhausted = await post(harness.base, SUMMARIZE_BODY, { ...headers, Authorization: `L402 ${second.macaroon}:${second.preimageHex}` });
    assert.equal(exhausted.status, 429);
    assert.equal(exhausted.json.error.code, -32010);
    assert.equal(Number.isInteger(exhausted.json.error.data.retry_after_seconds), true);
    assert.equal(exhausted.json.error.data.max_operations, 1);
    assert.equal(exhausted.headers.get("www-authenticate"), null);
    assert.equal(JSON.stringify(exhausted.json).includes("PRIVATE_PADDOCK"), false);
    assert.equal(harness.server.entitlementStore.isRedeemed(second.token.payload.payment_hash), false);
    assert.equal(harness.server.entitlementStore.listRecords().filter((record) => record.status === "redeemed").length, 1);

    // Cross-client isolation: client B's quota window is untouched.
    const clientBProof = await payFor(harness.base, harness.authority, SUMMARIZE_BODY);
    const clientB = await post(harness.base, SUMMARIZE_BODY, { "x-opaque-client-id": "client-b", Authorization: `L402 ${clientBProof.macaroon}:${clientBProof.preimageHex}` });
    assert.equal(clientB.status, 200);

    // After the quota window resets, the SAME unconsumed proof succeeds.
    nowMs += 60_001;
    const retried = await post(harness.base, SUMMARIZE_BODY, { ...headers, Authorization: `L402 ${second.macaroon}:${second.preimageHex}` });
    assert.equal(retried.status, 200);
    const log = JSON.stringify(harness.server.operationLog.list());
    assert.equal(log.includes("quota_exhausted"), true);
    assert.equal(log.includes("PRIVATE_PADDOCK"), false);
    assert.equal(log.includes("private.example.test"), false);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("the operation log and entitlement records stay content-free across a full round trip", async () => {
  const harness = await startPaddock();
  try {
    const { macaroon, preimageHex } = await payFor(harness.base, harness.authority, SUMMARIZE_BODY);
    const granted = await post(harness.base, SUMMARIZE_BODY, { Authorization: `L402 ${macaroon}:${preimageHex}` });
    assert.equal(granted.status, 200);
    const log = JSON.stringify(harness.server.operationLog.list());
    assert.equal(log.includes("private.example.test"), false);
    assert.equal(log.includes("PRIVATE_PADDOCK"), false);
    assert.equal(log.includes("SYNTHETIC-INVOICE"), false);
    assert.equal(log.includes(macaroon), false);
    assert.equal(log.includes(preimageHex), false);
    const records = JSON.stringify(harness.server.entitlementStore.listRecords());
    assert.equal(records.includes("private.example.test"), false);
    assert.equal(records.includes("SYNTHETIC-INVOICE"), false);
    assert.equal(records.includes(macaroon), false);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("batches, oversized bodies, and non-POST methods are rejected with bounded errors", async () => {
  const harness = await startPaddock();
  try {
    const batch = await post(harness.base, [{ jsonrpc: "2.0", id: 1, method: "ping" }]);
    assert.equal(batch.status, 400);
    assert.equal(batch.json.error.code, -32600);

    const wrongMethod = await fetch(`${harness.base}/mcp`, { method: "GET" });
    assert.equal(wrongMethod.status, 405);
    const wrongPath = await fetch(`${harness.base}/elsewhere`, { method: "POST" });
    assert.equal(wrongPath.status, 404);

    const oversized = await fetch(`${harness.base}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "a".repeat(1024 * 1024 + 512 * 1024),
    });
    assert.equal(oversized.status, 413);
  } finally {
    await harness.server.close();
    await harness.signerService.close();
  }
});

test("the public server module holds no key-store, library-bridge, or egress surface", () => {
  const source = readFileSync(SCRIPT_PATH, "utf8");
  // No credential-store or off-serving signer import: the signing key cannot
  // load in this process through this module.
  assert.doesNotMatch(source, /source-summarization-signer\.mjs/);
  assert.doesNotMatch(source, /source-summarization-receipt-signer\.mjs/);
  assert.equal(source.includes("createCredentialStoreSigner"), false);
  assert.equal(source.includes("createDpapiFileStorage"), false);
  // No child-process surface: the local library_cli bridge is unreachable.
  assert.doesNotMatch(source, /node:child_process/);
  assert.doesNotMatch(source, /library_cli/);
  // Listening sockets only: no client fetch/TCP/DNS egress.
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.doesNotMatch(source, /node:net/);
  assert.doesNotMatch(source, /node:dns/);
});

test("the operation log redacts unsafe strings and drops unknown fields", () => {
  const log = createOperationLog({ clock: FIXED_CLOCK });
  const cleaned = log.record({
    event: "http_request",
    tool: "summarize_source",
    status_code: 200,
    url: "https://private.example.test/leak",
    free_text: "PRIVATE_PADDOCK_TITLE",
    payment_hash: "ab".repeat(32),
  });
  assert.equal(cleaned.url, undefined);
  assert.equal(cleaned.free_text, undefined);
  assert.equal(cleaned.payment_hash, "ab".repeat(32));
  const attempted = log.record({ event: "tool_call", invoice: "SYNTHETIC-INVOICE-1:deadbeef" });
  assert.equal(attempted.invoice, undefined);
  assert.equal(attempted.event, "tool_call");
});
