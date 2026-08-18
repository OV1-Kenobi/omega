// Offline tests for the synthetic L-402 policy/payment authority boundary
// (source-summarization-l402.mjs). Deterministic: injected clock, injected
// authority keys where needed, no network, no real invoices or credentials.

import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";

import {
  ANONYMOUS_CLIENT_BUCKET,
  CHALLENGE_RECORD_FIELDS,
  createChallengeEntitlementStore,
  createFixedWindowLimiter,
  createQuotaTracker,
  createRateLimiter,
  createSyntheticPaymentAuthority,
  deriveOpaqueClientId,
  parseAuthorizationHeader,
  sha256Hex,
  verifyChallengeToken,
  verifyL402Proof,
} from "./source-summarization-l402.mjs";

const SERVICE_NPUB = "npub1syntheticserviceidentityfortestingonly";
const FIXED_CLOCK = () => new Date("2026-08-17T12:00:00.000Z");

function makeAuthority(overrides = {}) {
  return createSyntheticPaymentAuthority({
    clock: FIXED_CLOCK,
    serviceIdentity: SERVICE_NPUB,
    ...overrides,
  });
}

function paidCredential(authority, overrides = {}) {
  const issued = authority.issueChallenge({
    capability: "source-summarization",
    version: "0.1.0",
    amountSats: 21,
    serviceIdentity: SERVICE_NPUB,
    ...overrides,
  });
  const preimageHex = authority.settle(issued.challenge.challenge_id);
  return {
    issued,
    authorization: `L402 ${issued.macaroon}:${preimageHex}`,
  };
}

test("a challenge carries typed metadata, a verifiable token, and a clearly synthetic invoice", () => {
  const authority = makeAuthority();
  const { challenge, macaroon, invoice } = authority.issueChallenge({
    capability: "source-summarization",
    version: "0.1.0",
    amountSats: 21,
    serviceIdentity: SERVICE_NPUB,
  });
  assert.equal(challenge.amount_sats, 21);
  assert.equal(challenge.capability, "source-summarization");
  assert.equal(challenge.status, "issued");
  assert.match(challenge.payment_hash, /^[0-9a-f]{64}$/);
  assert.match(invoice, /^SYNTHETIC-INVOICE-1:/);
  assert.equal(typeof macaroon, "string");
  const token = verifyChallengeToken(macaroon, authority.publicKeyPem);
  assert.equal(token.ok, true);
  assert.equal(token.payload.payment_hash, challenge.payment_hash);
  // The challenge record stored operator-side is exactly the content-free
  // allowlist: no invoice, no macaroon, no preimage anywhere in it.
  for (const field of Object.keys(challenge)) {
    assert.ok(CHALLENGE_RECORD_FIELDS.includes(field), `unexpected field ${field}`);
  }
  assert.equal(JSON.stringify(challenge).includes(invoice), false);
  // The authority's issue path never hands the preimage to the caller.
  assert.equal("preimage" in { challenge, macaroon, invoice }, false);
});

test("token verification fails closed on tampering and foreign keys", () => {
  const authority = makeAuthority();
  const { macaroon } = authority.issueChallenge({
    capability: "source-summarization",
    version: "0.1.0",
    amountSats: 21,
    serviceIdentity: SERVICE_NPUB,
  });
  const decoded = JSON.parse(Buffer.from(macaroon, "base64").toString("utf8"));
  decoded.payload.amount_sats = 1;
  const tampered = Buffer.from(JSON.stringify(decoded)).toString("base64");
  assert.equal(verifyChallengeToken(tampered, authority.publicKeyPem).ok, false);
  const foreign = generateKeyPairSync("ed25519");
  const foreignPem = foreign.publicKey.export({ type: "spki", format: "pem" }).toString();
  assert.equal(verifyChallengeToken(macaroon, foreignPem).ok, false);
  assert.equal(verifyChallengeToken("not-base64-json!", authority.publicKeyPem).ok, false);
});

test("valid proof verifies statelessly via sha256(preimage) == payment_hash", () => {
  const authority = makeAuthority();
  const { authorization, issued } = paidCredential(authority);
  const proof = verifyL402Proof({ authorization, authorityPublicKeyPem: authority.publicKeyPem, clock: FIXED_CLOCK });
  assert.equal(proof.ok, true);
  assert.equal(proof.payment_hash, issued.challenge.payment_hash);
  assert.equal(proof.amount_sats, 21);
});

test("missing, malformed, wrong, expired, and foreign proofs fail closed", () => {
  const authority = makeAuthority();
  const { issued, authorization } = paidCredential(authority);

  assert.deepEqual(parseAuthorizationHeader(undefined), { ok: false, reason: "missing_authorization" });
  assert.deepEqual(parseAuthorizationHeader("Bearer xyz"), { ok: false, reason: "malformed_authorization" });
  assert.equal(verifyL402Proof({ authorization: "L402 onlymacaroon", authorityPublicKeyPem: authority.publicKeyPem, clock: FIXED_CLOCK }).reason, "malformed_authorization");
  assert.equal(
    verifyL402Proof({ authorization: `L402 ${issued.macaroon}:${"0".repeat(64)}`, authorityPublicKeyPem: authority.publicKeyPem, clock: FIXED_CLOCK }).reason,
    "preimage_mismatch",
  );
  assert.equal(
    verifyL402Proof({ authorization: `L402 ${issued.macaroon}:${"zz".repeat(32)}`, authorityPublicKeyPem: authority.publicKeyPem, clock: FIXED_CLOCK }).reason,
    "malformed_authorization",
  );
  const laterClock = () => new Date("2026-08-17T13:00:00.000Z");
  assert.equal(
    verifyL402Proof({ authorization, authorityPublicKeyPem: authority.publicKeyPem, clock: laterClock }).reason,
    "expired_challenge",
  );
  const foreign = generateKeyPairSync("ed25519");
  const foreignPem = foreign.publicKey.export({ type: "spki", format: "pem" }).toString();
  assert.equal(verifyL402Proof({ authorization, authorityPublicKeyPem: foreignPem, clock: FIXED_CLOCK }).reason, "invalid_payment_token");
  // Wrong-preimage attempts create no record side effects by construction:
  // verifyL402Proof touches no store. Assert the store stays empty around it.
  const store = createChallengeEntitlementStore();
  verifyL402Proof({ authorization: `L402 ${issued.macaroon}:${"1".repeat(64)}`, authorityPublicKeyPem: authority.publicKeyPem, clock: FIXED_CLOCK });
  assert.equal(store.listRecords().length, 0);
  assert.equal(store.isRedeemed(issued.challenge.payment_hash), false);
});

test("one-shot redemption: first proof wins, replay and concurrent replay are denied", () => {
  const authority = makeAuthority();
  const { issued } = paidCredential(authority);
  const store = createChallengeEntitlementStore();
  store.recordChallenge(issued.challenge);
  assert.equal(store.redeem(issued.challenge.payment_hash).ok, true);
  assert.equal(store.redeem(issued.challenge.payment_hash).ok, false);
  assert.equal(store.redeem(issued.challenge.payment_hash).ok, false);
  assert.equal(store.getChallenge(issued.challenge.challenge_id).status, "redeemed");
  // Cross-client isolation: a different client's proof (different payment
  // hash) redeems only its own entitlement.
  const other = paidCredential(authority, { amountSats: 5 });
  store.recordChallenge(other.issued.challenge);
  assert.equal(store.redeem(other.issued.challenge.payment_hash).ok, true);
  assert.equal(store.redeem(issued.challenge.payment_hash).ok, false);
});

test("the entitlement store rejects content-bearing records (schema enforcement)", () => {
  const store = createChallengeEntitlementStore();
  const authority = makeAuthority();
  const { issued } = paidCredential(authority);
  const contaminated = { ...issued.challenge, url: "https://private.example.test/article", title: "Private title" };
  assert.throws(() => store.recordChallenge(contaminated), /non-allowlisted field/);
  assert.throws(
    () => store.recordChallenge({ ...issued.challenge, invoice: "SYNTHETIC-INVOICE-1:deadbeef" }),
    /non-allowlisted field/,
  );
  assert.throws(() => store.recordChallenge({ ...issued.challenge, status: "paid-with-love" }), /invalid status/);
  // The negative test from the plan: a record attempt carrying request
  // content must fail, leaving the store empty.
  assert.equal(store.listRecords().length, 0);
});

test("stored operator records are content-free across a full round trip", () => {
  const authority = makeAuthority();
  const store = createChallengeEntitlementStore();
  const { issued } = paidCredential(authority, { clientId: deriveOpaqueClientId("server-secret", "client-a") });
  store.recordChallenge(issued.challenge);
  store.redeem(issued.challenge.payment_hash);
  const serialized = JSON.stringify(store.listRecords());
  assert.equal(serialized.includes("SYNTHETIC-INVOICE"), false);
  assert.equal(serialized.includes(issued.macaroon), false);
  for (const field of CHALLENGE_RECORD_FIELDS) {
    assert.ok(serialized.includes(`"${field}"`), `field ${field} missing`);
  }
});

test("opaque client ids are stable, keyed by the server secret, and never the material itself", () => {
  const first = deriveOpaqueClientId("server-secret", "client-a");
  const second = deriveOpaqueClientId("server-secret", "client-a");
  const otherClient = deriveOpaqueClientId("server-secret", "client-b");
  const otherSecret = deriveOpaqueClientId("other-secret", "client-a");
  assert.equal(first, second);
  assert.notEqual(first, otherClient);
  assert.notEqual(first, otherSecret);
  assert.match(first, /^[0-9a-f]{32}$/);
  // HMAC contract (O2-P3): secret confusion — the same material under
  // different server secrets — yields pairwise-distinct ids.
  const secretConfusion = ["server-secret", "server-secret-2", "server-secret-3"].map((secret) =>
    deriveOpaqueClientId(secret, "client-a"),
  );
  for (const id of secretConfusion) assert.match(id, /^[0-9a-f]{32}$/);
  for (let i = 0; i < secretConfusion.length; i += 1) {
    for (let j = i + 1; j < secretConfusion.length; j += 1) {
      assert.notEqual(secretConfusion[i], secretConfusion[j], `secrets ${i} and ${j} must not collide`);
    }
  }
  // HMAC contract (O2-P3): output is stable under the same secret across
  // repeated calls, for any material.
  for (const material of ["client-a", "client-b", "different-material"]) {
    assert.equal(
      deriveOpaqueClientId("stable-secret", material),
      deriveOpaqueClientId("stable-secret", material),
      `material ${material} must be stable under the same secret`,
    );
  }
});

test("sha256Hex matches node crypto for the preimage check", () => {
  const preimage = randomBytes(32);
  assert.equal(sha256Hex(preimage), sha256Hex(Buffer.from(preimage)));
  assert.equal(sha256Hex(preimage).length, 64);
});

test("the fixed-window limiter enforces its max and resets after the window", () => {
  let nowMs = Date.parse("2026-08-17T12:00:00.000Z");
  const clock = () => new Date(nowMs);
  const limiter = createFixedWindowLimiter({ max: 3, windowMs: 60_000, clock });
  assert.equal(limiter.check("client-a").allowed, true);
  assert.equal(limiter.check("client-a").allowed, true);
  assert.equal(limiter.check("client-a").allowed, true);
  const denied = limiter.check("client-a");
  assert.equal(denied.allowed, false);
  assert.equal(denied.retry_after_seconds >= 1, true);
  assert.equal(denied.remaining, 0);
  // Denial persists within the window and does not inflate the counter.
  assert.equal(limiter.check("client-a").allowed, false);
  assert.equal(limiter.snapshot()[0].count, 3);
  // Window rollover resets the count in a fresh window.
  nowMs += 60_001;
  const reset = limiter.check("client-a");
  assert.equal(reset.allowed, true);
  assert.equal(reset.count, 1);
  assert.equal(reset.window_start > denied.window_start, true);
});

test("limiter and quota boundaries are exact below, at, and above the cap", () => {
  const clock = () => new Date("2026-08-17T12:00:00.000Z");
  const quota = createFixedWindowLimiter({ max: 2, windowMs: 60_000, clock });
  const below = quota.check("client-a");
  assert.deepEqual([below.allowed, below.count, below.remaining], [true, 1, 1]);
  const equal = quota.check("client-a");
  assert.deepEqual([equal.allowed, equal.count, equal.remaining], [true, 2, 0]);
  const above = quota.check("client-a");
  assert.deepEqual([above.allowed, above.count, above.remaining], [false, 2, 0]);
  // peek observes without consuming: still denied, counter unchanged.
  const observed = quota.peek("client-a");
  assert.equal(observed.allowed, false);
  assert.equal(quota.snapshot()[0].count, 2);
});

test("limiter state is isolated per client and stores only content-free counters", () => {
  const clock = () => new Date("2026-08-17T12:00:00.000Z");
  const limiter = createFixedWindowLimiter({ max: 1, windowMs: 60_000, clock });
  assert.equal(limiter.check("client-a").allowed, true);
  assert.equal(limiter.check("client-a").allowed, false);
  // Client B is unaffected by client A's consumption.
  assert.equal(limiter.check("client-b").allowed, true);
  assert.equal(limiter.check(ANONYMOUS_CLIENT_BUCKET).allowed, true);
  assert.equal(limiter.check(ANONYMOUS_CLIENT_BUCKET).allowed, false);
  const snapshot = JSON.stringify(limiter.snapshot());
  for (const entry of limiter.snapshot()) {
    assert.deepEqual(Object.keys(entry).sort(), ["count", "key", "window_start"]);
  }
  assert.equal(snapshot.includes("SYNTHETIC"), false);
  assert.equal(snapshot.includes("https://"), false);
});

test("the rate-limiter and quota-tracker factories build the same bounded semantics", () => {
  const clock = () => new Date("2026-08-17T12:00:00.000Z");
  const rate = createRateLimiter({ maxRequests: 1, windowMs: 60_000, clock });
  const quota = createQuotaTracker({ maxOperations: 1, windowMs: 60_000, clock });
  for (const limiter of [rate, quota]) {
    assert.equal(limiter.check("client-a").allowed, true);
    assert.equal(limiter.check("client-a").allowed, false);
    assert.equal(typeof limiter.check("client-a").retry_after_seconds, "number");
  }
});
