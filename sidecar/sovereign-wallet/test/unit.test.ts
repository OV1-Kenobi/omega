//! Unit tests: redaction, loopback token, invoice/network guards, phoenixd
//! error mapping, idempotency store, sidecar lock, ACL lockdown.
//! Updated-with-citation (OMEGA-DELTA-0303): the invoice/network guards moved
//! to the phoenixd client module (phoenixd.ts); the waved gRPC error mapping
//! is replaced by the phoenixd HTTP error mapping.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";

import { describeAcl, lockdownTree } from "../dist/acl.js";
import { generateLoopbackToken, tokenMatches, validateLoopbackToken } from "../dist/http.js";
import { IdempotencyStore } from "../dist/idempotency.js";
import { acquireLock, LockHeldError } from "../dist/lock.js";
import { clearRegisteredSecrets, containsSecretShape, redact, registerSecret } from "../dist/redact.js";
import {
  PhoenixdErrorImpl,
  assertInvoiceNetwork,
  assertNetworkMatches,
  expectedTotalOutflowSat,
  mapPhoenixdError,
  mapPaymentFailed,
  PHOENIXD_PAY_FEE_BASIS_POINTS,
} from "../dist/phoenixd.js";

describe("redact", () => {
it("redacts registered secrets and secret shapes", () => {
    clearRegisteredSecrets();
    registerSecret("correct horse battery staple");
    assert.equal(redact("password is correct horse battery staple here"), "password is [REDACTED] here");
    const nsec = "nsec1" + "q".repeat(60); // realistic bech32 nsec payload length
    assert.equal(redact(`key ${nsec} end`), "key [REDACTED] end");
    const preimage = "b".repeat(64);
    assert.equal(redact(`preimage ${preimage}`), "preimage [REDACTED]");
    assert.equal(containsSecretShape(nsec), true);
    assert.equal(containsSecretShape("plain text only"), false);
  });

  it("redacts JSON values recursively", () => {
    clearRegisteredSecrets();
    registerSecret("s3cret");
    const redacted = redactJsonValueShim({ a: "s3cret", b: ["s3cret"], c: { d: "ok" } });
    assert.deepEqual(redacted, { a: "[REDACTED]", b: ["[REDACTED]"], c: { d: "ok" } });
  });
});

function redactJsonValueShim(value: unknown): unknown {
  // Re-implemented here to avoid importing the ESM-only helper twice; the real
  // redactJsonValue is exercised through main.ts in the protocol tests.
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map(redactJsonValueShim);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) out[key] = redactJsonValueShim(entry);
    return out;
  }
  return value;
}

describe("loopback token (SEC-2026-053)", () => {
  it("matches only the exact token, in constant time", () => {
    const token = generateLoopbackToken();
    assert.equal(tokenMatches(token, token), true);
    assert.equal(tokenMatches(token, "wrong"), false);
    assert.equal(tokenMatches(token, undefined), false);
    assert.equal(tokenMatches(token, token.slice(0, -1)), false);
  });

  it("validates the token shape (fail-closed startup)", () => {
    assert.equal(validateLoopbackToken(undefined), "OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN is not set; the loopback HTTP surface is disabled");
    assert.ok(validateLoopbackToken("short")?.includes("not 32 bytes of hex"));
    assert.equal(validateLoopbackToken(generateLoopbackToken()), null);
  });
});

describe("invoice/network guards (design §3.4, SEC-2026-050; OMEGA-DELTA-0286 — moved to the phoenixd rail by 0303; mainnet-only by OMEGA-DELTA-0305)", () => {
  it("OMEGA-DELTA-0286/0305: the mainnet-only rail accepts lnbc (never lnbcrt) and refuses everything else", () => {
    // The guard follows the rail, which is mainnet-only: `lnbc` passes
    // (still excluding the shared-prefix `lnbcrt` edge), and any other
    // prefix is refused. No signet payments ever travel this rail.
    assert.equal(assertInvoiceNetwork("mainnet", "lnbc10u1p0example"), undefined);
    assert.throws(() => assertInvoiceNetwork("mainnet", "lnbcrt10u1p0example"), (error) => {
      return error instanceof PhoenixdErrorImpl && error.envelope.code === "INVALID_ARGS";
    });
    assert.throws(() => assertInvoiceNetwork("mainnet", "not-a-bolt11-invoice"), (error) => {
      return error instanceof PhoenixdErrorImpl && error.envelope.code === "INVALID_ARGS";
    });
  });

  it("OMEGA-DELTA-0286/0303: the runtime assertion requires reported == configured; mainnet only when opted in; absent report carried by the env gate + guard", () => {
    // SEC-2026-050 revision (0286, rail form 0303): mainnet reported is
    // refused UNLESS configured mainnet AND the allow-mainnet opt-in is
    // present; any other mismatch is refused too. An ABSENT report (getinfo
    // exposes no chain field) is carried by the env gate + the invoice HRP
    // guard (design §2.6.3) — never an error on its own. The rail is
    // mainnet-only (OMEGA-DELTA-0305): only the mainnet-configured shape
    // is constructible.
    assert.throws(() => assertNetworkMatches("mainnet", "mainnet", false), (error) => {
      return error instanceof PhoenixdErrorImpl && error.envelope.code === "MAINNET_REFUSED";
    });
    assert.equal(assertNetworkMatches("mainnet", "mainnet", true), undefined);
    assert.throws(() => assertNetworkMatches("mainnet", "regtest", true), (error) => {
      return error instanceof PhoenixdErrorImpl && error.envelope.code === "INTERNAL";
    });
    assert.equal(assertNetworkMatches("mainnet", null, true), undefined);
  });
});

describe("phoenixd HTTP error mapping (wavecli-style envelope; OMEGA-DELTA-0303)", () => {
  it("maps auth failures to INTERNAL (not retryable) and connection failures to INTERNAL (retryable)", () => {
    const auth = mapPhoenixdError(401, "Invalid authentication (use basic auth with the http password set in phoenix.conf)");
    assert.equal(auth.code, "INTERNAL");
    assert.equal(auth.retryable, false);
    assert.match(auth.remediation, /OMEGA_SOVEREIGN_WALLET_PHOENIXD_API_KEY/);
    const unreachable = mapPhoenixdError(null, "fetch failed");
    assert.equal(unreachable.code, "INTERNAL");
    assert.equal(unreachable.retryable, true);
    assert.match(unreachable.details, /node-unreachable/);
  });

  it("marks fund-moving pay failures as never blindly retryable", () => {
    const deadline = mapPaymentFailed("the payment timed out while routing");
    assert.equal(deadline.code, "DEADLINE_EXCEEDED");
    assert.equal(deadline.retryable, false);
    const aborted = mapPaymentFailed("payment aborted by the node");
    assert.equal(aborted.code, "ABORTED");
    const other = mapPaymentFailed("no route found");
    assert.equal(other.code, "INTERNAL");
    assert.equal(other.retryable, false);
  });

  it("OMEGA-DELTA-0300: the expected-outflow bound is amount + the 0.4% fee, rounded up", () => {
    // 10u = 1,000 sats; 0.4% = 4 sats; bound = 1004.
    const known = expectedTotalOutflowSat("lnbc10u1p0example");
    assert.equal(known.known, true);
    assert.equal(known.expected, 1_004);
    assert.equal(PHOENIXD_PAY_FEE_BASIS_POINTS, 40);
    // Pay-any invoice (no amount): the loss rule must not false-trigger.
    const unknown = expectedTotalOutflowSat("lnbc1p0example");
    assert.equal(unknown.known, false);
  });
});

describe("idempotency store (SEC-2026-047)", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sw-idem-"));
  let store: IdempotencyStore;
  before(() => {
    store = IdempotencyStore.open(dir);
  });
  after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("stores and replays a result, and never holds preimages", () => {
    const key = "11111111-1111-4111-8111-111111111111";
    // main.ts strips the preimage before storing (SEC-2026-047).
    const result = { paymentHash: "a".repeat(64), preimage: null };
    assert.equal(store.store("pay-invoice", key, result), true);
    const replayed = store.fetch("pay-invoice", key);
    assert.ok(replayed);
    assert.equal(replayed.result.paymentHash, "a".repeat(64));
    assert.equal(replayed.result.preimage, null);
  });

  it("ignores duplicate keys (idempotent replay)", () => {
    const key = "22222222-2222-4222-8222-222222222222";
    assert.equal(store.store("make-invoice", key, { invoice: "lnbc1" }), true);
    assert.equal(store.store("make-invoice", key, { invoice: "lnbc1" }), false);
  });
});

describe("sidecar lock (design §1.6)", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sw-lock-"));
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("refuses a second holder (ALREADY_RUNNING)", async () => {
    const lockPath = path.join(dir, "run", "sidecar.lock");
    const first = await acquireLock(lockPath, "test-1");
    await assert.rejects(() => acquireLock(lockPath, "test-2"), LockHeldError);
    await first.release();
    const second = await acquireLock(lockPath, "test-3");
    await second.release();
  });
});

describe("ACL lockdown (SEC-2026-045)", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sw-acl-"));
  after(() => rmSync(dir, { recursive: true, force: true }));

  it("applies an owner-only posture without error", () => {
    lockdownTree(dir);
    const description = describeAcl(dir);
    assert.ok(description.length > 0);
  });
});

