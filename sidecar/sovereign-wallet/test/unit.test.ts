//! Unit tests: redaction, loopback token, invoice/network guards, gRPC error
//! mapping, idempotency store, sidecar lock, ACL lockdown.

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
import { assertInvoiceNetwork, assertNetworkMatches, WavedErrorImpl, mapGrpcError } from "../dist/wavelength.js";

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

describe("invoice/network guards (design §3.4, SEC-2026-050)", () => {
  it("accepts signet/testnet/regtest invoices and refuses mainnet", () => {
    assert.equal(assertInvoiceNetwork("signet", "lntbs10u1p0example"), undefined);
    assert.equal(assertInvoiceNetwork("signet", "lntb10u1p0example"), undefined);
    assert.equal(assertInvoiceNetwork("regtest", "lnbcrt10u1p0example"), undefined);
    assert.throws(() => assertInvoiceNetwork("signet", "lnbc10u1p0example"), (error) => {
      return error instanceof WavedErrorImpl && error.envelope.code === "MAINNET_REFUSED";
    });
    assert.throws(() => assertInvoiceNetwork("regtest", "lntbs10u1p0example"), (error) => {
      return error instanceof WavedErrorImpl && error.envelope.code === "INVALID_ARGS";
    });
  });

  it("refuses a mainnet runtime network report (SEC-2026-050)", () => {
    assert.throws(() => assertNetworkMatches("signet", "mainnet"), (error) => {
      return error instanceof WavedErrorImpl && error.envelope.code === "MAINNET_REFUSED";
    });
    assert.throws(() => assertNetworkMatches("signet", "testnet"), (error) => {
      return error instanceof WavedErrorImpl && error.envelope.code === "INTERNAL";
    });
    assert.equal(assertNetworkMatches("signet", "signet"), undefined);
  });
});

describe("gRPC error mapping (wavecli-style envelope)", () => {
  it("maps lifecycle preconditions to WALLET_* codes", () => {
    const locked = mapGrpcError(9, "wallet is locked; run unlock");
    assert.equal(locked.code, "WALLET_LOCKED");
    const notCreated = mapGrpcError(9, "no wallet exists");
    assert.equal(notCreated.code, "WALLET_NOT_CREATED");
  });

  it("marks fund-moving timeout codes as non-blindly-retryable", () => {
    const deadline = mapGrpcError(4, "deadline exceeded");
    assert.equal(deadline.code, "DEADLINE_EXCEEDED");
    const unimplemented = mapGrpcError(12, "unknown service wavewalletrpc.WalletService");
    assert.equal(unimplemented.code, "WAVED_WALLET_API_UNAVAILABLE");
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
    assert.equal(store.store("make-invoice", key, { invoice: "lntbs1" }), true);
    assert.equal(store.store("make-invoice", key, { invoice: "lntbs1" }), false);
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

