//! WP-6 L-402 gateway tests (MDK protocol; design §5; D3/D5).
//!
//! Coverage (WP-6 scope tests):
//! - BOLT11 payment-hash parsing (SEC-2026-055: server-derived, never
//!   client-supplied; spec-vector verified).
//! - Challenge issuance: HTTP 402 + `WWW-Authenticate: L402 macaroon="…",
//!   invoice="…"` + challenge JSON body.
//! - pay -> proof -> protected response end-to-end on signet (the demo paid
//!   echo route, immediate settlement).
//! - Double redemption refused (`credential_consumed`).
//! - Payment-hash mismatch refused (`invalid_payment_proof`).
//! - Locked-wallet: mint refused with the stable `wallet_locked` error;
//!   redemption of an already-issued challenge stays honored (SEC-2026-054).
//! - Restart idempotency: challenge/redemption state survives a sidecar
//!   restart (SQLite; no in-memory-only truth — design §5.5).
//! - Mandate-gated pay is Rust-side (crates/sovereign_wallet/src/l402.rs);
//!   the Node tests drive the pay step over the stdio `pay-invoice` method
//!   exactly as the mandate-gated Rust path does (see the Rust tests).
//! - Mainnet follows the configured network (OMEGA-DELTA-0287): the
//!   signet-configured gateway still refuses lnbc; a mainnet-configured
//!   gateway mints lnbc challenges and refuses mismatched-HRP invoices.
//! - Concurrency single-winner: parallel redemptions -> exactly one settles.
//! - Deferred-settlement crash-window recovery (SEC-2026-048): a `checked`
//!   redemption without a settle is recoverable after a restart; exactly one
//!   settled row ever exists.
//! - HMAC-key custody (SEC-2026-044): the key lives encrypted in the vault
//!   (`vault/l402/l402-hmac.key`), never in the gateway SQLite; a credential
//!   signed under a different key is rejected.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";

import { generateLoopbackToken } from "../dist/http.js";
import { L402Gateway, bolt11PaymentHash, DEMO_ECHO_PATH, DEMO_MCP_PATH_PREFIX } from "../dist/l402.js";
import { L402Store } from "../dist/l402-store.js";
import { Vault } from "../dist/vault/vault.js";
import { InMemoryKeychainBackend } from "../dist/vault/keychain.js";
import { buildTestBolt11 } from "./fixtures/build-bolt11.mjs";

const REPO_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..", "..", "..");
const MAIN_JS = path.join(REPO_ROOT, "sidecar", "sovereign-wallet", "dist", "main.js");
const FAKE_PHOENIXD_CMD = path.join(REPO_ROOT, "sidecar", "sovereign-wallet", "test", "fixtures", "fake-phoenixd.cmd");
/** The fixture's Basic-auth password (RV-C1: the username is not validated). */
const FAKE_PHOENIXD_API_KEY = "fixture-phoenixd-api-key";

/** The deterministic proof pair: preimage "b"*64 and its sha256 payment hash. */
const PREIMAGE = "b".repeat(64);
const PAYMENT_HASH = createHash("sha256").update(Buffer.from(PREIMAGE, "hex")).digest("hex");
const PASSPHRASE = "correct horse battery staple";

/** An envelope-shaped error so the gateway's walletReady catch maps it. */
function envErr(code: string, message: string): Error {
  return Object.assign(new Error(message), {
    envelope: { code, message, details: "", retryable: false, remediation: "" },
  });
}

interface TestWallet {
  locked: boolean;
  mintInvoice: (amtSat: number, memo: string) => Promise<{ invoice: string; entryPaymentHash: string | null }>;
}

function makeWallet(): TestWallet {
  const wallet: TestWallet = {
    locked: false,
    mintInvoice: async () => ({ invoice: buildTestBolt11(PAYMENT_HASH), entryPaymentHash: PAYMENT_HASH }),
  };
  return wallet;
}

async function makeGateway(opts: {
  vault: Vault;
  store: L402Store;
  wallet?: TestWallet;
  nowMs?: () => number;
  network?: "signet" | "regtest" | "mainnet";
  mintInvoiceOverride?: () => Promise<{ invoice: string; entryPaymentHash: string | null }>;
}): Promise<L402Gateway> {
  const wallet = opts.wallet ?? makeWallet();
  return new L402Gateway({
    network: opts.network ?? "signet",
    store: opts.store,
    vault: opts.vault,
    walletReady: async () => {
      if (wallet.locked) throw envErr("WALLET_LOCKED", "the wallet is locked; run unlock");
    },
    mintInvoice: opts.mintInvoiceOverride ?? wallet.mintInvoice,
    nowMs: opts.nowMs ?? (() => Date.now()),
  });
}

async function makeVault(): Promise<{ vault: Vault; dir: string }> {
  const dir = mkdtempSync(path.join(tmpdir(), "sw-l402-vault-"));
  // OMEGA-DELTA-0301: tests inject the in-memory keychain seam — the real
  // OS-keychain binding is never touched by the test suites.
  const vault = new Vault({ vaultRoot: "vault", idleTimeoutMs: 3_600_000 }, dir, new InMemoryKeychainBackend());
  await vault.initialize(PASSPHRASE);
  return { vault, dir };
}

async function makeStore(): Promise<{ store: L402Store; dir: string }> {
  const dir = mkdtempSync(path.join(tmpdir(), "sw-l402-store-"));
  return { store: L402Store.open(dir), dir };
}

/** Issue a challenge through a gateway and return the parsed challenge. */
async function issueChallenge(
  gateway: L402Gateway,
  route = DEMO_ECHO_PATH,
  body = "",
): Promise<{ status: number; headers: Record<string, string>; body: Record<string, unknown> }> {
  const result = await gateway.handleRequest("POST", route, {}, body);
  assert.ok(result, "the echo route must be a gateway route");
  return {
    status: result.status,
    headers: result.headers,
    body: result.body as Record<string, unknown>,
  };
}

/** Redeem with the X-OpenAgents-L402 proof header. */
function redeem(
  gateway: L402Gateway,
  route: string,
  macaroon: string,
  preimage: string,
  extraHeaders: Record<string, string | string[] | undefined> = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
  return gateway
    .handleRequest("POST", route, { "x-openagents-l402": `${macaroon}:${preimage}`, ...extraHeaders }, "")
    .then((result) => {
      assert.ok(result, "route must be a gateway route");
      return { status: result.status, body: result.body as Record<string, unknown> };
    });
}

// ---------------------------------------------------------------------------
// BOLT11 payment-hash parsing (SEC-2026-055)
// ---------------------------------------------------------------------------

describe("bolt11 payment-hash parsing (SEC-2026-055)", () => {
  it("parses the `p` field from a signet invoice with a digit-containing hrp", () => {
    const invoice = buildTestBolt11(PAYMENT_HASH);
    assert.ok(invoice.startsWith("lntbs100u1"), "hrp with digits must be handled: " + invoice.slice(0, 16));
    assert.equal(bolt11PaymentHash(invoice), PAYMENT_HASH);
  });

  it("matches the BOLT-11 spec examples (no-amount and amount-10m)", () => {
    const specNoAmount =
      "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
    const spec10m =
      "lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc";
    // Spec-verified payment hash for both examples.
    const specHash = "0001020304050607080900010203040506070809000102030405060708090102";
    assert.equal(bolt11PaymentHash(specNoAmount), specHash);
    assert.equal(bolt11PaymentHash(spec10m), specHash);
  });

  it("returns null for malformed or non-BOLT11 strings", () => {
    assert.equal(bolt11PaymentHash("lntbs10u1p0example"), null); // not real bech32 data
    assert.equal(bolt11PaymentHash("not-an-invoice"), null);
    assert.equal(bolt11PaymentHash(""), null);
  });
});

// ---------------------------------------------------------------------------
// Gateway unit: issuance, one-shot, locked, mainnet, crash-window, custody
// ---------------------------------------------------------------------------

describe("L-402 gateway unit", () => {
  it("issues a standard L402 challenge (402 + WWW-Authenticate + JSON body)", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({ vault, store });
      const challenge = await issueChallenge(gateway);
      assert.equal(challenge.status, 402);
      assert.match(
        challenge.headers["www-authenticate"] ?? "",
        /^L402 macaroon="v1\..+", invoice="lntbs/,
      );
      const body = challenge.body;
      assert.equal((body.error as { code: string }).code, "payment_required");
      assert.equal(typeof body.challengeId, "string");
      assert.equal(typeof body.macaroon, "string");
      assert.match(String(body.invoice), /^lntbs/);
      // SEC-2026-055: the paymentHash is the minted invoice's `p` field.
      assert.equal(body.paymentHash, PAYMENT_HASH);
      assert.equal(body.amountSats, 1);
      assert.ok(typeof body.expiresAt === "number" && body.expiresAt > 0);
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("SEC-2026-055: a client-supplied paymentHash is ignored (never accepted)", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({ vault, store });
      // The challenge route takes no paymentHash input; the returned hash is
      // always the minted invoice's `p` field (server-derived).
      const result = await gateway.handleRequest("POST", DEMO_ECHO_PATH, {}, JSON.stringify({ paymentHash: "f".repeat(64) }));
      assert.ok(result);
      assert.equal((result.body as { paymentHash: string }).paymentHash, PAYMENT_HASH);
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("pay -> proof -> protected response; double redemption refused; mismatch refused", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({ vault, store });
      const challenge = await issueChallenge(gateway);
      const macaroon = challenge.body.macaroon as string;

      // Proof with the CORRECT preimage: 200 + protected response.
      const ok = await redeem(gateway, DEMO_ECHO_PATH, macaroon, PREIMAGE);
      assert.equal(ok.status, 200);
      assert.equal((ok.body as { ok: boolean }).ok, true);

      // Double redemption: 401 credential_consumed.
      const again = await redeem(gateway, DEMO_ECHO_PATH, macaroon, PREIMAGE);
      assert.equal(again.status, 401);
      assert.equal((again.body.error as { code: string }).code, "credential_consumed");

      // Payment-hash mismatch: a different preimage is refused.
      const wrong = await redeem(gateway, DEMO_ECHO_PATH, macaroon, "c".repeat(64));
      assert.equal(wrong.status, 401);
      assert.equal((wrong.body.error as { code: string }).code, "invalid_payment_proof");
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resource mismatch: an echo challenge cannot redeem the MCP tool route", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({ vault, store });
      const challenge = await issueChallenge(gateway, DEMO_ECHO_PATH);
      const macaroon = challenge.body.macaroon as string;
      const crossed = await redeem(gateway, `${DEMO_MCP_PATH_PREFIX}srv/tool`, macaroon, PREIMAGE);
      assert.equal(crossed.status, 403);
      assert.equal((crossed.body.error as { code: string }).code, "resource_mismatch");
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("SEC-2026-054: locked-wallet mint fails closed (wallet_locked); redemption stays honored", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const wallet = makeWallet();
      const gateway = await makeGateway({ vault, store, wallet });
      const challenge = await issueChallenge(gateway);
      const macaroon = challenge.body.macaroon as string;

      // Lock the wallet; minting now fails with the stable named error.
      wallet.locked = true;
      const lockedMint = await issueChallenge(gateway);
      assert.equal(lockedMint.status, 503);
      assert.equal((lockedMint.body.error as { code: string }).code, "wallet_locked");

      // Redemption of the already-issued challenge does NOT need the wallet.
      const ok = await redeem(gateway, DEMO_ECHO_PATH, macaroon, PREIMAGE);
      assert.equal(ok.status, 200, "redemption-while-locked must stay honored (SEC-2026-054)");
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("SEC-2026-044: the HMAC key is vaulted, never in the gateway SQLite; a different key rejects", async () => {
    const { vault, dir } = await makeVault();
    const { store, dir: storeDir } = await makeStore();
    try {
      const gateway = await makeGateway({ vault, store });
      const challenge = await issueChallenge(gateway);
      const macaroon = challenge.body.macaroon as string;

      // The key is a vault entry, not a gateway-DB value.
      const { readFileSync } = await import("node:fs");
      const sqliteBytes = readFileSync(path.join(storeDir, "l402", "l402-gateway.db"));
      const sqliteText = sqliteBytes.toString("latin1");
      assert.ok(!sqliteText.includes(macaroon), "the credential must never be stored in the gateway SQLite");
      assert.ok(!sqliteText.includes("l402-hmac"), "the HMAC key filename must never appear in the gateway SQLite");

      // A second gateway with a DIFFERENT vault key rejects the first's token.
      const { vault: otherVault, dir: otherDir } = await makeVault();
      const { store: otherStore } = await makeStore();
      try {
        const otherGateway = await makeGateway({ vault: otherVault, store: otherStore });
        const rejected = await redeem(otherGateway, DEMO_ECHO_PATH, macaroon, PREIMAGE);
        assert.equal(rejected.status, 401);
        assert.equal((rejected.body.error as { code: string }).code, "invalid_credential");
      } finally {
        otherVault.lock();
        otherStore.close();
        rmSync(otherDir, { recursive: true, force: true });
      }
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("SEC-2026-060: racing first-loads on a fresh data root all verify against the SAME key", async () => {
    // WP-10 (SEC-2026-060 fix): on a data root whose vault has never stored
    // the gateway key, concurrent first requests must share ONE key
    // generation + store. Before the fix, each racer generated its own key
    // and last-write-wins left earlier challenges signed under a key that
    // failed HMAC verification (`invalid_credential`). This test races eight
    // first challenge issuances on a FRESH data root and then redeems ALL of
    // them — every redemption must verify against the same key (200), and
    // the vault must hold exactly one stored key.
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    const N = 8;
    const preimages = Array.from({ length: N }, (_, i) => Buffer.alloc(32, i).toString("hex"));
    const hashToPreimage = new Map(
      preimages.map((preimage) => [
        createHash("sha256").update(Buffer.from(preimage, "hex")).digest("hex"),
        preimage,
      ]),
    );
    let mintCount = 0;
    try {
      const gateway = await makeGateway({
        vault,
        store,
        // Each minted invoice must carry a DISTINCT payment hash so every
        // challenge row is unique (payment_hash is UNIQUE in the store).
        mintInvoiceOverride: async () => {
          const preimage = preimages[mintCount % N]!;
          mintCount += 1;
          const hash = createHash("sha256").update(Buffer.from(preimage, "hex")).digest("hex");
          return { invoice: buildTestBolt11(hash), entryPaymentHash: hash };
        },
      });

      // Fire all first-loads concurrently — the race window is exactly the
      // first `#ensureKey` before any of them resolves.
      const results = await Promise.all(
        Array.from({ length: N }, () => gateway.handleRequest("POST", DEMO_ECHO_PATH, {}, "")),
      );
      const challenges = results.map((result, i) => {
        assert.ok(result, `challenge ${i} must be a gateway route`);
        assert.equal(result.status, 402, `challenge ${i} must be issued: ${JSON.stringify(result.body)}`);
        return result.body as Record<string, unknown>;
      });

      // Redeem every challenge with ITS OWN preimage. Under the pre-fix
      // race, challenges signed under a key that lost the last-write-wins
      // race fail here with 401 invalid_credential; under the fix all eight
      // verify against the single shared key.
      const redemptions = await Promise.all(
        challenges.map((challenge, i) => {
          const paymentHash = challenge.paymentHash as string;
          const preimage = hashToPreimage.get(paymentHash)!;
          return redeem(gateway, DEMO_ECHO_PATH, challenge.macaroon as string, preimage).then(
            (result) => ({ index: i, result }),
          );
        }),
      );
      for (const { index, result } of redemptions) {
        assert.equal(
          result.status,
          200,
          `redemption ${index} must verify against the shared key: ${JSON.stringify(result.body)}`,
        );
      }

      // The vault must hold exactly ONE stored key (the fix generates once).
      const stored = await vault.getL402Key();
      assert.ok(stored.length === 32, "the stored key is 32 bytes");
      assert.equal(mintCount, N, "every challenge minted exactly one invoice");
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("SEC-2026-060: a locked-vault null load is not memoized — after unlock the gateway recovers", async () => {
    // The fix resets the memoized load promise when the load returns null
    // (vault locked): a later unlock must retry the load instead of serving
    // the stale null forever. This is the SEC-2026-054-compatible lifecycle.
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({ vault, store });
      // Lock the vault BEFORE the first load.
      vault.lock();
      const locked = await issueChallenge(gateway);
      assert.equal(locked.status, 503);
      assert.equal((locked.body.error as { code: string }).code, "gateway_locked");
      // Unlock and mint again: the memo must NOT have cached the null.
      await vault.unlock(PASSPHRASE);
      const challenge = await issueChallenge(gateway);
      assert.equal(challenge.status, 402, "after unlock the gateway must mint");
      const macaroon = challenge.body.macaroon as string;
      const paymentHash = challenge.body.paymentHash as string;
      const preimage = PREIMAGE; // the default wallet mints buildTestBolt11(PAYMENT_HASH)
      assert.equal(paymentHash, PAYMENT_HASH);
      const redeemed = await redeem(gateway, DEMO_ECHO_PATH, macaroon, preimage);
      assert.equal(redeemed.status, 200, "the post-unlock key must verify");
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("OMEGA-DELTA-0287: mainnet is refused on a signet-configured gateway — an lnbc invoice from the wallet never mints a challenge", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({
        vault,
        store,
        mintInvoiceOverride: async () => ({ invoice: "lnbc10u1p0example", entryPaymentHash: null }),
      });
      const result = await issueChallenge(gateway);
      assert.equal(result.status, 500);
      assert.equal((result.body.error as { code: string }).code, "mainnet_refused");
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("OMEGA-DELTA-0287: a mainnet-configured gateway mints an lnbc challenge and redeems it", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({
        vault,
        store,
        network: "mainnet",
        mintInvoiceOverride: async () => ({
          invoice: buildTestBolt11(PAYMENT_HASH, "lnbc100u"),
          entryPaymentHash: PAYMENT_HASH,
        }),
      });
      const challenge = await issueChallenge(gateway);
      assert.equal(challenge.status, 402);
      assert.match(challenge.headers["www-authenticate"] ?? "", /invoice="lnbc/);
      assert.match(String(challenge.body.invoice), /^lnbc/);
      assert.equal(challenge.body.paymentHash, PAYMENT_HASH);
      // Redemption is network-independent (unchanged; proof verification is a
      // gateway-HMAC property, not a network property).
      const macaroon = challenge.body.macaroon as string;
      const redeemed = await redeem(gateway, DEMO_ECHO_PATH, macaroon, PREIMAGE);
      assert.equal(redeemed.status, 200);
      assert.match(String((redeemed.body as { message: string }).message), /mainnet demo/);
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("OMEGA-DELTA-0287: a mainnet-configured gateway refuses a mismatched-HRP invoice from the wallet engine (configuration error)", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({
        vault,
        store,
        network: "mainnet",
        // The wallet engine mints a SIGNET invoice on the mainnet gateway.
        mintInvoiceOverride: async () => ({
          invoice: buildTestBolt11(PAYMENT_HASH, "lntbs100u"),
          entryPaymentHash: PAYMENT_HASH,
        }),
      });
      const result = await issueChallenge(gateway);
      assert.equal(result.status, 500);
      assert.equal((result.body.error as { code: string }).code, "configuration_error");
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("SEC-2026-048: deferred-settlement crash-window recovery — checked row settles exactly once after restart", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    const route = `${DEMO_MCP_PATH_PREFIX}srv/tool`;
    try {
      const gatewayA = await makeGateway({ vault, store });
      const challenge = await issueChallenge(gatewayA, route);
      const macaroon = challenge.body.macaroon as string;
      const requestId = createHash("sha256").update(`${sha256Hex(macaroon)}:${PREIMAGE}`).digest("hex").slice(0, 40);

      // Simulate the crash window: the handler ran (checked row inserted) but
      // the sidecar died BEFORE the settle was persisted.
      store.insertCheckedRedemption(String(challenge.body.challengeId), "paid:tool:srv:tool", requestId, Date.now());
      // Destroy the first gateway WITHOUT settling (crash).
      gatewayA.shutdown();

      // Restart: a NEW gateway over the SAME SQLite (and vault — the key is
      // re-loaded from the vault entry) re-executes the idempotent handler
      // and settles the SAME checked row.
      const gatewayB = await makeGateway({ vault, store });
      const recovered = await redeem(gatewayB, route, macaroon, PREIMAGE);
      assert.equal(recovered.status, 200, "the retry after restart must succeed");
      assert.equal(store.hasSettledRedemption(String(challenge.body.challengeId)), true);
      assert.equal(
        store.getCheckedRedemption(String(challenge.body.challengeId)),
        null,
        "the checked row must now be settled — exactly one redemption state",
      );
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("concurrency: parallel redemptions of the same challenge — exactly one winner", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    try {
      const gateway = await makeGateway({ vault, store });
      const challenge = await issueChallenge(gateway);
      const macaroon = challenge.body.macaroon as string;
      const results = await Promise.all([
        redeem(gateway, DEMO_ECHO_PATH, macaroon, PREIMAGE),
        redeem(gateway, DEMO_ECHO_PATH, macaroon, PREIMAGE),
        redeem(gateway, DEMO_ECHO_PATH, macaroon, PREIMAGE),
      ]);
      const winners = results.filter((result) => result.status === 200);
      const consumed = results.filter(
        (result) => result.status === 401 && (result.body.error as { code: string }).code === "credential_consumed",
      );
      assert.equal(winners.length, 1, "exactly one redemption wins: " + JSON.stringify(results.map((r) => r.status)));
      assert.equal(consumed.length, 2);
      assert.equal(store.hasSettledRedemption(String(challenge.body.challengeId)), true);
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("deferred MCP-tool lane: paid tool redemption returns the protected tool result", async () => {
    const { vault, dir } = await makeVault();
    const { store } = await makeStore();
    const route = `${DEMO_MCP_PATH_PREFIX}my-server/my-tool`;
    try {
      const gateway = await makeGateway({ vault, store });
      const challenge = await issueChallenge(gateway, route);
      assert.equal(challenge.status, 402);
      const macaroon = challenge.body.macaroon as string;
      const ok = await redeem(gateway, route, macaroon, PREIMAGE);
      assert.equal(ok.status, 200);
      const body = ok.body as { tool: string; result: { content: Array<{ text: string }> } };
      assert.equal(body.tool, "my-server:my-tool");
      assert.equal(body.result.content[0]?.text, "paid tool my-server:my-tool completed");
      // The deferred settle is single-winner too.
      const again = await redeem(gateway, route, macaroon, PREIMAGE);
      assert.equal(again.status, 401);
    } finally {
      vault.lock();
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// End-to-end over the real loopback HTTP surface (real sidecar + fake
// phoenixd node; OMEGA-DELTA-0303 — the sidecar is client-only, so the test
// harness owns the fake node's lifecycle)
// ---------------------------------------------------------------------------

interface Sidecar {
  child: ChildProcess;
  token: string;
  /** The fake phoenixd child (owned by the test harness; killed on close). */
  fakeNode: ChildProcess;
  request(method: string, params?: Record<string, unknown>, generation?: number): Promise<Record<string, unknown>>;
  close(): Promise<number | null>;
  stderrText(): string;
}

let portCounter = 13100;

function nextPort(): number {
  portCounter += 1;
  return 12_000 + ((portCounter * 7919) % 30_000);
}

/** Start the fake phoenixd node and wait for its "listening" line. */
async function startFakePhoenixd(port: number, overrides: Record<string, string>): Promise<ChildProcess> {
  const fakeNode = spawn(FAKE_PHOENIXD_CMD, [], {
    env: {
      FAKE_PHOENIXD_PORT: String(port),
      FAKE_PHOENIXD_API_KEY: FAKE_PHOENIXD_API_KEY,
      FAKE_PHOENIXD_CHAIN: overrides.FAKE_PHOENIXD_CHAIN ?? "signet",
      FAKE_PHOENIXD_MODE: overrides.FAKE_PHOENIXD_MODE ?? "normal",
      FAKE_PHOENIXD_INVOICE_HRP: overrides.FAKE_PHOENIXD_INVOICE_HRP ?? "lntbs100u",
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  fakeNode.stdout?.setEncoding("utf8");
  fakeNode.stderr?.setEncoding("utf8");
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("fake-phoenixd did not listen in time")), 10_000);
    const onData = (chunk: string): void => {
      if (chunk.includes("listening")) {
        clearTimeout(timer);
        fakeNode.stdout?.removeListener("data", onData);
        resolve();
      }
    };
    fakeNode.stdout?.on("data", onData);
    fakeNode.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`fake-phoenixd exited early with code ${code}`));
    });
  });
  return fakeNode;
}

async function spawnSidecar(overrides: Record<string, string>): Promise<Sidecar> {
  const dataRoot = mkdtempSync(path.join(tmpdir(), "sw-l402-"));
  const port = nextPort();
  const token = generateLoopbackToken();
  // OMEGA-DELTA-0303: the fake phoenixd node is spawned by the TEST (the
  // sidecar is client-only and never spawns a node child).
  const fakeNode = await startFakePhoenixd(port, overrides);
  const env: Record<string, string> = {
    OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
    OMEGA_SOVEREIGN_WALLET_NETWORK: "signet",
    OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN: token,
    OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL: `http://127.0.0.1:${port}`,
    OMEGA_SOVEREIGN_WALLET_PHOENIXD_API_KEY: FAKE_PHOENIXD_API_KEY,
    // OMEGA-DELTA-0301 (RV6-REQ-1): the TEST-ONLY in-memory keychain seam —
    // e2e processes must never touch the real OS keychain. Production never
    // sets this; the default is the OS-keychain binding.
    OMEGA_SOVEREIGN_WALLET_VAULT_KEYCHAIN: "memory",
    ...overrides,
  };
  const child = spawn(process.execPath, [MAIN_JS], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });

  let stdoutBuffer = "";
  let stderrBuffer = "";
  const pending: Array<{
    resolve: (value: Record<string, unknown>) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];

  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    stdoutBuffer += chunk;
    let newline: number;
    while ((newline = stdoutBuffer.indexOf("\n")) !== -1) {
      const line = stdoutBuffer.slice(0, newline);
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      if (line.trim().length === 0) continue;
      const waiter = pending.shift();
      if (waiter) {
        clearTimeout(waiter.timer);
        try {
          waiter.resolve(JSON.parse(line) as Record<string, unknown>);
        } catch (error) {
          waiter.reject(error instanceof Error ? error : new Error(String(error)));
        }
      }
    }
  });
  child.stderr?.on("data", (chunk: string) => {
    stderrBuffer += chunk;
  });

  let requestId = 0;
  const request = (
    method: string,
    params?: Record<string, unknown>,
    generation = 1,
  ): Promise<Record<string, unknown>> =>
    new Promise((resolve, reject) => {
      const id = String(++requestId);
      const frame = { schema: "openagents.omega.sovereign-wallet.v1", kind: "request", id, generation, method, params: params ?? {} };
      const timer = setTimeout(() => reject(new Error(`request ${method} timed out`)), 20_000);
      pending.push({ resolve, reject, timer });
      child.stdin?.write(`${JSON.stringify(frame)}\n`);
    });

  const close = async (): Promise<number | null> => {
    killTree(child.pid);
    killTree(fakeNode.pid);
    if (!child.pid) child.kill();
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null) {
        resolve();
        return;
      }
      const timer = setTimeout(resolve, 3_000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        rmSync(dataRoot, { recursive: true, force: true });
        break;
      } catch {
        await sleep(300);
      }
    }
    return child.exitCode;
  };

  return { child, token, fakeNode, request, close, stderrText: () => stderrBuffer };
}

function expectOk(response: Record<string, unknown>): Record<string, unknown> {
  assert.equal(response.ok, true, `expected ok response, got: ${JSON.stringify(response)}`);
  return response.result as Record<string, unknown>;
}

function expectError(response: Record<string, unknown>): { code: string; message: string } {
  assert.equal(response.ok, false, `expected error response, got: ${JSON.stringify(response)}`);
  const error = response.error as { code: string; message: string };
  return error;
}

function killTree(pid: number | undefined): void {
  if (!pid) return;
  try {
    execFileSync("taskkill", ["/PID", String(pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
  } catch {
    // already gone
  }
}

async function waitForExit(child: ChildProcess, ms = 10_000): Promise<number | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(child.exitCode), ms);
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

/**
 * Bring a fresh sidecar to the operator-ready state: identity ceremony (vault
 * unlocked — required for the gateway HMAC key, SEC-2026-044). The node rail
 * is client-only (OMEGA-DELTA-0303): the fake phoenixd answers the startup
 * probe, so the node-ready gate (the gateway's walletReady dep) passes; the
 * waved create-wallet/unlock ceremony is removed with the rail. Returns the
 * sidecar plus the data-root path for restart tests. `overrides` are extra
 * env vars for the spawned sidecar (e.g. OMEGA_SPEND_KILL for the 0300
 * kill-closure test).
 */
async function readySidecar(overrides: Record<string, string> = {}): Promise<{ sidecar: Sidecar; dataRoot: string }> {
  const sidecar = await spawnSidecar(overrides);
  await sidecar.request("initialize");
  const prepared = expectOk(await sidecar.request("vault-init-prepare"));
  const words = (prepared.mnemonic as string).split(" ");
  await sidecar.request("vault-init", {
    passphrase: PASSPHRASE,
    answers: { 2: words[1], 7: words[6], 11: words[10] },
  });
  const dataRoot = (expectOk(await sidecar.request("status")).dataRoot as string) ?? "";
  return { sidecar, dataRoot };
}

async function httpPort(sidecar: Sidecar): Promise<number> {
  const initialize = expectOk(await sidecar.request("initialize"));
  return (initialize.httpSurface as { bound: boolean; port: number }).port;
}

/** Pay a challenge invoice through the stdio pay-invoice (the mandate-gated Rust path's sidecar half). */
async function payInvoice(sidecar: Sidecar, invoice: string): Promise<string> {
  const paid = expectOk(
    await sidecar.request("pay-invoice", { invoice, idempotencyKey: `l402-pay-${Date.now()}-${Math.random().toString(36).slice(2)}` }),
  );
  assert.equal(typeof paid.preimage, "string", "a fresh pay returns the preimage");
  return paid.preimage as string;
}

describe("L-402 gateway end-to-end over the loopback HTTP surface", () => {
  it("402 -> pay -> proof -> protected response on signet; double redemption refused", async () => {
    const { sidecar } = await readySidecar();
    try {
      const port = await httpPort(sidecar);
      const base = `http://127.0.0.1:${port}`;
      const headers = { authorization: `Bearer ${sidecar.token}` };

      // 1. No proof -> HTTP 402 + WWW-Authenticate: L402 + challenge JSON.
      const first = await fetch(`${base}${DEMO_ECHO_PATH}`, { method: "POST", headers, body: "{}" });
      assert.equal(first.status, 402);
      const www = first.headers.get("www-authenticate") ?? "";
      assert.match(www, /^L402 macaroon="v1\..+", invoice="lntbs/);
      const challenge = (await first.json()) as {
        error: { code: string };
        challengeId: string;
        macaroon: string;
        invoice: string;
        paymentHash: string;
        amountSats: number;
      };
      assert.equal(challenge.error.code, "payment_required");
      assert.equal(challenge.amountSats, 1);
      assert.equal(challenge.paymentHash, PAYMENT_HASH, "payment hash must equal the minted invoice's p field");
      assert.match(challenge.invoice, /^lntbs/);

      // 2. Pay through the sidecar wallet (the mandate-gated Rust path's
      //    sidecar half; the mandate gate itself is Rust-side — see
      //    crates/sovereign_wallet/src/l402.rs tests).
      const preimage = await payInvoice(sidecar, challenge.invoice);

      // 3. Retry with the proof -> protected response.
      const retry = await fetch(`${base}${DEMO_ECHO_PATH}`, {
        method: "POST",
        headers: { ...headers, "x-openagents-l402": `${challenge.macaroon}:${preimage}` },
        body: "{}",
      });
      assert.equal(retry.status, 200);
      const protectedBody = (await retry.json()) as { ok: boolean; echo: { protectedRef: string } };
      assert.equal(protectedBody.ok, true);
      assert.equal(protectedBody.echo.protectedRef, "paid:echo");

      // 4. Double redemption refused.
      const again = await fetch(`${base}${DEMO_ECHO_PATH}`, {
        method: "POST",
        headers: { ...headers, "x-openagents-l402": `${challenge.macaroon}:${preimage}` },
        body: "{}",
      });
      assert.equal(again.status, 401);
      const againBody = (await again.json()) as { error: { code: string } };
      assert.equal(againBody.error.code, "credential_consumed");

      // 5. Payment-hash mismatch refused (wrong preimage).
      const wrongProof = await fetch(`${base}${DEMO_ECHO_PATH}`, {
        method: "POST",
        headers: { ...headers, "x-openagents-l402": `${challenge.macaroon}:${"c".repeat(64)}` },
        body: "{}",
      });
      assert.equal(wrongProof.status, 401);
      const wrongBody = (await wrongProof.json()) as { error: { code: string } };
      assert.equal(wrongBody.error.code, "invalid_payment_proof");
    } finally {
      await sidecar.close();
    }
  });

  it("OMEGA-DELTA-0303: node unreachable -> the mint fails with a stable named error; redemption stays honored", async () => {
    const { sidecar } = await readySidecar();
    try {
      const port = await httpPort(sidecar);
      const base = `http://127.0.0.1:${port}`;
      const headers = { authorization: `Bearer ${sidecar.token}` };

      const challenge = (await (await fetch(`${base}${DEMO_ECHO_PATH}`, { method: "POST", headers, body: "{}" })).json()) as {
        macaroon: string;
        invoice: string;
      };
      const preimage = await payInvoice(sidecar, challenge.invoice);

      // Take the fake phoenixd node down: the sidecar's make path fails
      // closed (the createinvoice fetch throws INTERNAL node-unreachable;
      // the gateway maps the mint failure to the stable named error — the
      // "wallet_locked" label is the gateway's pre-0303 mapping, recorded as
      // a C5 honesty-label item in the WP-C3 evidence).
      killTree(sidecar.fakeNode.pid);
      await sleep(300);

      const lockedMint = await fetch(`${base}${DEMO_ECHO_PATH}`, { method: "POST", headers, body: "{}" });
      assert.equal(lockedMint.status, 502);
      const lockedBody = (await lockedMint.json()) as { error: { code: string } };
      assert.equal(lockedBody.error.code, "invoice_mint_failed");

      // Redemption of the already-paid challenge stays honored (the proof is
      // a gateway-HMAC property, not a node property — SEC-2026-054).
      const retry = await fetch(`${base}${DEMO_ECHO_PATH}`, {
        method: "POST",
        headers: { ...headers, "x-openagents-l402": `${challenge.macaroon}:${preimage}` },
        body: "{}",
      });
      assert.equal(retry.status, 200, "redemption must stay honored when the node is unreachable");
    } finally {
      await sidecar.close();
    }
  });

  it("OMEGA-DELTA-0300 (kill closure): OMEGA_SPEND_KILL=1 refuses the gateway mint with the stable spend_halted error; un-killed mints", async () => {
    // Killed: the sidecar is spawned with the kill set; the gateway mint
    // path reads the kill itself (it does not traverse the Rust choke
    // point) and refuses BEFORE contacting waved.
    const killed = await readySidecar({ OMEGA_SPEND_KILL: "1" });
    try {
      const port = await httpPort(killed.sidecar);
      const base = `http://127.0.0.1:${port}`;
      const headers = { authorization: `Bearer ${killed.sidecar.token}` };
      const killedMint = await fetch(`${base}${DEMO_ECHO_PATH}`, { method: "POST", headers, body: "{}" });
      assert.equal(killedMint.status, 503);
      const killedBody = (await killedMint.json()) as { error: { code: string; message: string } };
      assert.equal(killedBody.error.code, "spend_halted");
      assert.match(killedBody.error.message, /OMEGA_SPEND_KILL=1/);
      assert.match(killedBody.error.message, /OMEGA-DELTA-0300/);
    } finally {
      await killed.sidecar.close();
    }

    // Un-killed control: the identical mint path proceeds per the existing
    // fixtures — the kill env is the only difference between the two spawns.
    const live = await readySidecar();
    try {
      const port = await httpPort(live.sidecar);
      const base = `http://127.0.0.1:${port}`;
      const headers = { authorization: `Bearer ${live.sidecar.token}` };
      const challenge = await fetch(`${base}${DEMO_ECHO_PATH}`, { method: "POST", headers, body: "{}" });
      assert.equal(challenge.status, 402);
      const body = (await challenge.json()) as { error: { code: string }; invoice: string };
      assert.equal(body.error.code, "payment_required");
      assert.match(body.invoice, /^lntbs/);
    } finally {
      await live.sidecar.close();
    }
  });

  it("restart idempotency: challenge state survives a sidecar restart and redeems", async () => {
    const { sidecar, dataRoot } = await readySidecar();
    let macaroon = "";
    let invoice = "";
    try {
      const port = await httpPort(sidecar);
      const base = `http://127.0.0.1:${port}`;
      const headers = { authorization: `Bearer ${sidecar.token}` };

      const challenge = (await (await fetch(`${base}${DEMO_ECHO_PATH}`, { method: "POST", headers, body: "{}" })).json()) as {
        macaroon: string;
        invoice: string;
      };
      macaroon = challenge.macaroon;
      invoice = challenge.invoice;
      const preimage = await payInvoice(sidecar, invoice);

      // Crash: kill the sidecar WITHOUT redeeming.
      killTree(sidecar.child.pid);
      await sleep(500);

      // Restart on the SAME data root: the gateway DB + vault survived.
      // OMEGA-DELTA-0301 (updated-with-citation): the in-memory keychain seam
      // is per-process, so the restarted process honestly models a device
      // whose OS keychain is unavailable — the unlock uses the DEGRADED path
      // (explicit opt-in OMEGA_VAULT_ALLOW_PASSPHRASE_FALLBACK=1) and reports
      // wrapMethod "passphrase-fallback" (RV6-REQ-5).
      const restarted = await spawnSidecar({
        OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
        OMEGA_VAULT_ALLOW_PASSPHRASE_FALLBACK: "1",
      });
      try {
        await restarted.request("initialize");
        // The normal operator flow after restart: unlock the vault (the
        // gateway's HMAC key is re-loaded from the vault entry). The node
        // rail is client-only — no wallet unlock step exists on the phoenixd
        // rail (OMEGA-DELTA-0303).
        const vaultUnlock = expectOk(await restarted.request("vault-unlock", { passphrase: PASSPHRASE }));
        assert.equal(vaultUnlock.wrapMethod, "passphrase-fallback", "restart unlock uses the degraded path (RV6-REQ-5)");
        const port2 = await httpPort(restarted);
        const base2 = `http://127.0.0.1:${port2}`;
        const headers2 = { authorization: `Bearer ${restarted.token}` };

        // The pre-restart challenge redeems (state persisted in SQLite).
        const retry = await fetch(`${base2}${DEMO_ECHO_PATH}`, {
          method: "POST",
          headers: { ...headers2, "x-openagents-l402": `${macaroon}:${preimage}` },
          body: "{}",
        });
        assert.equal(retry.status, 200, "a pre-restart challenge must redeem after restart (idempotent state)");
        const again = await fetch(`${base2}${DEMO_ECHO_PATH}`, {
          method: "POST",
          headers: { ...headers2, "x-openagents-l402": `${macaroon}:${preimage}` },
          body: "{}",
        });
        assert.equal(again.status, 401, "one-shot redemption survives restart (no double-spend)");
      } finally {
        await restarted.close();
      }
    } finally {
      await sidecar.close();
    }
  });

  it("concurrency: two parallel redemptions -> exactly one 200, one 401", async () => {
    const { sidecar } = await readySidecar();
    try {
      const port = await httpPort(sidecar);
      const base = `http://127.0.0.1:${port}`;
      const headers = { authorization: `Bearer ${sidecar.token}` };
      const challenge = (await (await fetch(`${base}${DEMO_ECHO_PATH}`, { method: "POST", headers, body: "{}" })).json()) as {
        macaroon: string;
        invoice: string;
      };
      const preimage = await payInvoice(sidecar, challenge.invoice);

      const attempts = await Promise.all(
        [0, 1].map(() =>
          fetch(`${base}${DEMO_ECHO_PATH}`, {
            method: "POST",
            headers: { ...headers, "x-openagents-l402": `${challenge.macaroon}:${preimage}` },
            body: "{}",
          }),
        ),
      );
      const statuses = attempts.map((response) => response.status).sort();
      assert.deepEqual(statuses, [200, 401], "exactly one redemption wins: " + JSON.stringify(statuses));
    } finally {
      await sidecar.close();
    }
  });

  it("gateway state is reported honestly in status.l402_gateway_state", async () => {
    const sidecar = await spawnSidecar({});
    try {
      const status = expectOk(await sidecar.request("status"));
      // Fresh data root: vault absent -> the gateway key is unavailable (locked).
      assert.equal(status.l402GatewayState, "locked");
      // After the identity ceremony (vault unlocked) the gateway is ready.
      await sidecar.request("initialize");
      const prepared = expectOk(await sidecar.request("vault-init-prepare"));
      const words = (prepared.mnemonic as string).split(" ");
      await sidecar.request("vault-init", {
        passphrase: PASSPHRASE,
        answers: { 2: words[1], 7: words[6], 11: words[10] },
      });
      const ready = expectOk(await sidecar.request("status"));
      assert.equal(ready.l402GatewayState, "ready");
    } finally {
      await sidecar.close();
    }
  });

  it("mcp-identity-map get/set round-trip (design §6.4 dashboard wiring)", async () => {
    const sidecar = await spawnSidecar({});
    try {
      await sidecar.request("initialize");
      const empty = expectOk(await sidecar.request("mcp-identity-map-get"));
      assert.deepEqual(empty.entries, {});

      const pubkey = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
      const set = expectOk(await sidecar.request("mcp-identity-map-set", { serverId: "om", principalPubkey: pubkey }));
      assert.equal(set.updated, true);
      const got = expectOk(await sidecar.request("mcp-identity-map-get"));
      assert.deepEqual(got.entries, { om: pubkey });

      // Invalid principal refused; unset (null) clears the mapping.
      const bad = expectError(await sidecar.request("mcp-identity-map-set", { serverId: "x", principalPubkey: "not-hex" }));
      assert.equal(bad.code, "INVALID_ARGS");
      expectOk(await sidecar.request("mcp-identity-map-set", { serverId: "om", principalPubkey: null }));
      const cleared = expectOk(await sidecar.request("mcp-identity-map-get"));
      assert.deepEqual(cleared.entries, {});
    } finally {
      await sidecar.close();
    }
  });
});

// The sidecar's loopback token is generated per test and returned by
// `spawnSidecar` (SEC-2026-053: per-launch, process-pair-only).

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}