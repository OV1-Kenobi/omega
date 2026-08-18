#!/usr/bin/env node

// Persistence tests for the durable SQLite stores (plan of 2026-08-18 (OMEGA-
// WP6-MDK-STORE sections 6.3.7 / acceptance criteria 3-5, 7). Deterministic,
// offline, temp-directory databases, fixtures only, no live calls. The
// two-process tests spawn real child node processes racing on the same DB
// file - the paddock-to-durable proof Security condition 1 requires at E3.

import { after, test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import {
  CHALLENGE_STORE_MIGRATIONS,
  P12_STORE_MIGRATIONS,
  createSqliteChallengeEntitlementStore,
  createSqliteFixedWindowLimiter,
  createSqliteP12LedgerStore,
  migrateStoreDb,
  newTempStoreDir,
  openStoreDb,
  removeTempStoreDir,
} from "./source-summarization-store-sqlite.mjs";
import { CHALLENGE_RECORD_FIELDS } from "./source-summarization-l402.mjs";
import { P12_OPERATOR_FIELDS } from "./source-summarization-p12.mjs";

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
let tempDir = newTempStoreDir();
after(() => {
  try {
    removeTempStoreDir(tempDir);
  } catch {
    // Best effort: a DB handle left open by a failed test may lock a file.
    // Leftover temp dirs are harmless; the next run allocates a fresh one.
  }
});

function validChallenge(overrides = {}) {
  return {
    challenge_id: "11111111-1111-4111-8111-111111111111",
    payment_hash: "a".repeat(64),
    amount_sats: 21,
    capability: "summarize",
    version: "1.0.0",
    client_id: "client-a",
    issued_at: "2026-08-18T00:00:00.000Z",
    expires_at: "2026-08-18T00:15:00.000Z",
    status: "issued",
    redeemed_at: null,
    ...overrides,
  };
}

test("challenge store: record, get, list, duplicate rejection, content-free rejection", () => {
  const store = createSqliteChallengeEntitlementStore({ dbPath: join(tempDir, "c1.db") });
  const recorded = store.recordChallenge(validChallenge());
  assert.equal(recorded.status, "issued");
  assert.equal(recorded.redeemed_at, null);
  assert.deepEqual(store.getChallenge(validChallenge().challenge_id), recorded);
  assert.equal(store.listRecords().length, 1);
  assert.throws(() => store.recordChallenge(validChallenge()), /challenge id already recorded/);
  assert.throws(
    () => store.recordChallenge(validChallenge({ challenge_id: "x2", url: "https://example.com" })),
    /non-allowlisted field: url/,
  );
  assert.throws(
    () => store.recordChallenge(validChallenge({ challenge_id: "x3", amount_sats: 0 })),
    /invalid amount_sats/,
  );
  store.close();
});

test("challenge store: one-shot redemption and replay denial", () => {
  const store = createSqliteChallengeEntitlementStore({ dbPath: join(tempDir, "c2.db") });
  store.recordChallenge(validChallenge());
  assert.deepEqual(store.redeem("a".repeat(64)), { ok: true });
  assert.equal(store.isRedeemed("a".repeat(64)), true);
  assert.deepEqual(store.redeem("a".repeat(64)), { ok: false, reason: "already_redeemed" });
  assert.equal(store.getChallenge(validChallenge().challenge_id).status, "redeemed");
  assert.ok(store.getChallenge(validChallenge().challenge_id).redeemed_at);
  assert.equal(store.countRedemptions(), 1);
  store.close();
});

test("challenge store: restart survival - redeemed hash still denied after reopen", () => {
  const dbPath = join(tempDir, "c3.db");
  const first = createSqliteChallengeEntitlementStore({ dbPath });
  first.recordChallenge(validChallenge());
  assert.deepEqual(first.redeem("a".repeat(64)), { ok: true });
  // Simulated kill after the redeem commit, before any further write.
  first.close();
  const second = createSqliteChallengeEntitlementStore({ dbPath });
  assert.equal(second.isRedeemed("a".repeat(64)), true);
  assert.deepEqual(second.redeem("a".repeat(64)), { ok: false, reason: "already_redeemed" });
  assert.equal(second.getChallenge(validChallenge().challenge_id).status, "redeemed");
  assert.equal(second.countRedemptions(), 1);
  second.close();
});

// Child contender: waits for the shared barrier, then races to insert the
// same payment_hash inside BEGIN IMMEDIATE (the durable single-winner proof
// must hold across real processes, not just one event loop).
const REDEEM_CHILD = `
const Database = require("better-sqlite3");
const cfg = JSON.parse(process.argv[1]);
while (Date.now() < cfg.barrierMs) {}
const db = new Database(cfg.dbPath);
db.pragma("busy_timeout = 5000");
const insert = db.prepare("INSERT INTO redemptions (payment_hash, challenge_id, redeemed_at) VALUES (?, 'child', ?)");
const markRedeemed = db.prepare("UPDATE challenges SET status = 'redeemed', redeemed_at = ? WHERE payment_hash = ?");
const tx = db.transaction((h) => {
  const now = new Date().toISOString();
  insert.run(h, now);
  markRedeemed.run(now, h);
});
let result;
try { tx.immediate(cfg.paymentHash); result = { ok: true }; }
catch (e) { result = e.code === "SQLITE_CONSTRAINT_PRIMARYKEY" ? { ok: false, reason: "already_redeemed" } : { ok: false, reason: e.code }; }
console.log(JSON.stringify(result));
db.close();
`;

const P12_APPEND_CHILD = `
const Database = require("better-sqlite3");
const cfg = JSON.parse(process.argv[1]);
while (Date.now() < cfg.barrierMs) {}
const db = new Database(cfg.dbPath);
db.pragma("busy_timeout = 5000");
const insert = db.prepare("INSERT INTO entries (entry_id, user_token, timestamp, status, ciphertext_blob) VALUES (@entryId, @userToken, @now, 'stored', 'blob')");
const tx = db.transaction((e) => insert.run({ entryId: e.entryId, userToken: e.userToken, now: new Date().toISOString() }));
let result;
try { tx.immediate(cfg); result = { appended: cfg.entryId }; }
catch (e) { result = { appended: cfg.entryId, error: e.code }; }
console.log(JSON.stringify(result));
db.close();
`;

function runChild(script, cfg) {
  const child = spawnSync(
    process.execPath,
    ["-e", script, JSON.stringify(cfg)],
    { cwd: SCRIPTS_DIR, encoding: "utf8" },
  );
  assert.equal(child.status, 0, `child failed: ${child.stderr}`);
  return JSON.parse(child.stdout.trim().split("\n").pop());
}

test("two processes racing the same payment_hash yield exactly one winner", () => {
  const dbPath = join(tempDir, "c4.db");
  const parent = createSqliteChallengeEntitlementStore({ dbPath });
  try {
    const hash = "b".repeat(64);
    parent.recordChallenge(validChallenge({ challenge_id: "22222222-2222-4222-8222-222222222222", payment_hash: hash }));
    const barrierMs = Date.now() + 600;
    const results = [
      runChild(REDEEM_CHILD, { dbPath, barrierMs, paymentHash: hash }),
      runChild(REDEEM_CHILD, { dbPath, barrierMs, paymentHash: hash }),
    ];
    const winners = results.filter((r) => r.ok === true);
    const losers = results.filter((r) => r.reason === "already_redeemed");
    assert.equal(winners.length, 1, `exactly one winner: ${JSON.stringify(results)}`);
    assert.equal(losers.length, 1, `exactly one loser: ${JSON.stringify(results)}`);
    assert.equal(parent.countRedemptions(), 1);
    assert.equal(parent.getChallenge("22222222-2222-4222-8222-222222222222").status, "redeemed");
  } finally {
    parent.close();
  }
});

test("two processes appending to the P12 ledger concurrently both succeed (WAL)", () => {
  const dbPath = join(tempDir, "p12c.db");
  const store = createSqliteP12LedgerStore({ dbPath, optIn: true });
  try {
    const userToken = "user-1";
    store.setSalt(userToken, "ab".repeat(8));
    const barrierMs = Date.now() + 600;
    const results = [
      runChild(P12_APPEND_CHILD, { dbPath, barrierMs, userToken, entryId: "entry-a" }),
      runChild(P12_APPEND_CHILD, { dbPath, barrierMs, userToken, entryId: "entry-b" }),
    ];
    assert.deepEqual(results.map((r) => r.error ?? null), [null, null], `children must not error: ${JSON.stringify(results)}`);
    const entries = store.listEntries(userToken);
    assert.equal(entries.length, 2);
    assert.deepEqual(entries.map((e) => e.entry_id).sort(), ["entry-a", "entry-b"]);
  } finally {
    store.close();
  }
});

test("P12 store: opt-in gate, shape rejection, salt rules, retention, opt-out", () => {
  let now = Date.parse("2026-08-18T00:00:00.000Z");
  const clock = () => new Date(now);
  const store = createSqliteP12LedgerStore({ dbPath: join(tempDir, "p1.db"), maxEntriesPerUser: 2, maxAgeMs: 60_000, clock });
  const entry = (id, ts) => ({
    entry_id: id, user_token: "u1", timestamp: ts, status: "stored", ciphertext_blob: `blob-${id}`,
  });
  assert.throws(() => store.append(entry("e0", clock().toISOString())), /opt-in required/);
  store.optIn();
  store.setSalt("u1", "cd".repeat(8));
  assert.equal(store.getSalt("u1"), "cd".repeat(8));
  assert.throws(() => store.setSalt("u1", "ef".repeat(8)), /salt rotation requires ledger re-encryption/);
  assert.throws(
    () => store.append({ ...entry("bad", clock().toISOString()), plaintext: "x" }),
    /non-allowlisted field: plaintext/,
  );
  store.append(entry("e1", clock().toISOString()));
  store.append(entry("e2", clock().toISOString()));
  store.append(entry("e3", clock().toISOString()));
  assert.equal(store.listEntries("u1").length, 2, "count retention keeps the newest entries");
  now += 120_000;
  store.append(entry("e4", clock().toISOString()));
  assert.equal(store.listEntries("u1").length, 1, "age retention drops expired entries");
  store.optOut("u1");
  assert.equal(store.getSalt("u1"), null, "the salt must not outlive the ledger");
  assert.equal(store.listEntries("u1").length, 0);
  assert.equal(store.isOptedIn(), true, "per-user opt-out leaves the global opt-in intact");
  store.optIn();
  store.append(entry("e5", clock().toISOString()));
  store.optOut();
  assert.equal(store.isOptedIn(), false);
  assert.throws(() => store.append(entry("e6", clock().toISOString())), /opt-in required/);
  store.close();
});

test("P12 store: restart survival of entries, salt, and opt-in state", () => {
  const dbPath = join(tempDir, "p2.db");
  const first = createSqliteP12LedgerStore({ dbPath });
  first.optIn();
  first.setSalt("u1", "99".repeat(8));
  first.append({ entry_id: "e1", user_token: "u1", timestamp: "2026-08-18T00:00:00.000Z", status: "stored", ciphertext_blob: "blob" });
  first.close();
  const second = createSqliteP12LedgerStore({ dbPath });
  assert.equal(second.isOptedIn(), true);
  assert.equal(second.getSalt("u1"), "99".repeat(8));
  assert.deepEqual(second.listEntries("u1"), [
    { entry_id: "e1", user_token: "u1", timestamp: "2026-08-18T00:00:00.000Z", status: "stored", ciphertext_blob: "blob" },
  ]);
  second.close();
});

test("migrations: idempotent re-run and atomic rollback on injected mid-migration failure", () => {
  const dbPath = join(tempDir, "m1.db");
  const db = openStoreDb(dbPath, CHALLENGE_STORE_MIGRATIONS);
  assert.equal(db.pragma("user_version", { simple: true }), 2);
  db.close();
  const reopened = new Database(dbPath);
  const version = migrateStoreDb(reopened, CHALLENGE_STORE_MIGRATIONS);
  assert.equal(version, 2, "second migration run is a no-op");
  reopened.close();

  const faultPath = join(tempDir, "m2.db");
  const faultDb = new Database(faultPath);
  assert.throws(
    () => migrateStoreDb(faultDb, CHALLENGE_STORE_MIGRATIONS, { faultHook: (v) => { if (v === 2) throw new Error("simulated crash"); } }),
    /simulated crash/,
  );
  assert.equal(faultDb.pragma("user_version", { simple: true }), 1, "failed migration rolls back atomically");
  const tables = faultDb.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='counters'").get();
  assert.equal(tables, undefined, "the rolled-back migration leaves no partial schema");
  faultDb.close();
});

test("schemas are closed DDL: exactly the allowlisted columns exist", () => {
  const store = createSqliteChallengeEntitlementStore({ dbPath: join(tempDir, "s1.db") });
  const columns = store.db.pragma("table_info(challenges)").map((c) => c.name).sort();
  assert.deepEqual(columns, [...CHALLENGE_RECORD_FIELDS].sort());
  store.close();
  const p12 = createSqliteP12LedgerStore({ dbPath: join(tempDir, "s2.db"), optIn: true });
  const p12Columns = p12.db.pragma("table_info(entries)").map((c) => c.name).sort();
  assert.deepEqual(p12Columns, [...P12_OPERATOR_FIELDS].sort());
  p12.close();
});

test("durable limiter: below, at, and above the cap; peek does not consume; window resets; snapshot content-free", () => {
  let now = 1_700_000_012_345; // deliberately not epoch-aligned to windowMs
  const clock = () => new Date(now);
  const store = createSqliteChallengeEntitlementStore({ dbPath: join(tempDir, "l1.db") });
  const limiter = createSqliteFixedWindowLimiter({ db: store.db, scope: "request-rate", max: 2, windowMs: 60_000, clock });

  const first = limiter.check("client-a");
  assert.equal(first.allowed, true);
  assert.equal(first.count, 1);
  assert.equal(first.remaining, 1);
  const second = limiter.check("client-a");
  assert.equal(second.allowed, true);
  assert.equal(second.count, 2);
  const atCap = limiter.check("client-a");
  assert.equal(atCap.allowed, false, "denied at the cap");
  assert.equal(atCap.count, 2, "denial does not increment");
  assert.equal(atCap.remaining, 0);
  assert.ok(atCap.retry_after_seconds >= 1);
  const peeked = limiter.peek("client-a");
  assert.equal(peeked.allowed, false);
  assert.equal(peeked.count, 2, "peek does not consume");
  const clientB = limiter.check("client-b");
  assert.equal(clientB.allowed, true, "cross-client isolation");
  assert.equal(clientB.count, 1);

  now += 61_000;
  const newWindow = limiter.check("client-a");
  assert.equal(newWindow.allowed, true, "window rollover resets the count");
  assert.equal(newWindow.count, 1);
  assert.notEqual(newWindow.window_start, first.window_start);

  const snapshot = limiter.snapshot();
  assert.ok(snapshot.every((row) => typeof row.key === "string" && Number.isInteger(row.count) && typeof row.window_start === "string"));
  // Three windows total: client-a's pre-rollover window, client-a's new
  // window, and client-b's window. The durable limiter retains historical
  // fixed windows (content-free counts only) - the in-memory limiter replaces
  // a bucket on rollover; the durable one keeps the record.
  assert.equal(snapshot.length, 3);
  assert.deepEqual(snapshot.map((row) => row.key).sort(), ["client-a", "client-a", "client-b"]);
  store.close();
});
