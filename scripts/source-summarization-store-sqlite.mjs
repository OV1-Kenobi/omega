#!/usr/bin/env node

// Durable SQLite stores for the WP6 public tier (plan ECP-2026-08-18-OMEGA-
// WP6-MDK-STORE sections 6.3.3-6.3.6; Security condition 1: durable
// single-winner redemption). These implement the SAME public method surfaces
// as the in-memory paddock stores in source-summarization-l402.mjs and
// source-summarization-p12.mjs so the composition layer (tests / staging
// harness) injects them without touching the six committed modules.
//
// PADDOCK/STAGING GRADE. No live calls, no credentials, no content: the
// schemas are the closed content-free DDL of the plan. The bolt11 invoice,
// preimage, macaroon, URL, title, and content have no column anywhere.
//
// Durability configuration (plan 6.3.5): journal_mode=WAL on both databases;
// synchronous=FULL on challenge-entitlement.db (the redemption commit must
// survive a crash after a receipt has been issued) and FULL on p12.db as well
// (recorded choice: consistency with the entitlement store; the write-rate
// cost is negligible at alpha volumes); busy_timeout 5000 ms (recorded value)
// so a concurrent writer waits instead of failing.
//
// Single-winner pattern (the durable analog of the paddock's synchronous
// check-and-set): BEGIN IMMEDIATE transaction + INSERT into `redemptions`,
// whose PRIMARY KEY on payment_hash makes the loser's insert fail inside the
// write transaction. Verified across two real processes by the test suite.
//
// Fixed-window counters: the in-memory limiter anchors a window on first
// sight; the durable limiter uses EPOCH-ALIGNED windows (floor(now/windowMs))
// so multiple processes agree on the bucket without coordination. Both are
// fixed-window; the epoch-aligned variant is the multi-process-correct
// choice. Counts and window timestamps only - content-free by construction.
//
// Capability manifest (agent-and-skill-security-policy section 2; plan 6.2.4):
//   - Files/dirs: two SQLite files supplied by the caller (challenge/
//     entitlement db and p12 db) plus their -wal/-shm sidecars; the
//     scripts\node_modules better-sqlite3 tree (gitignored).
//   - Network: NONE at runtime. The npm registry is contacted only at install
//     time (including the prebuilt-binary download or node-gyp toolchain
//     fetch, whichever the install gate records).
//   - Permissions: file ACLs limited to the serving service identity.
//   - Accounts/credentials/tokens: none. No credential value ever passes
//     through this module.
//   - Failure behavior: fail-closed typed errors; redemption contention
//     surfaces as already_redeemed; busy writers wait up to busy_timeout.
//   - Pinning: better-sqlite3 exact-pinned in scripts\package.json with the
//     committed lockfile; the native artifact is vendored/pinned at the
//     install gate; a cold-cache re-fetch is a re-review trigger.
//   - Owner: founder/operator.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { CHALLENGE_RECORD_FIELDS } from "./source-summarization-l402.mjs";
import { P12_OPERATOR_FIELDS, P12_STATUS_VOCABULARY } from "./source-summarization-p12.mjs";

export const STORE_BUSY_TIMEOUT_MS = 5000;

const CHALLENGE_STATUSES = new Set(["issued", "redeemed", "expired"]);

// ---------------------------------------------------------------------------
// Migrations (plan 6.3.3/6.3.4): additive, idempotent, user_version-stepped.
// ---------------------------------------------------------------------------

export const CHALLENGE_STORE_MIGRATIONS = [
  {
    version: 1,
    statements: [
      `CREATE TABLE IF NOT EXISTS challenges (
        challenge_id TEXT PRIMARY KEY,
        payment_hash TEXT NOT NULL,
        amount_sats INTEGER NOT NULL CHECK (amount_sats > 0),
        capability TEXT NOT NULL,
        version TEXT NOT NULL,
        client_id TEXT,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('issued','redeemed','expired')),
        redeemed_at TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS redemptions (
        payment_hash TEXT PRIMARY KEY,
        challenge_id TEXT NOT NULL,
        redeemed_at TEXT NOT NULL
      )`,
    ],
  },
  {
    version: 2,
    statements: [
      `CREATE TABLE IF NOT EXISTS counters (
        client_id TEXT NOT NULL,
        scope TEXT NOT NULL,
        window_start TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (client_id, scope, window_start)
      )`,
    ],
  },
];

export const P12_STORE_MIGRATIONS = [
  {
    version: 1,
    statements: [
      `CREATE TABLE IF NOT EXISTS entries (
        entry_id TEXT PRIMARY KEY,
        user_token TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('ok','stored','decrypt_failed','superseded')),
        ciphertext_blob TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS salts (
        user_token TEXT PRIMARY KEY,
        salt_hex TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS ledger_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )`,
    ],
  },
];

// Runs every migration whose version is above the stored user_version, each
// inside one BEGIN IMMEDIATE transaction (partial failure rolls back
// atomically). Re-running against a migrated database is a verified no-op.
// `faultHook(version)` - test-only injection point simulating a crash
// mid-migration.
export function migrateStoreDb(db, migrations, { faultHook = null } = {}) {
  const fromVersion = db.pragma("user_version", { simple: true });
  for (const migration of migrations) {
    if (fromVersion >= migration.version) continue;
    const run = db.transaction(() => {
      if (faultHook) faultHook(migration.version);
      for (const statement of migration.statements) db.exec(statement);
      db.pragma(`user_version = ${migration.version}`);
    });
    run.immediate();
  }
  return db.pragma("user_version", { simple: true });
}

export function openStoreDb(dbPath, migrations, { busyTimeoutMs = STORE_BUSY_TIMEOUT_MS, synchronous = "FULL", faultHook = null } = {}) {
  const db = new Database(dbPath);
  db.pragma(`busy_timeout = ${busyTimeoutMs}`);
  db.pragma("journal_mode = WAL");
  db.pragma(`synchronous = ${synchronous}`);
  migrateStoreDb(db, migrations, { faultHook });
  return db;
}

export function newTempStoreDir(prefix = "wp6-store-test-") {
  return mkdtempSync(join(tmpdir(), prefix));
}

export function removeTempStoreDir(dir) {
  rmSync(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Durable challenge/entitlement store (same surface as the in-memory seam)
// ---------------------------------------------------------------------------

export function createSqliteChallengeEntitlementStore({ dbPath, db = null, clock = () => new Date(), ownDb = false } = {}) {
  const database = db ?? openStoreDb(dbPath, CHALLENGE_STORE_MIGRATIONS);
  const ownsDb = db === null || ownDb;

  const insertChallenge = database.prepare(
    `INSERT INTO challenges (challenge_id, payment_hash, amount_sats, capability, version, client_id, issued_at, expires_at, status, redeemed_at)
     VALUES (@challenge_id, @payment_hash, @amount_sats, @capability, @version, @client_id, @issued_at, @expires_at, 'issued', NULL)`,
  );
  const markRedeemed = database.prepare(
    `UPDATE challenges SET status = 'redeemed', redeemed_at = ? WHERE payment_hash = ?`,
  );
  const insertRedemption = database.prepare(
    `INSERT INTO redemptions (payment_hash, challenge_id, redeemed_at) VALUES (?, ?, ?)`,
  );
  const findRedemption = database.prepare(`SELECT challenge_id FROM redemptions WHERE payment_hash = ?`);
  const challengeForHash = database.prepare(`SELECT challenge_id FROM challenges WHERE payment_hash = ? ORDER BY issued_at LIMIT 1`);
  const countRedemptions = database.prepare(`SELECT COUNT(*) AS n FROM redemptions`);
  const getChallengeRow = database.prepare(`SELECT * FROM challenges WHERE challenge_id = ?`);
  const listChallengeRows = database.prepare(`SELECT * FROM challenges ORDER BY issued_at, rowid`);

  function assertContentFreeRecord(record) {
    for (const key of Object.keys(record)) {
      if (!CHALLENGE_RECORD_FIELDS.includes(key)) {
        throw new Error(`challenge record carries a non-allowlisted field: ${key}`);
      }
    }
    if (!CHALLENGE_STATUSES.has(record.status)) throw new Error("challenge record has an invalid status");
    if (typeof record.payment_hash !== "string" || !/^[0-9a-f]{64}$/.test(record.payment_hash)) {
      throw new Error("challenge record has an invalid payment_hash");
    }
    if (!Number.isInteger(record.amount_sats) || record.amount_sats <= 0) {
      throw new Error("challenge record has an invalid amount_sats");
    }
  }

  // Durable one-shot redemption: BEGIN IMMEDIATE + INSERT into redemptions.
  // The UNIQUE primary key on payment_hash makes exactly one writer the
  // winner, across processes; every other attempt (including a concurrent
  // one that waited on busy_timeout) receives already_redeemed.
  const redeemTx = database.transaction((paymentHash) => {
    const existing = findRedemption.get(paymentHash);
    if (existing) return { ok: false, reason: "already_redeemed" };
    const redeemedAt = clock().toISOString();
    let challengeId = challengeForHash.get(paymentHash)?.challenge_id ?? null;
    if (challengeId === null) {
      // A proof whose challenge was never recorded still burns its payment
      // hash exactly once (stateless verification precedes the store), but
      // the row needs a challenge_id; use the hash itself as the marker.
      challengeId = `unrecorded:${paymentHash}`;
    }
    insertRedemption.run(paymentHash, challengeId, redeemedAt);
    markRedeemed.run(redeemedAt, paymentHash);
    return { ok: true };
  });

  return {
    recordChallenge(challenge) {
      // Reject a content-bearing field on the INPUT, never silently drop it
      // behind an allowlist copy (the in-memory seam's contract).
      if (challenge === null || typeof challenge !== "object" || Array.isArray(challenge)) {
        throw new Error("challenge record must be an object");
      }
      for (const key of Object.keys(challenge)) {
        if (!CHALLENGE_RECORD_FIELDS.includes(key)) {
          throw new Error(`challenge record carries a non-allowlisted field: ${key}`);
        }
      }
      const record = {};
      for (const field of CHALLENGE_RECORD_FIELDS) {
        if (challenge[field] !== undefined) record[field] = challenge[field];
      }
      if (record.status !== undefined && !CHALLENGE_STATUSES.has(record.status)) {
        throw new Error("challenge record has an invalid status");
      }
      record.status = "issued";
      record.redeemed_at = null;
      assertContentFreeRecord(record);
      try {
        insertChallenge.run(record);
      } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_PRIMARYKEY") throw new Error("challenge id already recorded");
        throw error;
      }
      return { ...record };
    },
    redeem(paymentHash) {
      try {
        return redeemTx.immediate(paymentHash);
      } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_PRIMARYKEY") return { ok: false, reason: "already_redeemed" };
        throw error;
      }
    },
    isRedeemed(paymentHash) {
      return findRedemption.get(paymentHash) !== undefined;
    },
    getChallenge(challengeId) {
      const row = getChallengeRow.get(challengeId);
      return row ? { ...row } : null;
    },
    listRecords() {
      return listChallengeRows.all().map((row) => ({ ...row }));
    },
    countRedemptions() {
      return countRedemptions.get().n;
    },
    close() {
      if (ownsDb) database.close();
    },
    get db() {
      return database;
    },
  };
}

// ---------------------------------------------------------------------------
// Durable P12 ledger store (same surface as the in-memory seam)
// ---------------------------------------------------------------------------

export function createSqliteP12LedgerStore({
  dbPath,
  db = null,
  optIn = false,
  maxEntriesPerUser = 1000,
  maxAgeMs = 365 * 24 * 60 * 60 * 1000,
  clock = () => new Date(),
  ownDb = false,
} = {}) {
  const database = db ?? openStoreDb(dbPath, P12_STORE_MIGRATIONS);
  const ownsDb = db === null || ownDb;

  const getState = database.prepare(`SELECT value FROM ledger_state WHERE key = 'opted_in'`);
  const setState = database.prepare(`INSERT INTO ledger_state (key, value) VALUES ('opted_in', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`);
  const insertEntry = database.prepare(
    `INSERT INTO entries (entry_id, user_token, timestamp, status, ciphertext_blob) VALUES (@entry_id, @user_token, @timestamp, @status, @ciphertext_blob)`,
  );
  const entryExistsForUser = database.prepare(`SELECT 1 FROM entries WHERE user_token = ? AND entry_id = ?`);
  const listEntriesFor = database.prepare(`SELECT entry_id, user_token, timestamp, status, ciphertext_blob FROM entries WHERE user_token = ? ORDER BY rowid`);
  const deleteEntriesFor = database.prepare(`DELETE FROM entries WHERE user_token = ?`);
  const deleteSaltFor = database.prepare(`DELETE FROM salts WHERE user_token = ?`);
  const deleteAllEntries = database.prepare(`DELETE FROM entries`);
  const deleteAllSalts = database.prepare(`DELETE FROM salts`);
  const getSaltRow = database.prepare(`SELECT salt_hex FROM salts WHERE user_token = ?`);
  const insertSalt = database.prepare(`INSERT INTO salts (user_token, salt_hex) VALUES (?, ?)`);
  const trimByAge = database.prepare(`DELETE FROM entries WHERE user_token = ? AND timestamp < ?`);
  const trimByCount = database.prepare(
    `DELETE FROM entries WHERE user_token = ? AND entry_id IN (
       SELECT entry_id FROM entries WHERE user_token = ? ORDER BY timestamp DESC, rowid DESC LIMIT -1 OFFSET ?
     )`,
  );

  function optedIn() {
    return getState.get()?.value === "1";
  }

  function assertEntryShape(entry) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) throw new Error("ledger entry must be an object");
    for (const key of Object.keys(entry)) {
      if (!P12_OPERATOR_FIELDS.includes(key)) {
        throw new Error(`ledger entry carries a non-allowlisted field: ${key}`);
      }
    }
    for (const field of P12_OPERATOR_FIELDS) {
      if (typeof entry[field] !== "string" || entry[field] === "") {
        throw new Error(`ledger entry is missing field: ${field}`);
      }
    }
    if (!P12_STATUS_VOCABULARY.includes(entry.status)) {
      throw new Error("ledger entry status is outside the enumerated vocabulary");
    }
    if (Number.isNaN(Date.parse(entry.timestamp))) throw new Error("ledger entry timestamp is invalid");
  }

  function enforceRetention(userToken) {
    const cutoff = new Date(clock().getTime() - maxAgeMs).toISOString();
    trimByAge.run(userToken, cutoff);
    trimByCount.run(userToken, userToken, maxEntriesPerUser);
  }

  if (optIn === true && !optedIn()) setState.run("1");

  return {
    isOptedIn: () => optedIn(),
    optIn() {
      setState.run("1");
    },
    optOut(userToken = null) {
      if (userToken === null) {
        deleteAllEntries.run();
        deleteAllSalts.run();
        setState.run("0");
        return;
      }
      deleteEntriesFor.run(userToken);
      deleteSaltFor.run(userToken);
    },
    setSalt(userToken, saltHex) {
      if (typeof saltHex !== "string" || !/^[0-9a-f]{2,}$/.test(saltHex)) throw new Error("salt must be hex");
      const existing = getSaltRow.get(userToken);
      if (existing !== undefined && existing.salt_hex !== saltHex) {
        // Stable per ledger lifetime; a change means re-encryption, never a
        // silent swap under old ciphertext (paddock rule preserved).
        throw new Error("salt rotation requires ledger re-encryption");
      }
      if (existing === undefined) insertSalt.run(userToken, saltHex);
    },
    getSalt(userToken) {
      return getSaltRow.get(userToken)?.salt_hex ?? null;
    },
    append(entry) {
      if (!optedIn()) throw new Error("ledger is not enabled: user opt-in required");
      assertEntryShape(entry);
      if (entryExistsForUser.get(entry.user_token, entry.entry_id) !== undefined) {
        throw new Error("entry_id must be unique within the user's ledger");
      }
      insertEntry.run(entry);
      enforceRetention(entry.user_token);
    },
    listEntries(userToken) {
      return listEntriesFor.all(userToken).map((row) => ({ ...row }));
    },
    close() {
      if (ownsDb) database.close();
    },
    get db() {
      return database;
    },
  };
}

// ---------------------------------------------------------------------------
// Durable fixed-window limiter over the counters table (same outcome shape
// as the in-memory limiter; epoch-aligned windows - see header note)
// ---------------------------------------------------------------------------

export function createSqliteFixedWindowLimiter({ db, scope, max, windowMs, clock = () => new Date() } = {}) {
  if (!Number.isInteger(max) || max <= 0) throw new Error("max must be a positive integer");
  if (!Number.isInteger(windowMs) || windowMs <= 0) throw new Error("windowMs must be a positive integer");
  if (typeof scope !== "string" || scope === "") throw new Error("scope must be a non-empty string");

  const getCount = db.prepare(`SELECT count FROM counters WHERE client_id = ? AND scope = ? AND window_start = ?`);
  const insertCount = db.prepare(`INSERT INTO counters (client_id, scope, window_start, count) VALUES (?, ?, ?, 1)`);
  const bumpCount = db.prepare(`UPDATE counters SET count = count + 1 WHERE client_id = ? AND scope = ? AND window_start = ?`);
  const listWindows = db.prepare(`SELECT client_id, count, window_start FROM counters WHERE scope = ? ORDER BY window_start, client_id`);

  function windowStartFor(now) {
    const aligned = Math.floor(now / windowMs) * windowMs;
    return { key: new Date(aligned).toISOString(), resetAtMs: aligned + windowMs };
  }

  function outcome(keyIso, resetAtMs, now, count, allowed) {
    return {
      allowed,
      count,
      max,
      remaining: Math.max(0, max - count),
      window_start: keyIso,
      reset_at: new Date(resetAtMs).toISOString(),
      retry_after_seconds: Math.max(1, Math.ceil((resetAtMs - now) / 1000)),
    };
  }

  const checkTx = db.transaction((key) => {
    const now = clock().getTime();
    const { key: keyIso, resetAtMs } = windowStartFor(now);
    const row = getCount.get(key, scope, keyIso);
    if (row === undefined) {
      insertCount.run(key, scope, keyIso);
      return outcome(keyIso, resetAtMs, now, 1, true);
    }
    if (row.count >= max) return outcome(keyIso, resetAtMs, now, row.count, false);
    bumpCount.run(key, scope, keyIso);
    return outcome(keyIso, resetAtMs, now, row.count + 1, true);
  });

  return {
    check(key) {
      if (typeof key !== "string" || key === "") throw new Error("limiter key must be a non-empty string");
      return checkTx.immediate(key);
    },
    peek(key) {
      if (typeof key !== "string" || key === "") throw new Error("limiter key must be a non-empty string");
      const now = clock().getTime();
      const { key: keyIso, resetAtMs } = windowStartFor(now);
      const row = getCount.get(key, scope, keyIso);
      const count = row === undefined ? 0 : row.count;
      return outcome(keyIso, resetAtMs, now, count, count < max);
    },
    snapshot() {
      // Content-free: opaque keys, counts, window starts - nothing else.
      return listWindows.all(scope).map((row) => ({ key: row.client_id, count: row.count, window_start: row.window_start }));
    },
  };
}
