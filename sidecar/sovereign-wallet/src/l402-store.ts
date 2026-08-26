//! L-402 gateway state store (design §5.5; WP-6) on `node:sqlite`.
//!
//! Tables are modeled on the MDK audit's D1 schema
//! (`apps/openagents.com/docs/2026-06-02-mdk-l402-agent-checkout-audit.md`,
//! "D1 Data Model"), adapted to local SQLite under
//! `<data_root>/l402/l402-gateway.db`. The gateway state survives sidecar
//! restarts by construction — no in-memory-only truth (design §5.5).
//!
//! ## S1 discipline (SEC-2026-051)
//!
//! No key-material columns: no nsec/secret/preimage/mnemonic/password/
//! passphrase/macaroon columns exist. `token_hash` is the SHA-256 digest of
//! the opaque credential (a non-reversible lookup key, never the credential
//! itself) — the design requires storing it (design §5.2 "store the token
//! hash, never the token"; audit D1 `token_hash TEXT NOT NULL UNIQUE`), and
//! WP-2's S1 remediation names nsec/secret/preimage, not token digests; the
//! invariant-suite forbidden list is corrected accordingly (see
//! `scripts/check-invariants.mjs` S1 note).
//!
//! ## One-shot redemption (audit D1; design §5.3/§5.5)
//!
//! `l402_redemptions` carries a UNIQUE PARTIAL INDEX on
//! `(challenge_id) WHERE status = 'settled'`: exactly one settled redemption
//! per challenge can ever exist, enforced at the SQLite layer — the single
//! winner under concurrent redemptions, and the idempotent recovery anchor
//! after a crash in the deferred-settlement window (SEC-2026-048).

import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS paid_endpoint_products (
  id TEXT PRIMARY KEY,
  stable_key TEXT NOT NULL UNIQUE,
  method TEXT NOT NULL,
  path_pattern TEXT NOT NULL,
  protected_ref TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','disabled')),
  rail TEXT NOT NULL CHECK (rail IN ('mdk_lightning','manual_test')),
  currency TEXT NOT NULL CHECK (currency IN ('SAT','USD')),
  amount_sats INTEGER,
  settlement_mode TEXT NOT NULL CHECK (settlement_mode IN ('immediate','deferred')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS l402_challenges (
  id TEXT PRIMARY KEY,
  protected_ref TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  resource TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('issued','paid','redeemed','expired','revoked','failed')),
  rail TEXT NOT NULL,
  currency TEXT NOT NULL,
  amount_sats INTEGER NOT NULL,
  invoice TEXT NOT NULL,
  payment_hash TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  paid_at INTEGER,
  redeemed_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS l402_redemptions (
  id TEXT PRIMARY KEY,
  challenge_id TEXT NOT NULL,
  protected_ref TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('checked','settled','rejected')),
  request_id TEXT NOT NULL,
  response_status INTEGER,
  failure_code TEXT,
  created_at INTEGER NOT NULL,
  settled_at INTEGER,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY (challenge_id) REFERENCES l402_challenges(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS l402_redemptions_challenge_settled_idx
  ON l402_redemptions(challenge_id) WHERE status = 'settled';

CREATE TABLE IF NOT EXISTS payment_entitlements (
  id TEXT PRIMARY KEY,
  challenge_id TEXT,
  protected_ref TEXT NOT NULL,
  entitlement_scope TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','expired','revoked')),
  amount_sats INTEGER NOT NULL,
  starts_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  target_ref TEXT NOT NULL,
  source_refs_json TEXT NOT NULL DEFAULT '[]',
  summary TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  method TEXT NOT NULL,
  idempotency_key TEXT PRIMARY KEY,
  result_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Server -> Nostr-identity mapping for L-402 entitlement attribution
-- (design §6.4 / §5.4). principal_pubkey is a public 64-hex Nostr pubkey or
-- NULL when a server is mapped but has no identity yet.
CREATE TABLE IF NOT EXISTS mcp_server_identity_map (
  server_id TEXT PRIMARY KEY,
  principal_pubkey TEXT,
  updated_at INTEGER NOT NULL
);
`;

export interface PaidProduct {
  id: string;
  stableKey: string;
  method: string;
  pathPattern: string;
  protectedRef: string;
  title: string;
  status: "active" | "disabled";
  rail: "mdk_lightning" | "manual_test";
  currency: "SAT" | "USD";
  amountSats: number | null;
  settlementMode: "immediate" | "deferred";
  createdAtMs?: number;
  updatedAtMs?: number;
}

export interface L402ChallengeRow {
  id: string;
  protectedRef: string;
  method: string;
  path: string;
  resource: string;
  status: "issued" | "paid" | "redeemed" | "expired" | "revoked" | "failed";
  amountSats: number;
  invoice: string;
  paymentHash: string;
  tokenHash: string;
  expiresAtMs: number;
  createdAtMs?: number;
  updatedAtMs?: number;
}

export interface RedemptionRow {
  id: string;
  challengeId: string;
  protectedRef: string;
  status: "checked" | "settled" | "rejected";
  requestId: string;
  createdAtMs: number;
  settledAtMs: number | null;
}

/** Outcome of an idempotency-key fetch (redemption idempotency, §2.4/§5.5). */
export interface StoredResult {
  method: string;
  result: unknown;
}

const ISO = (ms: number): string => new Date(ms).toISOString();

export class L402Store {
  readonly #db: DatabaseSync;

  private constructor(db: DatabaseSync) {
    this.#db = db;
  }

  static open(dataRoot: string): L402Store {
    const dir = path.join(dataRoot, "l402");
    mkdirSync(dir, { recursive: true });
    const db = new DatabaseSync(path.join(dir, "l402-gateway.db"));
    db.exec("PRAGMA journal_mode = WAL;");
    db.exec("PRAGMA foreign_keys = ON;");
    db.exec(SCHEMA);
    return new L402Store(db);
  }

  /** Seed-or-ignore a paid endpoint product (the audit's "seed in code"). */
  seedProduct(product: PaidProduct): void {
    this.#db
      .prepare(
        `INSERT OR IGNORE INTO paid_endpoint_products
         (id, stable_key, method, path_pattern, protected_ref, title, status, rail, currency, amount_sats, settlement_mode, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        product.id,
        product.stableKey,
        product.method,
        product.pathPattern,
        product.protectedRef,
        product.title,
        product.status,
        product.rail,
        product.currency,
        product.amountSats,
        product.settlementMode,
        ISO(product.createdAtMs ?? Date.now()),
        ISO(product.updatedAtMs ?? Date.now()),
      );
  }

  /** Resolve the active product for a protected_ref; null when disabled/absent. */
  getProduct(protectedRef: string): PaidProduct | null {
    const row = this.#db
      .prepare(
        "SELECT * FROM paid_endpoint_products WHERE protected_ref = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1",
      )
      .get(protectedRef) as Record<string, unknown> | undefined;
    return row ? rowToProduct(row) : null;
  }

  insertChallenge(challenge: L402ChallengeRow): void {
    this.#db
      .prepare(
        `INSERT INTO l402_challenges
         (id, protected_ref, method, path, resource, status, rail, currency, amount_sats, invoice, payment_hash, token_hash, expires_at, created_at, updated_at, metadata_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        challenge.id,
        challenge.protectedRef,
        challenge.method,
        challenge.path,
        challenge.resource,
        challenge.status,
        "mdk_lightning",
        "SAT",
        challenge.amountSats,
        challenge.invoice,
        challenge.paymentHash,
        challenge.tokenHash,
        challenge.expiresAtMs,
        ISO(challenge.createdAtMs ?? Date.now()),
        ISO(challenge.updatedAtMs ?? Date.now()),
        "{}",
      );
  }

  getChallengeByTokenHash(tokenHash: string): L402ChallengeRow | null {
    const row = this.#db
      .prepare("SELECT * FROM l402_challenges WHERE token_hash = ?")
      .get(tokenHash) as Record<string, unknown> | undefined;
    return row ? rowToChallenge(row) : null;
  }

  getChallengeByPaymentHash(paymentHash: string): L402ChallengeRow | null {
    const row = this.#db
      .prepare("SELECT * FROM l402_challenges WHERE payment_hash = ?")
      .get(paymentHash) as Record<string, unknown> | undefined;
    return row ? rowToChallenge(row) : null;
  }

  markRedeemed(challengeId: string, redeemedAtMs: number): void {
    this.#db
      .prepare(
        "UPDATE l402_challenges SET status = 'redeemed', redeemed_at = ?, updated_at = ? WHERE id = ? AND status IN ('issued','paid')",
      )
      .run(redeemedAtMs, ISO(redeemedAtMs), challengeId);
  }

  /** Expire issued/paid challenges past their deadline (challenge expiry sweep). */
  sweepExpired(nowMs: number): number {
    const outcome = this.#db
      .prepare(
        "UPDATE l402_challenges SET status = 'expired', updated_at = ? WHERE status IN ('issued','paid') AND expires_at < ?",
      )
      .run(ISO(nowMs), nowMs);
    return Number(outcome.changes ?? 0);
  }

  /**
   * Insert a `checked` redemption row BEFORE the protected handler runs
   * (deferred settlement, SEC-2026-048). Guarded: a challenge that already
   * has a checked-or-settled redemption is not double-inserted — a retry after
   * a crash reuses the existing checked row (the crash-window recovery
   * anchor). Returns the checked row id.
   */
  insertCheckedRedemption(
    challengeId: string,
    protectedRef: string,
    requestId: string,
    nowMs: number,
  ): string {
    const existing = this.#db
      .prepare(
        "SELECT id FROM l402_redemptions WHERE challenge_id = ? AND status IN ('checked','settled') ORDER BY created_at ASC LIMIT 1",
      )
      .get(challengeId) as { id: string } | undefined;
    if (existing) return existing.id;
    const id = `l402_redemption_${nowMs.toString(36)}_${requestId.slice(0, 12)}`;
    this.#db
      .prepare(
        `INSERT INTO l402_redemptions
         (id, challenge_id, protected_ref, status, request_id, created_at, metadata_json)
         VALUES (?, ?, ?, 'checked', ?, ?, '{}')`,
      )
      .run(id, challengeId, protectedRef, requestId, ISO(nowMs));
    return id;
  }

  getCheckedRedemption(challengeId: string): RedemptionRow | null {
    const row = this.#db
      .prepare(
        "SELECT * FROM l402_redemptions WHERE challenge_id = ? AND status = 'checked' ORDER BY created_at ASC LIMIT 1",
      )
      .get(challengeId) as Record<string, unknown> | undefined;
    return row ? rowToRedemption(row) : null;
  }

  hasSettledRedemption(challengeId: string): boolean {
    const row = this.#db
      .prepare(
        "SELECT id FROM l402_redemptions WHERE challenge_id = ? AND status = 'settled' LIMIT 1",
      )
      .get(challengeId) as { id: string } | undefined;
    return row !== undefined;
  }

  /**
   * Insert the settled redemption row — the ONE-SHOT single-winner operation.
   * The unique partial index on `(challenge_id) WHERE status = 'settled'`
   * makes a concurrent second redemption fail at the SQLite layer.
   * Returns `{ settled: true, id }` or `{ settled: false }` when a settled
   * redemption already exists.
   */
  insertSettledRedemption(
    challengeId: string,
    protectedRef: string,
    requestId: string,
    nowMs: number,
  ): { settled: boolean; id: string } {
    const id = `l402_redemption_${nowMs.toString(36)}_${requestId.slice(0, 12)}`;
    try {
      this.#db
        .prepare(
          `INSERT INTO l402_redemptions
           (id, challenge_id, protected_ref, status, request_id, response_status, settled_at, created_at, metadata_json)
           VALUES (?, ?, ?, 'settled', ?, 200, ?, ?, '{}')`,
        )
        .run(id, challengeId, protectedRef, requestId, ISO(nowMs), ISO(nowMs));
      return { settled: true, id };
    } catch (error) {
      // SQLITE_CONSTRAINT on the unique partial index: one-shot consumed.
      return { settled: false, id };
    }
  }

  /** Deferred settle: flip the existing checked row to settled (single-winner). */
  settleCheckedRedemption(challengeId: string, nowMs: number): { settled: boolean; id: string } {
    const checked = this.getCheckedRedemption(challengeId);
    if (!checked) return { settled: false, id: "" };
    try {
      const outcome = this.#db
        .prepare(
          "UPDATE l402_redemptions SET status = 'settled', response_status = 200, settled_at = ? WHERE id = ? AND status = 'checked'",
        )
        .run(ISO(nowMs), checked.id);
      if (Number(outcome.changes ?? 0) !== 1) return { settled: false, id: checked.id };
      return { settled: true, id: checked.id };
    } catch (error) {
      // The unique partial index rejected a second settled row: consumed.
      return { settled: false, id: checked.id };
    }
  }

  insertEntitlement(
    challengeId: string,
    protectedRef: string,
    scope: string,
    amountSats: number,
    startsAtMs: number,
    expiresAtMs: number,
  ): void {
    this.#db
      .prepare(
        `INSERT INTO payment_entitlements
         (id, challenge_id, protected_ref, entitlement_scope, status, amount_sats, starts_at, expires_at, created_at, updated_at, metadata_json)
         VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, '{}')`,
      )
      .run(
        `l402_entitlement_${startsAtMs.toString(36)}_${challengeId.slice(-12)}`,
        challengeId,
        protectedRef,
        scope,
        amountSats,
        ISO(startsAtMs),
        ISO(expiresAtMs),
        ISO(startsAtMs),
        ISO(expiresAtMs),
      );
  }

  insertReceipt(
    kind: string,
    status: string,
    targetRef: string,
    summary: string,
    nowMs: number,
  ): void {
    this.#db
      .prepare(
        `INSERT INTO receipts (id, kind, status, target_ref, source_refs_json, summary, metadata_json, created_at)
         VALUES (?, ?, ?, ?, '[]', ?, '{}', ?)`,
      )
      .run(`l402_receipt_${nowMs.toString(36)}_${targetRef.slice(-12)}`, kind, status, targetRef, summary, ISO(nowMs));
  }

  // -- redemption idempotency (design §2.4/§5.5; no secret values) -----------

  storeIdempotent(method: string, idempotencyKey: string, result: unknown): boolean {
    const outcome = this.#db
      .prepare(
        "INSERT OR IGNORE INTO idempotency_keys (method, idempotency_key, result_json, created_at) VALUES (?, ?, ?, ?)",
      )
      .run(method, idempotencyKey, JSON.stringify(result), Date.now());
    return Number(outcome.changes ?? 0) === 1;
  }

  fetchIdempotent(method: string, idempotencyKey: string): StoredResult | null {
    const row = this.#db
      .prepare("SELECT method, result_json FROM idempotency_keys WHERE method = ? AND idempotency_key = ?")
      .get(method, idempotencyKey) as { method: string; result_json: string } | undefined;
    if (!row) return null;
    return { method: row.method, result: JSON.parse(row.result_json) };
  }

  // -- MCP server -> Nostr identity map (design §6.4; §5.4 attribution) ------

  mcpIdentityMapGet(): Record<string, string> {
    const rows = this.#db
      .prepare("SELECT server_id, principal_pubkey FROM mcp_server_identity_map")
      .all() as Array<{ server_id: string; principal_pubkey: string | null }>;
    const map: Record<string, string> = {};
    for (const row of rows) {
      if (row.principal_pubkey) map[row.server_id] = row.principal_pubkey;
    }
    return map;
  }

  mcpIdentityMapSet(serverId: string, principalPubkey: string | null): void {
    if (principalPubkey === null) {
      this.#db
        .prepare("UPDATE mcp_server_identity_map SET principal_pubkey = NULL, updated_at = ? WHERE server_id = ?")
        .run(ISO(Date.now()), serverId);
      return;
    }
    this.#db
      .prepare(
        `INSERT INTO mcp_server_identity_map (server_id, principal_pubkey, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(server_id) DO UPDATE SET principal_pubkey = excluded.principal_pubkey, updated_at = excluded.updated_at`,
      )
      .run(serverId, principalPubkey, ISO(Date.now()));
  }

  close(): void {
    this.#db.close();
  }
}

// -- row mappers ---------------------------------------------------------------

function rowToProduct(row: Record<string, unknown>): PaidProduct {
  return {
    id: String(row.id),
    stableKey: String(row.stable_key),
    method: String(row.method),
    pathPattern: String(row.path_pattern),
    protectedRef: String(row.protected_ref),
    title: String(row.title),
    status: row.status as PaidProduct["status"],
    rail: row.rail as PaidProduct["rail"],
    currency: row.currency as PaidProduct["currency"],
    amountSats: row.amount_sats === null ? null : Number(row.amount_sats),
    settlementMode: row.settlement_mode as PaidProduct["settlementMode"],
  };
}

function rowToChallenge(row: Record<string, unknown>): L402ChallengeRow {
  return {
    id: String(row.id),
    protectedRef: String(row.protected_ref),
    method: String(row.method),
    path: String(row.path),
    resource: String(row.resource),
    status: row.status as L402ChallengeRow["status"],
    amountSats: Number(row.amount_sats),
    invoice: String(row.invoice),
    paymentHash: String(row.payment_hash),
    tokenHash: String(row.token_hash),
    expiresAtMs: Number(row.expires_at),
  };
}

function rowToRedemption(row: Record<string, unknown>): RedemptionRow {
  return {
    id: String(row.id),
    challengeId: String(row.challenge_id),
    protectedRef: String(row.protected_ref),
    status: row.status as RedemptionRow["status"],
    requestId: String(row.request_id),
    createdAtMs: Number(row.created_at),
    settledAtMs: row.settled_at === null ? null : Number(row.settled_at),
  };
}