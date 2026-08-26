//! Idempotency ledger (design §2.4) on `node:sqlite` (Node >= 23.4).
//!
//! SEC-2026-047: the result cache NEVER stores payment preimages. For
//! `pay-invoice`, the stored result is preimage-free; a duplicate-key replay
//! re-derives the preimage from the activity feed instead of reading it from
//! this store. No secret column exists in this schema (S1).

import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS idempotency_keys (
  method TEXT NOT NULL,
  idempotency_key TEXT PRIMARY KEY,
  result_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`;

export interface StoredResult {
  method: string;
  result: unknown;
}

export class IdempotencyStore {
  readonly #db: DatabaseSync;

  private constructor(db: DatabaseSync) {
    this.#db = db;
  }

  static open(dataRoot: string): IdempotencyStore {
    const dir = path.join(dataRoot, "run");
    mkdirSync(dir, { recursive: true });
    const db = new DatabaseSync(path.join(dir, "idempotency.db"));
    db.exec("PRAGMA journal_mode = WAL;");
    db.exec(SCHEMA);
    return new IdempotencyStore(db);
  }

  /** Store a processed idempotency key result. Returns true when newly stored. */
  store(method: string, idempotencyKey: string, result: unknown): boolean {
    const json = JSON.stringify(result);
    const insert = this.#db.prepare(
      "INSERT OR IGNORE INTO idempotency_keys (method, idempotency_key, result_json, created_at) VALUES (?, ?, ?, ?)",
    );
    const outcome = insert.run(method, idempotencyKey, json, Date.now());
    return outcome.changes === 1;
  }

  /** Fetch a stored result for a key, or null. */
  fetch(method: string, idempotencyKey: string): StoredResult | null {
    const row = this.#db
      .prepare("SELECT method, result_json FROM idempotency_keys WHERE method = ? AND idempotency_key = ?")
      .get(method, idempotencyKey) as { method: string; result_json: string } | undefined;
    if (!row) return null;
    return { method: row.method, result: JSON.parse(row.result_json) };
  }

  close(): void {
    this.#db.close();
  }
}