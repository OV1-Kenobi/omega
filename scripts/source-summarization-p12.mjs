#!/usr/bin/env node

// P12 client-side encryption and ciphertext ledger boundary for the WP6 public
// tier (PRD P12; the implementation staging plan slice 6; wp6-p12-
// security-review.md conditions; AEAD binding AAD-binding remediation).
//
// CRYPTO STATUS — PROVISIONAL, SECURITY-AGENT REVIEW PENDING. The AEAD here is
// AES-256-GCM from the Node standard library (one of the two candidate
// algorithms named in the approved design, wp6-public-l402-gate.md section
// 9.2) with the AEAD binding remediation implemented: the operator-readable
// metadata (entry_id, user_token, timestamp, status) is bound as AEAD
// associated data, every encryption uses a fresh CSPRNG nonce, and the ledger
// key is derived into a dedicated subkey (key separation). The FINAL AEAD
// selection and the FINAL KDF (Argon2id for human users) remain open until the
// Security-Agent fixes and approves them: Argon2id is not available in the
// Node standard library, and adding a dependency is outside this slice. Only
// the agent-caller high-entropy key path and a provisional scrypt path (for
// paddock determinism) are implemented. No human-passphrase path exists here.
//
// CLIENT-SIDE-ONLY INVARIANT: key derivation and decryption run in the
// CALLER's process. The operator-side store in this module accepts ciphertext
// blobs and public salts only; it has no function that takes, derives, wraps,
// stores, or recovers key material, and it rejects entries carrying anything
// beyond the five operator-readable fields. Introducing any server-side KDF,
// key wrap, or escrow would raise P12 to a founder decision immediately
// (wp6-p12-security-review.md section 7 tripwire) — none exists here.
//
// Capability manifest (agent-and-skill-security-policy section 2):
//   - Files/dirs: none. The store is in-memory; a deployment store is a
//     separate, later component.
//   - Network: none. node:crypto only; no http/net/dns/fetch imports.
//   - Credentials: none held. User key material passes through the encrypt/
//     decrypt functions in the caller's process and is never persisted.
//   - Persistence: in-memory entries {entry_id, user_token, timestamp, status,
//     ciphertext_blob} plus a per-user public salt — nothing else.
//   - Boundaries: caller (user side) <-> store (operator side); the store
//     never sees plaintext or keys.
//   - Failure: decryption failure is a typed error; tampering with ciphertext
//     or with any AAD metadata fails closed.

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, scryptSync, randomUUID } from "node:crypto";

export const P12_OPERATOR_FIELDS = ["entry_id", "user_token", "timestamp", "status", "ciphertext_blob"];
export const P12_STATUS_VOCABULARY = ["ok", "stored", "decrypt_failed", "superseded"];
export const P12_SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const SCRYPT_PROVISIONAL = { N: 1 << 14, r: 8, p: 1 };

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number in canonical data");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
  if (isObject(value)) {
    const entries = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new Error("unsupported value in canonical data");
}

// A fresh public salt per user. Public by design: its job is cross-user
// correlation resistance and precomputation resistance (PRD P12), never
// secrecy. One salt per user for the ledger's lifetime; rotation means
// re-encryption, never a silent salt change.
export function createUserSalt() {
  return randomBytes(P12_SALT_BYTES).toString("hex");
}

// Key derivation seam. `keyMaterial` is the user-held secret. Two paths:
//   - "raw-key" (agent callers): a 32-byte high-entropy key; HKDF-SHA256 with
//     the user salt derives the dedicated ledger AEAD subkey.
//   - "scrypt-provisional" (paddock/test): scrypt over passphrase-shaped
//     material with provisional parameters. The production human-user path is
//     Argon2id with Security-Agent-approved parameters — NOT IMPLEMENTED here.
// HKDF-SHA256 domain separation: the purpose string is bound into the key
// derivation, so identical input entropy can never produce the same key
// material in two domains. The key-separation property (P12 ledger keys
// distinct from receipt-signing and authority keys by construction) is
// asserted explicitly in the test suite via this exported pure function.
export const P12_KEY_DOMAIN = "p12-ledger-aead-v1";

export function derivePurposeKey(keyMaterial, saltHex, purpose) {
  if (typeof purpose !== "string" || purpose.trim() === "") throw new Error("purpose is required");
  const salt = Buffer.from(saltHex, "hex");
  if (salt.length !== P12_SALT_BYTES) throw new Error("salt must be 16 bytes hex");
  const material = Buffer.isBuffer(keyMaterial) ? keyMaterial : Buffer.from(keyMaterial, "hex");
  if (material.length !== KEY_BYTES) throw new Error("raw key material must be 32 bytes");
  return Buffer.from(hkdfSync("sha256", material, salt, purpose, KEY_BYTES));
}

function deriveLedgerKey(keyMaterial, saltHex, mode) {
  const salt = Buffer.from(saltHex, "hex");
  if (salt.length !== P12_SALT_BYTES) throw new Error("salt must be 16 bytes hex");
  if (mode === "raw-key") {
    return derivePurposeKey(keyMaterial, saltHex, P12_KEY_DOMAIN);
  }
  if (mode === "scrypt-provisional") {
    const material = Buffer.isBuffer(keyMaterial) ? keyMaterial : Buffer.from(String(keyMaterial), "utf8");
    return scryptSync(material, salt, KEY_BYTES, SCRYPT_PROVISIONAL);
  }
  throw new Error(`unknown kdf mode: ${mode}`);
}

// The AEAD associated data: the operator-readable metadata tuple. Any change
// to these fields after encryption breaks authentication (AEAD binding).
function associatedData({ entry_id, user_token, timestamp, status }) {
  return Buffer.from(canonicalize({ entry_id, user_token, timestamp, status }));
}

// Runs in the CALLER's process. Produces exactly the five operator-readable
// fields; the plaintext history detail never appears in the return value.
export function encryptHistoryEntry({
  plaintext,
  keyMaterial,
  kdfMode = "raw-key",
  saltHex,
  userToken,
  status = "stored",
  entryId = randomUUID(),
  timestamp = new Date().toISOString(),
}) {
  if (typeof plaintext !== "string" || plaintext === "") throw new Error("plaintext is required");
  if (!P12_STATUS_VOCABULARY.includes(status)) throw new Error(`status must be one of ${P12_STATUS_VOCABULARY.join(", ")}`);
  if (typeof userToken !== "string" || userToken === "") throw new Error("userToken is required");
  const key = deriveLedgerKey(keyMaterial, saltHex, kdfMode);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(associatedData({ entry_id: entryId, user_token: userToken, timestamp, status }));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    entry_id: entryId,
    user_token: userToken,
    timestamp,
    status,
    ciphertext_blob: Buffer.concat([nonce, tag, ciphertext]).toString("base64"),
  };
}

// Runs in the CALLER's process. Fails closed on any tampering with the blob
// or with the operator-readable metadata (AAD mismatch).
export function decryptHistoryEntry({ entry, keyMaterial, kdfMode = "raw-key", saltHex }) {
  for (const field of P12_OPERATOR_FIELDS) {
    if (typeof entry[field] !== "string" || entry[field] === "") throw new Error(`entry is missing field: ${field}`);
  }
  const blob = Buffer.from(entry.ciphertext_blob, "base64");
  if (blob.length <= NONCE_BYTES + 16) throw new Error("ciphertext blob is truncated");
  const nonce = blob.subarray(0, NONCE_BYTES);
  const tag = blob.subarray(NONCE_BYTES, NONCE_BYTES + 16);
  const ciphertext = blob.subarray(NONCE_BYTES + 16);
  const key = deriveLedgerKey(keyMaterial, saltHex, kdfMode);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(associatedData({ entry_id: entry.entry_id, user_token: entry.user_token, timestamp: entry.timestamp, status: entry.status }));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("ledger decryption failed");
  }
}

// Operator-side ciphertext store. Schema-enforced to the five fields; opt-in
// with a default of OFF on the public tier; retention enforced on metadata
// only (age/count over timestamps, never content); opt-out deletes both the
// ciphertext and the user's salt (the salt must not outlive the ledger).
export function createP12LedgerStore({
  optIn = false,
  maxEntriesPerUser = 1000,
  maxAgeMs = 365 * 24 * 60 * 60 * 1000,
  clock = () => new Date(),
} = {}) {
  const entries = new Map(); // user_token -> [{entry}, ...]
  const salts = new Map(); // user_token -> salt hex
  let optedIn = optIn === true;

  function assertEntryShape(entry) {
    if (!isObject(entry)) throw new Error("ledger entry must be an object");
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
    const now = clock().getTime();
    const kept = (entries.get(userToken) ?? []).filter((entry) => now - Date.parse(entry.timestamp) <= maxAgeMs);
    kept.splice(0, Math.max(0, kept.length - maxEntriesPerUser));
    entries.set(userToken, kept);
  }

  return {
    isOptedIn: () => optedIn,
    optIn() {
      optedIn = true;
    },
    optOut(userToken = null) {
      if (userToken === null) {
        entries.clear();
        salts.clear();
        optedIn = false;
        return;
      }
      entries.delete(userToken);
      salts.delete(userToken);
    },
    setSalt(userToken, saltHex) {
      if (typeof saltHex !== "string" || !/^[0-9a-f]{2,}$/.test(saltHex)) throw new Error("salt must be hex");
      if (salts.has(userToken) && salts.get(userToken) !== saltHex) {
        // A stable salt per ledger lifetime; a change means re-encryption of
        // the whole ledger, never a silent swap under old ciphertext.
        throw new Error("salt rotation requires ledger re-encryption");
      }
      salts.set(userToken, saltHex);
    },
    getSalt(userToken) {
      return salts.get(userToken) ?? null;
    },
    append(entry) {
      if (!optedIn) throw new Error("ledger is not enabled: user opt-in required");
      assertEntryShape(entry);
      const list = entries.get(entry.user_token) ?? [];
      if (list.some((existing) => existing.entry_id === entry.entry_id)) {
        throw new Error("entry_id must be unique within the user's ledger");
      }
      list.push({ ...entry });
      entries.set(entry.user_token, list);
      enforceRetention(entry.user_token);
    },
    listEntries(userToken) {
      return (entries.get(userToken) ?? []).map((entry) => ({ ...entry }));
    },
  };
}

// Digest helper for tests and future retention surfaces.
export function p12EntryReference(entry) {
  return createHash("sha256").update(canonicalize(entry)).digest("hex");
}
