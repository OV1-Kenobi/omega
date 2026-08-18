#!/usr/bin/env node

// Synthetic L-402 payment policy and authority boundary for the WP6 public
// source-summarization transport (the planning folder (phase-2
// summarization-feature, the implementation staging plan slice 3/4).
//
// SYNTHETIC PADDOCK ONLY. This module implements a local, deterministic,
// off-serving payment AUTHORITY plus the serving-side policy layer so the
// L-402 flow can be exercised and fail-closed tested without a live Lightning
// provider, real invoices, real wallet credentials, or any network egress. It
// does NOT claim live MDK conformance, bLIP-26 live conformance, or true
// macaroon caveat delegation: the "macaroon" is an authority-signed opaque
// token (an Ed25519 signature over the challenge fields), documented as such.
//
// Capability manifest (agent-and-skill-security-policy section 2):
//   - Files/dirs read or written: none. All state is in-memory (challenge and
//     entitlement maps inside the created objects).
//   - External network/services: none. node:crypto only; no http/https/net/dns
//     imports, no fetch, no WebSocket anywhere in this module.
//   - Accounts/credentials/tokens: the synthetic authority holds an Ed25519
//     keypair generated in-memory per instance (or injected); it never touches
//     a real wallet, node, NWC string, or OS credential store.
//   - Persistence/looping: none; objects live for the process lifetime.
//   - Rate/quota/challenge-bound state: in-memory fixed-window counters keyed
//     on opaque client identifiers (counts and window timestamps only).
//   - Upstream/downstream boundaries: the authority is consumed by the public
//     HTTP transport adapter (serving plane). The serving plane receives only
//     the authority PUBLIC key (verification), never the private key, so a
//     compromised serving path cannot mint challenges or substitute invoice
//     metadata (origin-binding evidence invoice-origin binding at paddock grade).
//   - Capacity for surprise/damage: no sats, no credentials, no content. The
//     entitlement store is schema-enforced to content-free fields only.
//
// Implemented HTTP status mapping on the protected path (PROVISIONAL; the
// approved documents leave the exact mapping Requires Verification — recorded
// here as the implemented behavior, not as an approved rule):
//   - no Authorization header            -> 402 + fresh challenge
//   - Authorization not "L402 a:b" shape -> 400 malformed_authorization
//   - token signature invalid            -> 400 invalid_payment_token
//   - challenge expired                  -> 402 + fresh challenge
//   - wrong preimage                     -> 402 + fresh challenge (no effect)
//   - valid proof, entitlement consumed  -> 402 + fresh challenge (replay)
//
// Record discipline (P10 strict ledger option, design section 4.10): the
// challenge/entitlement store keeps opaque ids, payment hash, sats, capability
// version, timestamps, and status ONLY. The invoice string and the signed
// token are returned to the caller in the 402 response and are never stored.

import {
  createHash,
  createHmac,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";

export const L402_AUTHORIZATION_PREFIX = "L402";
export const DEFAULT_CHALLENGE_VALIDITY_SECONDS = 15 * 60;

// The only fields an operator-side challenge/entitlement record may carry.
// Anything else (url, title, content, invoice, macaroon, preimage, ...) is
// rejected by schema enforcement — the negative path is covered by tests.
export const CHALLENGE_RECORD_FIELDS = [
  "challenge_id",
  "payment_hash",
  "amount_sats",
  "capability",
  "version",
  "client_id",
  "issued_at",
  "expires_at",
  "status",
  "redeemed_at",
];

const CHALLENGE_STATUSES = new Set(["issued", "redeemed", "expired"]);

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

export function sha256Hex(value) {
  return createHash("sha256").update(typeof value === "string" ? Buffer.from(value) : value).digest("hex");
}

// Opaque pseudonymous client identifier per PRD P10: HMAC-SHA256 over the
// caller-supplied opaque material, keyed with a server-side secret (a real
// keyed MAC, not a keyed-by-concatenation hash). The version prefix is
// message content, never key material. Never derived from request content;
// the material itself is never stored. Output keeps the original 32-hex-char
// format so callers and stored records remain format-compatible.
export function deriveOpaqueClientId(secret, material) {
  return createHmac("sha256", secret).update(`client-v1:${material}`).digest("hex").slice(0, 32);
}

// ---------------------------------------------------------------------------
// Synthetic payment authority (operator plane; off the serving path)
// ---------------------------------------------------------------------------

export function createSyntheticPaymentAuthority({
  ed25519KeyPair,
  clock = () => new Date(),
  validitySeconds = DEFAULT_CHALLENGE_VALIDITY_SECONDS,
  idFactory = () => randomUUID(),
} = {}) {
  const keyPair = ed25519KeyPair ?? generateKeyPairSync("ed25519");
  // Authority-side preimage custody: preimages never leave the authority
  // through issueChallenge; only settle() (the synthetic payer path that
  // models "the invoice was paid and the payer learned the preimage") reveals
  // one, keyed by challenge id. In production the payer learns the preimage
  // from the real Lightning network, never from the operator.
  const preimagesByChallengeId = new Map();

  function authoritySign(payload) {
    return edSign(null, Buffer.from(canonicalize(payload)), keyPair.privateKey);
  }

  function issueChallenge({ capability, version, amountSats, serviceIdentity, clientId = null }) {
    if (typeof capability !== "string" || capability.trim() === "") throw new Error("capability is required");
    if (typeof version !== "string" || version.trim() === "") throw new Error("version is required");
    if (!Number.isInteger(amountSats) || amountSats <= 0) throw new Error("amountSats must be a positive integer");
    const issuedAt = new Date(clock().getTime());
    const expiresAt = new Date(issuedAt.getTime() + validitySeconds * 1000);
    const challengeId = idFactory();
    const preimage = randomBytes(32);
    preimagesByChallengeId.set(challengeId, preimage);
    const paymentHash = sha256Hex(preimage);
    const payload = {
      challenge_id: challengeId,
      capability,
      version,
      amount_sats: amountSats,
      payment_hash: paymentHash,
      service_identity: serviceIdentity,
      client_id: clientId,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
    };
    const signature = authoritySign(payload);
    const token = Buffer.from(
      JSON.stringify({ l402_synthetic: "1", payload, signature: signature.toString("base64") }),
    ).toString("base64");
    // NOT a BOLT11 string. Real invoice encoding is provider-bound and remains
    // Requires Verification; the paddock invoice is an opaque synthetic value.
    const invoice = `SYNTHETIC-INVOICE-1:${randomBytes(16).toString("hex")}`;
    return {
      challenge: {
        challenge_id: challengeId,
        payment_hash: paymentHash,
        amount_sats: amountSats,
        capability,
        version,
        client_id: clientId,
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        status: "issued",
        redeemed_at: null,
      },
      macaroon: token,
      invoice,
    };
  }

  function settle(challengeId) {
    const preimage = preimagesByChallengeId.get(challengeId);
    if (preimage === undefined) throw new Error("unknown challenge id");
    return preimage.toString("hex");
  }

  return {
    issueChallenge,
    settle,
    publicKeyPem: keyPair.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function verifyChallengeToken(macaroon, authorityPublicKeyPem) {
  if (typeof macaroon !== "string" || macaroon === "") return { ok: false, reason: "invalid_payment_token" };
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(macaroon, "base64").toString("utf8"));
  } catch {
    return { ok: false, reason: "invalid_payment_token" };
  }
  if (!isObject(decoded) || decoded.l402_synthetic !== "1" || !isObject(decoded.payload)) {
    return { ok: false, reason: "invalid_payment_token" };
  }
  const payload = decoded.payload;
  const required = ["challenge_id", "capability", "version", "amount_sats", "payment_hash", "expires_at"];
  for (const field of required) {
    if (payload[field] === undefined) return { ok: false, reason: "invalid_payment_token" };
  }
  if (!/^[0-9a-f]{64}$/.test(payload.payment_hash)) return { ok: false, reason: "invalid_payment_token" };
  let valid;
  try {
    valid = edVerify(
      null,
      Buffer.from(canonicalize(payload)),
      authorityPublicKeyPem,
      Buffer.from(decoded.signature, "base64"),
    );
  } catch {
    return { ok: false, reason: "invalid_payment_token" };
  }
  if (!valid) return { ok: false, reason: "invalid_payment_token" };
  return { ok: true, payload };
}

// ---------------------------------------------------------------------------
// Serving-plane L-402 policy
// ---------------------------------------------------------------------------

export function parseAuthorizationHeader(value) {
  if (typeof value !== "string") return { ok: false, reason: "missing_authorization" };
  const trimmed = value.trim();
  if (trimmed === "") return { ok: false, reason: "missing_authorization" };
  const spaceAt = trimmed.indexOf(" ");
  if (spaceAt === -1 || trimmed.slice(0, spaceAt) !== L402_AUTHORIZATION_PREFIX) {
    return { ok: false, reason: "malformed_authorization" };
  }
  const credential = trimmed.slice(spaceAt + 1).trim();
  const separatorAt = credential.indexOf(":");
  if (separatorAt === -1) return { ok: false, reason: "malformed_authorization" };
  const macaroon = credential.slice(0, separatorAt);
  const preimageHex = credential.slice(separatorAt + 1);
  if (macaroon === "" || !/^[0-9a-f]{64}$/i.test(preimageHex)) {
    return { ok: false, reason: "malformed_authorization" };
  }
  return { ok: true, macaroon, preimageHex: preimageHex.toLowerCase() };
}

// Stateless proof check (design section 4.3): sha256(preimage) == the payment
// hash committed inside the authority-signed token. No store lookup happens
// before this comparison, and a failed check performs no side effect.
export function verifyL402Proof({ authorization, authorityPublicKeyPem, clock = () => new Date() }) {
  const parsed = parseAuthorizationHeader(authorization);
  if (!parsed.ok) return parsed;
  const token = verifyChallengeToken(parsed.macaroon, authorityPublicKeyPem);
  if (!token.ok) return token;
  const payload = token.payload;
  if (Date.parse(payload.expires_at) <= clock().getTime()) {
    return { ok: false, reason: "expired_challenge" };
  }
  if (sha256Hex(Buffer.from(parsed.preimageHex, "hex")) !== payload.payment_hash) {
    return { ok: false, reason: "preimage_mismatch" };
  }
  return {
    ok: true,
    challenge_id: payload.challenge_id,
    payment_hash: payload.payment_hash,
    amount_sats: payload.amount_sats,
    capability: payload.capability,
    version: payload.version,
    client_id: payload.client_id ?? null,
  };
}

// ---------------------------------------------------------------------------
// Content-free challenge/entitlement store (P10 strict ledger option)
// ---------------------------------------------------------------------------

export function createChallengeEntitlementStore() {
  const byChallengeId = new Map();
  const redeemedPaymentHashes = new Set();

  function assertContentFreeRecord(record) {
    if (!isObject(record)) throw new Error("challenge record must be an object");
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

  return {
    recordChallenge(challenge) {
      // Validate the INPUT record's own keys: a content-bearing field is
      // rejected, never silently dropped by an allowlist copy.
      if (!isObject(challenge)) throw new Error("challenge record must be an object");
      for (const key of Object.keys(challenge)) {
        if (!CHALLENGE_RECORD_FIELDS.includes(key)) {
          throw new Error(`challenge record carries a non-allowlisted field: ${key}`);
        }
      }
      const record = {};
      for (const field of CHALLENGE_RECORD_FIELDS) {
        if (challenge[field] !== undefined) record[field] = challenge[field];
      }
      // The store owns status transitions: a caller-supplied status must still
      // be a valid vocabulary value, then is normalized to "issued".
      if (record.status !== undefined && !CHALLENGE_STATUSES.has(record.status)) {
        throw new Error("challenge record has an invalid status");
      }
      record.status = "issued";
      record.redeemed_at = null;
      assertContentFreeRecord(record);
      if (byChallengeId.has(record.challenge_id)) throw new Error("challenge id already recorded");
      byChallengeId.set(record.challenge_id, record);
      return record;
    },
    // One-shot redemption: synchronous check-and-set on the Node event loop
    // makes exactly one caller the winner; every later or concurrent attempt
    // (a replay of the same proof) fails without a second entitlement.
    redeem(paymentHash) {
      if (redeemedPaymentHashes.has(paymentHash)) {
        return { ok: false, reason: "already_redeemed" };
      }
      redeemedPaymentHashes.add(paymentHash);
      for (const record of byChallengeId.values()) {
        if (record.payment_hash === paymentHash) {
          record.status = "redeemed";
          record.redeemed_at = new Date().toISOString();
        }
      }
      return { ok: true };
    },
    isRedeemed(paymentHash) {
      return redeemedPaymentHashes.has(paymentHash);
    },
    getChallenge(challengeId) {
      const record = byChallengeId.get(challengeId);
      return record ? { ...record } : null;
    },
    listRecords() {
      return [...byChallengeId.values()].map((record) => ({ ...record }));
    },
  };
}

// ---------------------------------------------------------------------------
// Per-client rate limiting, free-allowance quota, and challenge-issuance
// bounds (P5 abuse controls; wp4-exposure-readiness-qa.md section 7.10 makes
// them operative before alpha). All state is keyed on OPAQUE pseudonymous
// client identifiers — never on request content — and stores only counts and
// window timestamps: the same content-free record discipline as the
// challenge/entitlement store.
// ---------------------------------------------------------------------------

// Fallback bucket when a caller supplies no opaque client identifier. A single
// shared bucket keeps even header-less abuse bounded; per-client isolation
// applies wherever the identifier is present.
export const ANONYMOUS_CLIENT_BUCKET = "anonymous-shared-bucket";

// Fixed-window counter: deterministic under an injected clock, race-free on
// the Node event loop (synchronous check-and-increment), and content-free by
// construction. One generic mechanism serves request rate limiting, challenge
// issuance bounds, and free-allowance quota.
export function createFixedWindowLimiter({ max, windowMs, clock = () => new Date() } = {}) {
  if (!Number.isInteger(max) || max <= 0) throw new Error("max must be a positive integer");
  if (!Number.isInteger(windowMs) || windowMs <= 0) throw new Error("windowMs must be a positive integer");
  const buckets = new Map();

  function windowState(key, now) {
    let bucket = buckets.get(key);
    if (bucket === undefined || now - bucket.windowStart >= windowMs) {
      bucket = { windowStart: now, count: 0 };
      buckets.set(key, bucket);
    }
    return bucket;
  }

  function outcome(bucket, now, allowed) {
    const resetAtMs = bucket.windowStart + windowMs;
    return {
      allowed,
      count: bucket.count,
      max,
      remaining: Math.max(0, max - bucket.count),
      window_start: new Date(bucket.windowStart).toISOString(),
      reset_at: new Date(resetAtMs).toISOString(),
      retry_after_seconds: Math.max(1, Math.ceil((resetAtMs - now) / 1000)),
    };
  }

  return {
    // Consumes one slot when allowed; a denied check does not increment (the
    // caller stays denied until the window resets either way, so denial spam
    // cannot inflate or evade the counter).
    check(key) {
      if (typeof key !== "string" || key === "") throw new Error("limiter key must be a non-empty string");
      const now = clock().getTime();
      const bucket = windowState(key, now);
      if (bucket.count >= max) return outcome(bucket, now, false);
      bucket.count += 1;
      return outcome(bucket, now, true);
    },
    // Observes the window without consuming a slot.
    peek(key) {
      if (typeof key !== "string" || key === "") throw new Error("limiter key must be a non-empty string");
      const now = clock().getTime();
      const bucket = windowState(key, now);
      return outcome(bucket, now, bucket.count < max);
    },
    snapshot() {
      // Content-free inspection surface for tests and evidence: opaque keys,
      // counts, window starts — nothing else.
      return [...buckets.entries()].map(([key, bucket]) => ({
        key,
        count: bucket.count,
        window_start: new Date(bucket.windowStart).toISOString(),
      }));
    },
  };
}

export function createRateLimiter({ maxRequests, windowMs, clock } = {}) {
  return createFixedWindowLimiter({ max: maxRequests, windowMs, clock });
}

export function createQuotaTracker({ maxOperations, windowMs, clock } = {}) {
  return createFixedWindowLimiter({ max: maxOperations, windowMs, clock });
}

export function challengeHttpResponse(challenge, macaroon, invoice) {
  return {
    status: 402,
    headers: {
      "WWW-Authenticate": `L402 macaroon="${macaroon}", invoice="${invoice}"`,
    },
  };
}
