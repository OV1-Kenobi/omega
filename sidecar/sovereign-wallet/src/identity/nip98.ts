//! NIP-98 HTTP Authentication (kind 27235) — construct + verify (WP-4).
//!
//! Faithful port of satnam-v0.2 `src/lib/nip98/{construct,verify}.ts` using the
//! noble crypto primitives already installed (no `nostr-tools` dependency).
//! NIP-98 replaces signed-token auth (kind 27235) on the sidecar's
//! authenticated HTTP surfaces.
//!
//! - `Authorization: Nostr <base64-of-signed-event-JSON>`
//! - tags: `u` (exact URL), `method` (HTTP method), `payload` (SHA-256 of body
//!   for POST/PUT/PATCH).
//! - kind 27235, ±60 s clock skew.
//! - Replay-safe: the verifier returns the event `id` (`eventId`); callers dedupe
//!   on it (satnam H-2 fix).

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { schnorr } from "@noble/curves/secp256k1.js";

const NIP98_KIND = 27235;
const CLOCK_SKEW_TOLERANCE_S = 60;
const DELEGATION_TAG = "delegation";
const BODY_METHODS = new Set(["POST", "PUT", "PATCH"]);

interface SignedEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface AuthResult {
  readonly authenticated: true;
  readonly pubkey: string;
  readonly eventId?: string;
  readonly delegatedBy?: string;
  readonly delegationConditions?: string;
}

export interface AuthError {
  readonly authenticated: false;
  readonly reason:
    | "missing_header"
    | "invalid_scheme"
    | "decode_failed"
    | "wrong_kind"
    | "expired"
    | "url_mismatch"
    | "method_mismatch"
    | "payload_mismatch"
    | "invalid_signature"
    | "delegation_invalid";
}

export type AuthOutcome = AuthResult | AuthError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function safeBase64Decode(encoded: string): Uint8Array | null {
  try {
    return new Uint8Array(Buffer.from(encoded, "base64"));
  } catch {
    return null;
  }
}

function hashBody(body: Uint8Array): string {
  return bytesToHex(sha256(body));
}

/** NIP-01 canonical serialization → SHA-256 event id. */
function computeEventId(event: {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}): string {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
  return bytesToHex(sha256(utf8ToBytes(serialized)));
}

function findTag(tags: string[][], name: string): string[] | null {
  return tags.find((t) => t[0] === name) ?? null;
}

function verifyEventSignature(event: SignedEvent): boolean {
  try {
    const expectedId = computeEventId(event);
    if (expectedId !== event.id) return false;
    return schnorr.verify(hexToBytes(event.sig), hexToBytes(event.id), hexToBytes(event.pubkey));
  } catch {
    return false;
  }
}

function verifyEventSatisfiesConditions(event: { created_at: number; kind: number }, conditions: string): boolean {
  if (!conditions || conditions.trim() === "") return true;
  const parts = conditions.split("&");
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("kind=")) {
      const allowedKind = parseInt(trimmed.slice("kind=".length), 10);
      if (Number.isNaN(allowedKind) || event.kind !== allowedKind) return false;
    } else if (trimmed.startsWith("created_at<")) {
      const maxTs = parseInt(trimmed.slice("created_at<".length), 10);
      if (Number.isNaN(maxTs) || event.created_at >= maxTs) return false;
    } else if (trimmed.startsWith("created_at>")) {
      const minTs = parseInt(trimmed.slice("created_at>".length), 10);
      if (Number.isNaN(minTs) || event.created_at <= minTs) return false;
    } else {
      return false; // unknown conditions are treated as unsatisfied (strict)
    }
  }
  return true;
}

function verifyDelegationTag(
  event: SignedEvent,
  delegationTag: string[],
): { delegatorPubkey: string; conditions: string } | null {
  if (delegationTag.length < 4) return null;
  const delegatorPubkey = delegationTag[1];
  const conditions = delegationTag[2];
  const delegationSig = delegationTag[3];
  if (!delegatorPubkey || !conditions || !delegationSig) return null;

  const token = `nostr:delegation:${event.pubkey}:${conditions}`;
  const tokenHash = sha256(utf8ToBytes(token));
  try {
    if (!schnorr.verify(hexToBytes(delegationSig), tokenHash, hexToBytes(delegatorPubkey))) {
      return null;
    }
  } catch {
    return null;
  }
  if (!verifyEventSatisfiesConditions(event, conditions)) return null;
  return { delegatorPubkey, conditions };
}

// ---------------------------------------------------------------------------
// Construct
// ---------------------------------------------------------------------------

/**
 * Construct and sign a NIP-98 auth event, returning the base64-encoded signed
 * event JSON for use as `Authorization: Nostr <returned>`.
 *
 * @param secret - 32-byte secret key
 * @param targetUrl - the exact URL (must match server-side `u` tag)
 * @param httpMethod - e.g. GET/POST/PUT/PATCH
 * @param requestBody - body bytes; a `payload` tag is added for POST/PUT/PATCH
 */
export function constructNip98Event(
  secret: Uint8Array,
  targetUrl: string,
  httpMethod: string,
  requestBody?: Uint8Array,
): string {
  const pubkey = bytesToHex(schnorr.getPublicKey(secret));
  const tags: string[][] = [
    ["u", targetUrl],
    ["method", httpMethod.toUpperCase()],
  ];
  const upperMethod = httpMethod.toUpperCase();
  if (BODY_METHODS.has(upperMethod) && requestBody && requestBody.length > 0) {
    tags.push(["payload", hashBody(requestBody)]);
  }

  const unsigned = {
    pubkey,
    created_at: Math.floor(Date.now() / 1000),
    kind: NIP98_KIND,
    tags,
    content: "",
  };
  const id = computeEventId(unsigned);
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secret));
  const signed: SignedEvent = { ...unsigned, id, sig };
  return toBase64(utf8ToBytes(JSON.stringify(signed)));
}

/** Build the full `Authorization: Nostr <base64>` header value. */
export function buildNip98AuthHeader(
  secret: Uint8Array,
  targetUrl: string,
  httpMethod: string,
  requestBody?: Uint8Array,
): string {
  return `Nostr ${constructNip98Event(secret, targetUrl, httpMethod, requestBody)}`;
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/**
 * Verify a NIP-98 `Authorization` header. Returns an AuthOutcome — either
 * authenticated (with the signer pubkey and replay-safe eventId) or a typed
 * rejection reason. No key material or internal paths appear in the reason.
 */
export function verifyNip98(
  authHeader: string | undefined | null,
  requestUrl: string,
  httpMethod: string,
  requestBody?: Uint8Array,
): AuthOutcome {
  if (!authHeader || authHeader.trim() === "") {
    return { authenticated: false, reason: "missing_header" };
  }
  const trimmed = authHeader.trim();
  if (!trimmed.startsWith("Nostr ")) {
    return { authenticated: false, reason: "invalid_scheme" };
  }
  const base64Part = trimmed.slice("Nostr ".length).trim();
  const eventBytes = safeBase64Decode(base64Part);
  if (!eventBytes) return { authenticated: false, reason: "decode_failed" };

  let event: SignedEvent;
  try {
    event = JSON.parse(new TextDecoder().decode(eventBytes)) as SignedEvent;
  } catch {
    return { authenticated: false, reason: "decode_failed" };
  }

  if (event.kind !== NIP98_KIND) return { authenticated: false, reason: "wrong_kind" };

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(event.created_at - now) > CLOCK_SKEW_TOLERANCE_S) {
    return { authenticated: false, reason: "expired" };
  }

  const uTag = findTag(event.tags, "u");
  if (!uTag || uTag[1] !== requestUrl) return { authenticated: false, reason: "url_mismatch" };

  const methodTag = findTag(event.tags, "method");
  if (!methodTag || methodTag[1]?.toUpperCase() !== httpMethod.toUpperCase()) {
    return { authenticated: false, reason: "method_mismatch" };
  }

  const payloadTag = findTag(event.tags, "payload");
  if (requestBody && requestBody.length > 0) {
    if (!payloadTag || !payloadTag[1]) return { authenticated: false, reason: "payload_mismatch" };
    if (payloadTag[1] !== hashBody(requestBody)) return { authenticated: false, reason: "payload_mismatch" };
  } else if (payloadTag) {
    if (payloadTag[1] !== hashBody(new Uint8Array(0))) return { authenticated: false, reason: "payload_mismatch" };
  }

  if (!verifyEventSignature(event)) return { authenticated: false, reason: "invalid_signature" };

  const delegationTag = findTag(event.tags, DELEGATION_TAG);
  if (delegationTag) {
    const delegationResult = verifyDelegationTag(event, delegationTag);
    if (!delegationResult) return { authenticated: false, reason: "delegation_invalid" };
    return {
      authenticated: true,
      pubkey: event.pubkey,
      eventId: event.id,
      delegatedBy: delegationResult.delegatorPubkey,
      delegationConditions: delegationResult.conditions,
    };
  }

  return { authenticated: true, pubkey: event.pubkey, eventId: event.id };
}
