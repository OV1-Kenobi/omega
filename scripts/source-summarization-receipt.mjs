#!/usr/bin/env node

// Canonical receipt contract and the serving-plane receipt-signer client for
// the WP6 public tier (receipt-signing custody remediation, the implementation staging plan
// plan.md slice 5).
//
// TRUST BOUNDARY: this module is imported by the PUBLIC SERVING process. It
// therefore contains no key-store code: it imports only the pure BIP-340
// verification math and the npub decoder from source-summarization-signer.mjs
// (functions that never touch the credential store), and its client speaks to
// the off-serving receipt signer over an authenticated local named pipe. The
// serving process never loads, holds, or can load the service signing key.
//
// Capability manifest (agent-and-skill-security-policy section 2):
//   - Files/dirs: none read or written by this module.
//   - Network: node:net ONLY, and only to a local named-pipe path supplied by
//     the caller. No TCP/DNS/http/fetch. No remote destination exists.
//   - Credentials: the client holds a per-boot HMAC request-auth secret (a
//     REQUEST credential, not a signing key). It never sees key material.
//   - Persistence: none.
//   - Boundaries: serving plane -> off-serving receipt signer (operator
//     plane) over authenticated local IPC; responses are verified against the
//     pinned service npub before use.
//   - Failure behavior: connect/timeout/auth failures fail closed with typed
//     errors; no receipt is ever issued without a verified signature.
//
// Receipt content rule (PRD P4): a receipt carries payment/entitlement facts
// only — receipt identity, capability/version, amount in sats, payment hash,
// opaque client identifier, service operator identity, validity window. It
// never carries the source URL, title, content, summary, excerpt, raw
// invoice, preimage, macaroon, NWC string, node credential, or P12 key. The
// field list below is exhaustive and schema-enforced.

import { createHash, createHmac, randomBytes } from "node:crypto";
import { connect } from "node:net";

import { npubToPublicKeyHex, schnorrVerify } from "./source-summarization-signer.mjs";

export const RECEIPT_FIELDS = [
  "receipt_id",
  "capability",
  "version",
  "amount_sats",
  "payment_hash",
  "client_id",
  "service_identity",
  "issued_at",
  "valid_until",
];

const HEX_64 = /^[0-9a-f]{64}$/;

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

export function assertReceiptShape(receipt) {
  if (!isObject(receipt)) throw new Error("receipt must be an object");
  for (const key of Object.keys(receipt)) {
    if (!RECEIPT_FIELDS.includes(key)) {
      throw new Error(`receipt carries a non-allowlisted field: ${key}`);
    }
  }
  for (const field of ["receipt_id", "capability", "version", "service_identity", "issued_at", "valid_until"]) {
    if (typeof receipt[field] !== "string" || receipt[field].trim() === "") {
      throw new Error(`receipt field is missing or invalid: ${field}`);
    }
  }
  if (!Number.isInteger(receipt.amount_sats) || receipt.amount_sats <= 0) {
    throw new Error("receipt amount_sats must be a positive integer");
  }
  if (typeof receipt.payment_hash !== "string" || !HEX_64.test(receipt.payment_hash)) {
    throw new Error("receipt payment_hash must be a sha-256 hex digest");
  }
  if (Number.isNaN(Date.parse(receipt.issued_at)) || Number.isNaN(Date.parse(receipt.valid_until))) {
    throw new Error("receipt validity timestamps are invalid");
  }
}

export function receiptDigest(receipt) {
  assertReceiptShape(receipt);
  return createHash("sha256").update(canonicalize(receipt)).digest("hex");
}

// Public verification of a receipt signature against the durable service
// identity. Uses only public data: the receipt body, the signature, and the
// pinned service npub.
export function verifyReceiptSignature(receipt, signatureHex, serviceNpub) {
  try {
    assertReceiptShape(receipt);
  } catch {
    return false;
  }
  if (typeof signatureHex !== "string" || !/^[0-9a-f]{128}$/i.test(signatureHex)) return false;
  if (receipt.service_identity !== serviceNpub) return false;
  return schnorrVerify(
    Buffer.from(receiptDigest(receipt), "hex"),
    Buffer.from(npubToPublicKeyHex(serviceNpub), "hex"),
    Buffer.from(signatureHex.toLowerCase(), "hex"),
  );
}

// ---------------------------------------------------------------------------
// Serving-plane client: authenticated named-pipe request to the off-serving
// receipt signer. Wire protocol (newline-delimited JSON):
//   server -> client : {"nonce":"<hex>"}
//   client -> server : {"mac":"<hex hmac-sha256(secret, nonce)>"}
//   client -> server : {"op":"sign_receipt","request_id":"...","receipt":{...}}
//   server -> client : {"ok":true,"signature":"<hex>","service_identity":"npub..."}
// ---------------------------------------------------------------------------

const CLIENT_CONNECT_TIMEOUT_MS = 5000;
const CLIENT_REQUEST_TIMEOUT_MS = 10000;
const MAX_WIRE_LINE_BYTES = 1024 * 1024;

export function receiptSignerPipePath(suffix = "default") {
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\omega-ss-receipt-signer-${suffix}`;
  }
  // Non-Windows hosts use Unix-domain sockets in the temp dir (the plan's
  // fallback primitive for hosts without named pipes).
  return `/tmp/omega-ss-receipt-signer-${suffix}.sock`;
}

export class ReceiptSignerClient {
  constructor({ pipePath, authSecret, expectedServiceNpub, connectTimeoutMs = CLIENT_CONNECT_TIMEOUT_MS }) {
    if (typeof pipePath !== "string" || pipePath === "") throw new Error("pipePath is required");
    if (typeof authSecret !== "string" || authSecret === "") throw new Error("authSecret is required");
    if (typeof expectedServiceNpub !== "string" || expectedServiceNpub === "") {
      throw new Error("expectedServiceNpub is required");
    }
    this.pipePath = pipePath;
    this.authSecret = authSecret;
    this.expectedServiceNpub = expectedServiceNpub;
    this.connectTimeoutMs = connectTimeoutMs;
  }

  async requestSignature(receipt, { requestId } = {}) {
    assertReceiptShape(receipt);
    return this.request({ op: "sign_receipt", receipt }, {
      requestId,
      verifyResponse: (message) => {
        if (!verifyReceiptSignature(receipt, message.signature, this.expectedServiceNpub)) {
          throw new Error("signature verification failed");
        }
        return { signature: message.signature, service_identity: message.service_identity };
      },
    });
  }

  // Artifact digests are content-free 32-byte values. Signing them under the
  // distinct "artifact_sign" purpose lets the public transport preserve the V1
  // signed-artifact contract without any local key operation.
  async requestArtifactSignature(artifactDigestHex, { requestId } = {}) {
    if (typeof artifactDigestHex !== "string" || !/^[0-9a-f]{64}$/.test(artifactDigestHex)) {
      return Promise.reject(new Error("artifact digest must be a sha-256 hex digest"));
    }
    return this.request({ op: "artifact_sign", artifact_digest: artifactDigestHex }, {
      requestId,
      verifyResponse: (message) => {
        const valid = schnorrVerify(
          Buffer.from(artifactDigestHex, "hex"),
          Buffer.from(npubToPublicKeyHex(this.expectedServiceNpub), "hex"),
          Buffer.from(message.signature, "hex"),
        );
        if (!valid) throw new Error("signature verification failed");
        return { signature: message.signature, service_identity: message.service_identity };
      },
    });
  }

  request(payload, { requestId, verifyResponse } = {}) {
    const requestIdValue = requestId ?? randomBytes(16).toString("hex");
    return new Promise((resolvePromise, rejectPromise) => {
      const socket = connect(this.pipePath);
      let buffer = "";
      let authenticated = false;
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(connectTimer);
        clearTimeout(requestTimer);
        socket.destroy();
        if (error) rejectPromise(error);
        else resolvePromise(value);
      };
      const connectTimer = setTimeout(() => {
        finish(new Error("receipt signer connection timed out"));
      }, this.connectTimeoutMs);
      let requestTimer = null;
      socket.on("connect", () => {
        clearTimeout(connectTimer);
      });
      socket.on("error", (error) => {
        finish(new Error(`receipt signer unreachable: ${error.code ?? "error"}`));
      });
      socket.setEncoding("utf8");
      socket.on("data", (chunk) => {
        buffer += chunk;
        if (buffer.length > MAX_WIRE_LINE_BYTES) {
          finish(new Error("receipt signer response exceeded the bounded wire size"));
          return;
        }
        let newlineAt = buffer.indexOf("\n");
        while (newlineAt !== -1) {
          const lineText = buffer.slice(0, newlineAt);
          buffer = buffer.slice(newlineAt + 1);
          let line;
          try {
            line = JSON.parse(lineText);
          } catch {
            finish(new Error("receipt signer sent a malformed line"));
            return;
          }
          if (!authenticated) {
            if (typeof line.nonce !== "string") {
              finish(new Error("receipt signer handshake was malformed"));
              return;
            }
            const mac = createHmac("sha256", this.authSecret).update(line.nonce).digest("hex");
            socket.write(`${JSON.stringify({ mac })}\n`);
            socket.write(`${JSON.stringify({ ...payload, request_id: requestIdValue })}\n`);
            authenticated = true;
            requestTimer = setTimeout(() => {
              finish(new Error("receipt signer request timed out"));
            }, CLIENT_REQUEST_TIMEOUT_MS);
            return;
          }
          clearTimeout(requestTimer);
          if (line.ok !== true || typeof line.signature !== "string" || typeof line.service_identity !== "string") {
            const code = typeof line.error === "string" ? line.error : "signer_rejected";
            finish(new Error(code));
            return;
          }
          if (line.service_identity !== this.expectedServiceNpub) {
            finish(new Error("signer identity mismatch"));
            return;
          }
          try {
            finish(null, verifyResponse(line));
          } catch (error) {
            finish(error);
          }
          return;
        }
      });
    });
  }
}

// V1 `signer` contract adapter for the public transport. Signing is forwarded
// to the off-serving signer over the authenticated pipe (artifact_sign
// purpose); verification is pure public-key math against the pinned service
// npub and runs locally. No path from this adapter to any key store exists.
export function createRemoteArtifactSigner({ client, serviceNpub }) {
  if (!client || typeof client.requestArtifactSignature !== "function") throw new Error("client is required");
  if (typeof serviceNpub !== "string" || serviceNpub === "") throw new Error("serviceNpub is required");
  const servicePublicKeyHex = npubToPublicKeyHex(serviceNpub);
  return {
    publisher_npub: serviceNpub,
    async sign({ artifact_digest }) {
      const response = await client.requestArtifactSignature(artifact_digest);
      return { publisher_signature: response.signature, publisher_npub: response.service_identity };
    },
    async verify({ artifact_digest, publisher_signature, publisher_npub }) {
      // Same-identity rule carried from the local signer: a foreign npub is
      // rejected even with a mathematically valid foreign signature.
      if (publisher_npub !== serviceNpub) return false;
      if (typeof publisher_signature !== "string" || !/^[0-9a-f]{128}$/i.test(publisher_signature)) return false;
      if (typeof artifact_digest !== "string" || !/^[0-9a-f]{64}$/i.test(artifact_digest)) return false;
      return schnorrVerify(
        Buffer.from(artifact_digest.toLowerCase(), "hex"),
        Buffer.from(servicePublicKeyHex, "hex"),
        Buffer.from(publisher_signature.toLowerCase(), "hex"),
      );
    },
  };
}
