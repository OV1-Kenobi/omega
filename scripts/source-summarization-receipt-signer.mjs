#!/usr/bin/env node

// Off-serving receipt signer for the WP6 public tier (receipt-signing custody).
//
// This process runs in the OPERATOR plane, separate from the public serving
// process. It alone opens the service signing identity (the same DPAPI-backed
// credential-store signer used by the local V1 stdio server, so one npub binds
// artifacts, receipts, and the future M9 catalog record). The public serving
// process never imports this module; it reaches this process only through the
// authenticated named-pipe request path implemented here and in
// source-summarization-receipt.mjs.
//
// SYNTHETIC/LOCAL-GRADE AUTHENTICATION: the request channel is authenticated
// with a per-boot HMAC secret shared with the serving process (boot-secret
// file or injected value). Windows named pipes created by this process carry
// the creating user's default discretionary ACL; the HMAC layer adds explicit
// request authentication on top. OS-level peer-identity verification (pipe
// client process identity) is not available in the Node standard library, so
// production custody hardening of this channel remains a Security-Agent /
// DevOps verification item before any exposure. This module is the paddock
// implementation of the boundary, not the final custody decision.
//
// Capability manifest (agent-and-skill-security-policy section 2):
//   - Files/dirs read: the signer key store under
//     %APPDATA%\Omega Dev\source-summarization\signer.key (or
//     OMEGA_SOURCE_SUMMARIZATION_SIGNER_DIR), via the V1 DPAPI store; when
//     run with --auth-secret-file, that one file (read once at boot).
//   - Files/dirs written: none (the boot-secret file is produced by the
//     operator harness, not by this process).
//   - Network: node:net ONLY, listening on one local named pipe. No TCP/DNS/
//     http/fetch; no remote destination.
//   - Credentials: the service signing key (opened lazily from the protected
//     store inside this process only) and the per-boot request-auth secret.
//     Neither is ever logged or returned; responses carry only the signature
//     and the public service npub.
//   - Persistence/looping: a long-running pipe listener with a bounded replay
//     cache; no other state.
//   - Boundaries: accepts authenticated requests from the local serving
//     process; enforces a purpose allowlist; never accepts raw source content,
//     URLs, titles, invoices, preimages, macaroons, or payout destinations.
//   - Failure behavior: unauthenticated, replayed, out-of-allowlist, or
//     malformed requests are rejected without signing; signer-store failures
//     fail closed.
//
// Wire protocol: see source-summarization-receipt.mjs (the client half).

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:net";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { createCredentialStoreSigner } from "./source-summarization-signer.mjs";
import { assertReceiptShape, receiptDigest } from "./source-summarization-receipt.mjs";

const MAX_WIRE_LINE_BYTES = 1024 * 1024;
const DEFAULT_REPLAY_WINDOW_MS = 10 * 60 * 1000;

// Artifact digests are content-free 32-byte values; allowing the serving
// process to obtain signatures for them under a distinct purpose preserves the
// V1 signed-artifact contract on the public transport without exposing the
// key. "sign_receipt" is the only purpose enabled by default; "artifact_sign"
// must be enabled explicitly by the operator configuration.
export const SIGNER_PURPOSES = new Set(["sign_receipt", "artifact_sign"]);

function hmacHex(secret, value) {
  return createHmac("sha256", secret).update(value).digest("hex");
}

function safeEqualHex(a, b) {
  const bufferA = Buffer.from(String(a));
  const bufferB = Buffer.from(String(b));
  return bufferA.length === bufferB.length && timingSafeEqual(bufferA, bufferB);
}

export function createReceiptSignerService({
  signer,
  pipePath,
  authSecret,
  allowedPurposes = ["sign_receipt"],
  clock = () => new Date(),
  replayWindowMs = DEFAULT_REPLAY_WINDOW_MS,
}) {
  if (!signer || typeof signer.sign !== "function") throw new Error("a signer is required");
  if (typeof pipePath !== "string" || pipePath === "") throw new Error("pipePath is required");
  if (typeof authSecret !== "string" || authSecret === "") throw new Error("authSecret is required");
  const purposes = new Set(allowedPurposes);
  for (const purpose of purposes) {
    if (!SIGNER_PURPOSES.has(purpose)) throw new Error(`unknown signer purpose: ${purpose}`);
  }

  const seenRequestIds = new Map();

  function reject(socket, code) {
    socket.write(`${JSON.stringify({ ok: false, error: code })}\n`);
  }

  const server = createServer((socket) => {
    let buffer = "";
    let authenticated = false;
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      if (buffer.length > MAX_WIRE_LINE_BYTES) {
        socket.destroy();
        return;
      }
      let newlineAt = buffer.indexOf("\n");
      while (newlineAt !== -1) {
        const line = buffer.slice(0, newlineAt);
        buffer = buffer.slice(newlineAt + 1);
        let message;
        try {
          message = JSON.parse(line);
        } catch {
          reject(socket, "malformed_request");
          continue;
        }
        handleLine(socket, message);
        newlineAt = buffer.indexOf("\n");
      }
    });
    socket.on("error", () => socket.destroy());

    function handleLine(socket, message) {
      if (!authenticated) {
        const nonce = handshakeNonce;
        handshakeNonce = null;
        if (typeof message.mac !== "string" || nonce === null || !safeEqualHex(message.mac, hmacHex(authSecret, nonce))) {
          reject(socket, "authentication_failed");
          socket.end();
          return;
        }
        authenticated = true;
        return;
      }
      const purpose = message.op;
      if (!purposes.has(purpose)) {
        reject(socket, "purpose_not_allowed");
        return;
      }
      if (typeof message.request_id !== "string" || message.request_id === "") {
        reject(socket, "request_id_required");
        return;
      }
      const now = clock().getTime();
      for (const [seenId, seenAt] of seenRequestIds) {
        if (now - seenAt > replayWindowMs) seenRequestIds.delete(seenId);
      }
      if (seenRequestIds.has(message.request_id)) {
        reject(socket, "replayed_request");
        return;
      }
      seenRequestIds.set(message.request_id, now);
      if (purpose === "sign_receipt") {
        void (async () => {
          try {
            assertReceiptShape(message.receipt);
          } catch (error) {
            reject(socket, "invalid_receipt");
            return;
          }
          try {
            const signed = await signer.sign({ artifact_digest: receiptDigest(message.receipt) });
            socket.write(
              `${JSON.stringify({ ok: true, signature: signed.publisher_signature, service_identity: signed.publisher_npub })}\n`,
            );
          } catch {
            reject(socket, "signer_unavailable");
          }
        })();
        return;
      }
      if (purpose === "artifact_sign") {
        void (async () => {
          const digest = message.artifact_digest;
          if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) {
            reject(socket, "invalid_digest");
            return;
          }
          try {
            const signed = await signer.sign({ artifact_digest: digest });
            socket.write(
              `${JSON.stringify({ ok: true, signature: signed.publisher_signature, service_identity: signed.publisher_npub })}\n`,
            );
          } catch {
            reject(socket, "signer_unavailable");
          }
        })();
      }
    }

    // Per-connection handshake nonce, issued immediately on connect and
    // consumed exactly once by the client's first authenticated line.
    let handshakeNonce = randomBytes(24).toString("hex");
    socket.write(`${JSON.stringify({ nonce: handshakeNonce })}\n`);
  });

  return {
    pipePath,
    listen() {
      return new Promise((resolvePromise, rejectPromise) => {
        server.once("error", rejectPromise);
        server.listen(pipePath, () => resolvePromise());
      });
    },
    async close() {
      await new Promise((resolvePromise) => server.close(() => resolvePromise()));
    },
  };
}

async function main() {
  const args = process.argv.slice(2);
  const optionAt = (name) => {
    const index = args.indexOf(name);
    return index === -1 ? null : args[index + 1];
  };
  const pipePath = optionAt("--pipe");
  const authSecretFile = optionAt("--auth-secret-file");
  const purposes = (optionAt("--purposes") ?? "sign_receipt").split(",");
  if (!pipePath || !authSecretFile) {
    process.stderr.write("usage: node source-summarization-receipt-signer.mjs --pipe <path> --auth-secret-file <path> [--purposes sign_receipt,artifact_sign]\n");
    process.exitCode = 2;
    return;
  }
  const authSecret = (await readFile(authSecretFile, "utf8")).trim();
  const signer = createCredentialStoreSigner();
  const service = createReceiptSignerService({ signer, pipePath, authSecret, allowedPurposes: purposes });
  await service.listen();
  process.stdout.write(`receipt-signer-listening ${pipePath}\n`);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) await main();
