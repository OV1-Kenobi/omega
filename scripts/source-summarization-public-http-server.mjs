#!/usr/bin/env node

// Public HTTP(S) MCP transport adapter for the Omega source-summarization
// capability (WP6; the implementation staging plan slice 2; PRD M7/P1;
// wp6-public-l402-gate.md section 4).
//
// BOUNDARY SUMMARY
//   - Reuses the V1 tool core (createServer from source-summarization-mcp.mjs)
//     behind a new transport binding; it adds public POLICY, not a second
//     interpretation of the tool contract.
//   - HTTPS-only at the public edge: constructing the server without TLS
//     material throws unless the explicitly named paddock mode
//     `plaintextLoopbackPaddock` is set, and that mode refuses to bind any
//     host except 127.0.0.1. The L402 Authorization header must never cross a
//     plaintext public listener.
//   - Public tool allowlist: only the stateless computation surface
//     (summarize_source, ask_source, export_source_analysis restricted to
//     caller-held artifacts) is exposed. The local-library tools
//     (save/get/list) are rejected BEFORE dispatch, and the V1 core is
//     constructed with a rejecting bridge stub so a bug in the allowlist still
//     cannot reach the local LMDB library bridge (boundary isolation).
//   - No egress: this module opens LISTENING sockets only (node:http/https
//     server). It imports no client fetch/TCP code; provider/invoice material
//     arrives through the injected synthetic authority; signatures through the
//     authenticated local IPC client.
//   - Key custody (receipt-signing custody): this module never loads a signing key. It
//     imports no credential-store code; artifact signatures and receipt
//     signatures are obtained from the off-serving receipt signer through
//     source-summarization-receipt.mjs (client) and verified against the
//     pinned service npub.
//   - Abuse controls (P5): per-client request rate limiting, bounded challenge
//     issuance, and an optional free-allowance quota, all keyed on opaque
//     client identifiers (never content) with constructor-configurable
//     thresholds; defaults documented at the limiter construction below.
//   - Stateless public tier (P11): caller content is processed in memory and
//     returned; nothing about the request content is persisted. The only
//     operator-side records are the content-free challenge/entitlement store
//     and the operation log below.
//
// Implemented MCP surface (recorded; streaming/SSE is NOT implemented):
//   POST <path> with a single JSON-RPC 2.0 request (batches are rejected with
//   -32600); initialize, ping, tools/list (filtered to the public allowlist),
//   tools/call. GET /health returns non-sensitive readiness state.
//
// Capability manifest (agent-and-skill-security-policy section 2):
//   - Files/dirs: none read or written.
//   - Network: one LISTENING socket (TLS when configured; loopback-only
//     plaintext in the named paddock mode). No outbound connections.
//   - Credentials: none held. The L402 Authorization header is consumed for
//     verification and never logged or echoed. A server-side client-id
//     derivation secret is received at construction and used only as the HMAC
//     key for deriveOpaqueClientId; the raw x-opaque-client-id header is never
//     used as identity, stored, or logged.
//   - Persistence: the challenge/entitlement store is injected at construction
//     (in-memory in the paddock/tests; the durable SQLite store at staging) —
//     there is no silent in-memory default. The operation log is in-memory.
//   - Boundaries: public callers -> this adapter -> V1 tool core (in memory);
//     adapter -> off-serving receipt signer over authenticated local IPC;
//     adapter -> injected synthetic payment authority (in-process paddock).
//   - Failure: every payment-path failure fails closed (no entitlement, no
//     receipt, no tool execution); errors are bounded and content-free.

import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { randomUUID } from "node:crypto";

import {
  MAX_SOURCE_CONTENT_BYTES,
  PROTOCOL_VERSION,
  SERVER_NAME,
  SERVER_VERSION,
  TOOLS,
  createServer as createV1Server,
} from "./source-summarization-mcp.mjs";
import {
  ANONYMOUS_CLIENT_BUCKET,
  challengeHttpResponse,
  createFixedWindowLimiter,
  createSyntheticPaymentAuthority,
  deriveOpaqueClientId,
  verifyL402Proof,
} from "./source-summarization-l402.mjs";
import { RECEIPT_FIELDS } from "./source-summarization-receipt.mjs";

export const PUBLIC_MCP_PATH_DEFAULT = "/mcp";
export const PUBLIC_HEALTH_PATH = "/health";
export const PUBLIC_TOOL_ALLOWLIST = ["summarize_source", "ask_source", "export_source_analysis"];
const LIBRARY_TOOLS = ["save_source_analysis", "get_saved_analysis", "list_saved_analyses"];
const MAX_REQUEST_BYTES = MAX_SOURCE_CONTENT_BYTES + 128 * 1024;
const DEFAULT_RECEIPT_VALIDITY_SECONDS = 3600;
const V1_TOOL_NAMES = new Set(TOOLS.map((tool) => tool.name));

// JSON-RPC error codes for the payment boundary (transport-level; recorded as
// the implemented mapping, Requires Verification against the final protocol).
const JSONRPC_PAYMENT_REQUIRED = -32001;
const JSONRPC_MALFORMED_AUTHORIZATION = -32002;
const JSONRPC_INVALID_PAYMENT_TOKEN = -32003;
const JSONRPC_REPLAYED_PROOF = -32004;
const JSONRPC_EXPIRED_CHALLENGE = -32005;
const JSONRPC_PREIMAGE_MISMATCH = -32006;
const JSONRPC_RECEIPT_SIGNING_FAILED = -32007;
const JSONRPC_RATE_LIMITED = -32009;
const JSONRPC_QUOTA_EXHAUSTED = -32010;
const JSONRPC_CHALLENGE_LIMIT = -32011;
const JSONRPC_BATCH_NOT_SUPPORTED = -32600;

// ---------------------------------------------------------------------------
// Content-free operation log (P10/N2)
// ---------------------------------------------------------------------------

const OPERATION_LOG_FIELDS = [
  "at",
  "event",
  "method",
  "tool",
  "status_code",
  "request_bytes",
  "response_bytes",
  "duration_ms",
  "client_id",
  "amount_sats",
  "payment_hash",
  "outcome",
  "challenge_id",
];

// Strings that survive into an operation record must be short, boring
// identifiers. Anything else (URLs, invoice-like strings, free text) is
// replaced before the record is stored.
const SAFE_LOG_STRING = /^[a-z0-9_][a-z0-9_.:\-]{0,63}$/i;

export function createOperationLog({ clock = () => new Date() } = {}) {
  const records = [];
  return {
    record(entry) {
      const clean = {};
      for (const [key, value] of Object.entries(entry)) {
        if (!OPERATION_LOG_FIELDS.includes(key)) continue;
        if (typeof value === "string" && !SAFE_LOG_STRING.test(value)) {
          clean[key] = "[redacted]";
          continue;
        }
        clean[key] = value;
      }
      clean.at = clock().toISOString();
      records.push(clean);
      return clean;
    },
    list() {
      return records.map((record) => ({ ...record }));
    },
  };
}

// ---------------------------------------------------------------------------
// Rejecting library bridge stub (defense in depth for boundary isolation)
// ---------------------------------------------------------------------------

export function createRejectingLibraryBridge() {
  let rejectedCalls = 0;
  const reject = async () => {
    rejectedCalls += 1;
    throw new Error("public_transport_rejects_library_operations");
  };
  return {
    save: reject,
    get: reject,
    search: reject,
    rejectionCount: () => rejectedCalls,
  };
}

// ---------------------------------------------------------------------------
// Public server
// ---------------------------------------------------------------------------

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isLoopbackHost(host) {
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

export function createPublicSourceSummarizationServer({
  tls = null,
  plaintextLoopbackPaddock = false,
  host = "127.0.0.1",
  port = 0,
  mcpPath = PUBLIC_MCP_PATH_DEFAULT,
  signer,
  bridge = createRejectingLibraryBridge(),
  authority = createSyntheticPaymentAuthority({ serviceIdentity: "unset" }),
  authorityPublicKeyPem = authority?.publicKeyPem,
  entitlementStore,
  clientIdDerivationSecret,
  receiptSignerClient = null,
  serviceNpub,
  pricing = { summarize_source: 21, ask_source: 5, export_source_analysis: 1 },
  capability = "source-summarization",
  version = SERVER_VERSION,
  receiptValiditySeconds = DEFAULT_RECEIPT_VALIDITY_SECONDS,
  clock = () => new Date(),
  operationLog = createOperationLog({ clock }),
  maxRequestBytes = MAX_REQUEST_BYTES,
  abuseControls,
} = {}) {
  if (typeof serviceNpub !== "string" || serviceNpub === "") {
    throw new Error("serviceNpub (the pinned durable service identity) is required");
  }
  if (!plaintextLoopbackPaddock && (!tls || !tls.cert || !tls.key)) {
    throw new Error(
      "tls_required: the public transport is HTTPS-only; construct with TLS material or the explicit plaintextLoopbackPaddock test mode",
    );
  }
  if (plaintextLoopbackPaddock && !isLoopbackHost(host)) {
    throw new Error("plaintextLoopbackPaddock mode refuses to bind a non-loopback host");
  }
  for (const tool of Object.keys(pricing)) {
    if (!Number.isInteger(pricing[tool]) || pricing[tool] <= 0) throw new Error(`pricing for ${tool} must be positive integer sats`);
  }
  // The entitlement store is an explicit construction choice, never a silent
  // in-memory default: a caller that forgets to inject the durable store must
  // fail here rather than run with process-lifetime state, so no construction
  // path unknowingly assumes durable semantics (O2-P1).
  if (
    !isObject(entitlementStore) ||
    typeof entitlementStore.recordChallenge !== "function" ||
    typeof entitlementStore.redeem !== "function"
  ) {
    throw new Error(
      "entitlementStore is required: pass an explicit challenge/entitlement store (paddock in-memory or the durable SQLite store)",
    );
  }
  // The x-opaque-client-id header is ONLY derivation material. Without a
  // server-side derivation secret there is no keyed derivation, so
  // construction fails rather than falling back to raw-header identity (O2-P2).
  if (typeof clientIdDerivationSecret !== "string" || clientIdDerivationSecret === "") {
    throw new Error("clientIdDerivationSecret (the server-side secret for deriveOpaqueClientId) is required");
  }

  // Abuse controls (P5): per-client request rate limiting, bounded challenge
  // issuance, and an optional free-allowance quota — all keyed on OPAQUE
  // client identifiers, never content. Defaults are paddock-safe; every
  // threshold is constructor-configurable.
  const controls = {
    requestWindowMs: 60_000,
    maxRequestsPerWindow: 60,
    challengeWindowMs: 60_000,
    maxChallengesPerWindow: 5,
    freeAllowance: null,
    ...(abuseControls ?? {}),
  };
  for (const [name, value] of [
    ["requestWindowMs", controls.requestWindowMs],
    ["maxRequestsPerWindow", controls.maxRequestsPerWindow],
    ["challengeWindowMs", controls.challengeWindowMs],
    ["maxChallengesPerWindow", controls.maxChallengesPerWindow],
  ]) {
    if (!Number.isInteger(value) || value <= 0) throw new Error(`abuseControls.${name} must be a positive integer`);
  }
  if (controls.freeAllowance !== null && controls.freeAllowance !== undefined) {
    const allowance = controls.freeAllowance;
    if (
      !isObject(allowance) ||
      !Number.isInteger(allowance.windowMs) ||
      allowance.windowMs <= 0 ||
      !Number.isInteger(allowance.operationsPerWindow) ||
      allowance.operationsPerWindow <= 0
    ) {
      throw new Error("abuseControls.freeAllowance must be { windowMs, operationsPerWindow } with positive integers");
    }
  } else {
    controls.freeAllowance = null;
  }
  const requestLimiter = createFixedWindowLimiter({ max: controls.maxRequestsPerWindow, windowMs: controls.requestWindowMs, clock });
  const challengeLimiter = createFixedWindowLimiter({ max: controls.maxChallengesPerWindow, windowMs: controls.challengeWindowMs, clock });
  const quotaLimiter =
    controls.freeAllowance === null
      ? null
      : createFixedWindowLimiter({ max: controls.freeAllowance.operationsPerWindow, windowMs: controls.freeAllowance.windowMs, clock });

  const v1Server = createV1Server({ bridge, signer, clock, productionMode: true });
  const publicTools = TOOLS.filter((tool) => PUBLIC_TOOL_ALLOWLIST.includes(tool.name));

  function errorBody(id, code, message) {
    return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
  }

  function errorBodyWithData(id, code, message, data) {
    return { jsonrpc: "2.0", id: id ?? null, error: { code, message, data } };
  }

  function issueChallengeResponse(clientId, toolName, id, paymentCode) {
    // Bounded challenge issuance (P5 abuse control): over the per-client cap
    // no new challenge is minted — the response carries no invoice material.
    const gate = challengeLimiter.check(clientId ?? ANONYMOUS_CLIENT_BUCKET);
    if (!gate.allowed) {
      operationLog.record({ event: "challenge_limit_reached", tool: toolName, client_id: clientId ?? undefined, outcome: "denied" });
      return {
        httpStatus: 429,
        headers: { "Retry-After": String(gate.retry_after_seconds) },
        body: errorBodyWithData(id, JSONRPC_CHALLENGE_LIMIT, "Challenge issuance is temporarily bounded.", {
          retry_after_seconds: gate.retry_after_seconds,
        }),
      };
    }
    const issued = authority.issueChallenge({
      capability,
      version,
      amountSats: pricing[toolName] ?? pricing.summarize_source,
      serviceIdentity: serviceNpub,
      clientId,
    });
    entitlementStore.recordChallenge(issued.challenge);
    const challenge = challengeHttpResponse(issued.challenge, issued.macaroon, issued.invoice);
    return {
      httpStatus: 402,
      headers: challenge.headers,
      body: errorBody(id, paymentCode, "Payment required."),
    };
  }

  async function handleToolsCall(request, { authorization, clientId }) {
    const params = isObject(request.params) ? request.params : null;
    const toolName = params && typeof params.name === "string" ? params.name : null;
    const id = Object.prototype.hasOwnProperty.call(request, "id") ? request.id : null;
    const limiterKey = clientId ?? ANONYMOUS_CLIENT_BUCKET;
    // Per-client request rate limit (P5): keyed on the opaque identifier,
    // never on content; denial emits a bounded, content-free 429.
    const requestGate = requestLimiter.check(limiterKey);
    if (!requestGate.allowed) {
      operationLog.record({ event: "rate_limited", tool: toolName ?? undefined, client_id: clientId ?? undefined, outcome: "denied" });
      return {
        httpStatus: 429,
        headers: { "Retry-After": String(requestGate.retry_after_seconds) },
        body: errorBodyWithData(id, JSONRPC_RATE_LIMITED, "Request rate limit exceeded for this window.", {
          retry_after_seconds: requestGate.retry_after_seconds,
        }),
      };
    }
    if (!toolName) {
      return { httpStatus: 200, body: errorBody(id, -32602, "Invalid tools/call parameters.") };
    }
    if (!V1_TOOL_NAMES.has(toolName)) {
      return {
        httpStatus: 200,
        body: { jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify({ error: { code: "unknown_tool", message: "The requested tool is not registered." } }) }], isError: true } },
      };
    }
    if (LIBRARY_TOOLS.includes(toolName)) {
      return {
        httpStatus: 200,
        body: {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  error: {
                    code: "tool_not_available_on_public_transport",
                    message: "Local library operations are not available on the public transport.",
                  },
                }),
              },
            ],
            isError: true,
          },
        },
      };
    }
    if (!PUBLIC_TOOL_ALLOWLIST.includes(toolName)) {
      return {
        httpStatus: 200,
        body: {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  error: {
                    code: "tool_not_available_on_public_transport",
                    message: "This tool is not exposed on the public transport.",
                  },
                }),
              },
            ],
            isError: true,
          },
        },
      };
    }
    const args = isObject(params.arguments) ? params.arguments : {};
    if (toolName === "export_source_analysis" && args.artifact === undefined) {
      return {
        httpStatus: 200,
        body: {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  error: {
                    code: "tool_not_available_on_public_transport",
                    message: "Only caller-held artifacts can be exported on the public transport.",
                  },
                }),
              },
            ],
            isError: true,
          },
        },
      };
    }

    // Payment gate: policy before the protected tool call, never after. A
    // token minted for another capability is not payment for this one.
    const proof = verifyL402Proof({ authorization, authorityPublicKeyPem, clock });
    if (proof.ok && proof.capability !== capability) {
      return { httpStatus: 400, body: errorBody(id, JSONRPC_INVALID_PAYMENT_TOKEN, "The payment token is invalid.") };
    }
    if (!proof.ok) {
      if (proof.reason === "malformed_authorization") {
        return { httpStatus: 400, body: errorBody(id, JSONRPC_MALFORMED_AUTHORIZATION, "Malformed L402 authorization header.") };
      }
      if (proof.reason === "invalid_payment_token") {
        return { httpStatus: 400, body: errorBody(id, JSONRPC_INVALID_PAYMENT_TOKEN, "The payment token is invalid.") };
      }
      const code =
        proof.reason === "expired_challenge"
          ? JSONRPC_EXPIRED_CHALLENGE
          : proof.reason === "preimage_mismatch"
            ? JSONRPC_PREIMAGE_MISMATCH
            : JSONRPC_PAYMENT_REQUIRED;
      return issueChallengeResponse(clientId, toolName, id, code);
    }
    // Free-allowance quota (P5): consumed atomically BEFORE redemption so a
    // quota denial never burns the paid proof (the proof stays replayable
    // after the quota window resets). The slot is consumed even if a later
    // step fails closed (tool execution) — consistent with the entitlement
    // fail-closed posture recorded as handoff deviation 2.
    if (quotaLimiter) {
      const quotaGate = quotaLimiter.check(limiterKey);
      if (!quotaGate.allowed) {
        operationLog.record({ event: "quota_exhausted", tool: toolName, client_id: clientId ?? undefined, outcome: "denied" });
        return {
          httpStatus: 429,
          headers: { "Retry-After": String(quotaGate.retry_after_seconds) },
          body: errorBodyWithData(id, JSONRPC_QUOTA_EXHAUSTED, "The free-allowance quota for this window is exhausted.", {
            retry_after_seconds: quotaGate.retry_after_seconds,
            max_operations: quotaGate.max,
          }),
        };
      }
    }
    // Receipt signing BEFORE redemption (O2-P5; founder-approved order
    // sign -> redeem -> execute): signing is a side-effect-free local
    // operation on an already-verified proof, so signer unavailability fails
    // closed at 503 WITHOUT burning the entitlement — the proof stays
    // replayable and a paid caller is never charged with nothing delivered.
    // A paid call still never returns content without a verified content-free
    // receipt (PRD P4).
    if (!receiptSignerClient) {
      return { httpStatus: 503, body: errorBody(id, JSONRPC_RECEIPT_SIGNING_FAILED, "Receipt signing is unavailable.") };
    }
    const now = clock();
    const receipt = {
      receipt_id: randomUUID(),
      capability,
      version,
      amount_sats: proof.amount_sats,
      payment_hash: proof.payment_hash,
      client_id: proof.client_id ?? clientId ?? null,
      service_identity: serviceNpub,
      issued_at: now.toISOString(),
      valid_until: new Date(now.getTime() + receiptValiditySeconds * 1000).toISOString(),
    };
    if (receipt.client_id === null) delete receipt.client_id;
    let signed;
    try {
      signed = await receiptSignerClient.requestSignature(receipt);
    } catch {
      operationLog.record({ event: "receipt_signing_failed", tool: toolName, outcome: "fail_closed", client_id: clientId ?? undefined });
      return { httpStatus: 503, body: errorBody(id, JSONRPC_RECEIPT_SIGNING_FAILED, "Receipt signing failed.") };
    }

    // Redemption stays the single-winner gate immediately before execution:
    // exactly one caller per paid proof executes; every replay is denied here.
    const redemption = entitlementStore.redeem(proof.payment_hash);
    if (!redemption.ok) {
      // One-shot replay denial: a fresh challenge, no second grant, no effect.
      return issueChallengeResponse(clientId, toolName, id, JSONRPC_REPLAYED_PROOF);
    }

    const result = await v1Server.callTool(toolName, args);
    const structured = isObject(result.structuredContent) ? result.structuredContent : {};
    structured.l402_receipt = { ...receipt, signature: signed.signature };
    operationLog.record({
      event: "tool_call",
      tool: toolName,
      status_code: 200,
      client_id: proof.client_id ?? clientId ?? undefined,
      amount_sats: proof.amount_sats,
      payment_hash: proof.payment_hash,
      outcome: result.isError === true ? "tool_error" : "ok",
    });
    return { httpStatus: 200, body: { jsonrpc: "2.0", id, result: { ...result, structuredContent: structured } } };
  }

  async function handleJsonRpcRequest(request, { authorization, clientId }) {
    if (Array.isArray(request)) {
      return { httpStatus: 400, body: errorBody(null, JSONRPC_BATCH_NOT_SUPPORTED, "JSON-RPC batches are not supported on this transport.") };
    }
    if (request.method === "tools/list") {
      const id = Object.prototype.hasOwnProperty.call(request, "id") ? request.id : null;
      return { httpStatus: 200, body: { jsonrpc: "2.0", id, result: { tools: publicTools } } };
    }
    if (request.method === "tools/call") {
      return handleToolsCall(request, { authorization, clientId });
    }
    const response = await v1Server.handleRequest(request);
    return { httpStatus: 200, body: response ?? errorBody(null, -32600, "Invalid JSON-RPC request.") };
  }

  function readBody(req) {
    // Bounded read: past the request limit the body is drained (discarded) so
    // the 413 response can be delivered cleanly; a second hard cap destroys
    // the socket so a hostile upload cannot hold it open indefinitely.
    const drainLimit = maxRequestBytes * 8;
    return new Promise((resolvePromise, rejectPromise) => {
      const chunks = [];
      let total = 0;
      let rejected = false;
      req.on("data", (chunk) => {
        if (!rejected) chunks.push(chunk);
        total += chunk.length;
        if (!rejected && total > maxRequestBytes) {
          rejected = true;
          rejectPromise(new Error("request_too_large"));
        }
        if (total > drainLimit) {
          req.destroy();
        }
      });
      req.on("end", () => {
        if (!rejected) resolvePromise(Buffer.concat(chunks));
      });
      req.on("error", (error) => {
        if (!rejected) rejectPromise(error);
      });
    });
  }

  const requestHandler = async (req, res) => {
    const startedAt = Date.now();
    const url = new URL(req.url ?? "/", "https://public.invalid");
    const authorization = req.headers.authorization;
    // Identity boundary (O2-P2): the caller-supplied x-opaque-client-id header
    // is derivation material ONLY — never used verbatim as identity. The
    // server-side secret keys the derivation, so the derived id keys the
    // limiter, quota, challenge, receipt, and log records; an absent header
    // keeps the anonymous shared bucket.
    const clientIdHeader = req.headers["x-opaque-client-id"];
    const clientId =
      typeof clientIdHeader === "string" && clientIdHeader !== ""
        ? deriveOpaqueClientId(clientIdDerivationSecret, clientIdHeader)
        : null;
    const send = (status, body, headers = {}) => {
      const payload = JSON.stringify(body);
      res.writeHead(status, { "Content-Type": "application/json", ...headers });
      res.end(payload);
      operationLog.record({
        event: "http_request",
        method: req.method,
        status_code: status,
        request_bytes: Number(req.headers["content-length"] ?? 0),
        response_bytes: Buffer.byteLength(payload),
        duration_ms: Date.now() - startedAt,
        client_id: clientId ?? undefined,
        outcome: status < 400 ? "ok" : status < 500 ? "client_error" : "server_error",
      });
    };

    if (req.method === "GET" && url.pathname === PUBLIC_HEALTH_PATH) {
      send(200, {
        ok: true,
        service: SERVER_NAME,
        version: SERVER_VERSION,
        protocol: PROTOCOL_VERSION,
        configuration_class: plaintextLoopbackPaddock ? "paddock-loopback" : "public-tls",
        transport: tls ? "tls" : "paddock-plaintext-loopback",
        public_tools: PUBLIC_TOOL_ALLOWLIST,
      });
      return;
    }
    if (url.pathname !== mcpPath) {
      send(404, { error: { code: "not_found", message: "Unknown path." } });
      return;
    }
    if (req.method !== "POST") {
      send(405, { error: { code: "method_not_allowed", message: "Use POST for MCP requests." } });
      return;
    }
    let body;
    try {
      body = await readBody(req);
    } catch {
      send(413, { error: { code: "request_too_large", message: "The request exceeded the bounded body size." } });
      return;
    }
    let request;
    try {
      request = JSON.parse(body.toString("utf8"));
    } catch {
      send(200, errorBody(null, -32700, "Parse error."));
      return;
    }
    if (!isObject(request)) {
      // A JSON-RPC batch (array) or non-object body is a client protocol
      // error on this single-request transport.
      const isBatch = Array.isArray(request);
      send(isBatch ? 400 : 200, errorBody(null, JSONRPC_BATCH_NOT_SUPPORTED, isBatch ? "JSON-RPC batches are not supported on this transport." : "Invalid JSON-RPC request."));
      return;
    }
    try {
      const outcome = await handleJsonRpcRequest(request, { authorization, clientId });
      send(outcome.httpStatus, outcome.body, outcome.headers ?? {});
    } catch {
      send(200, errorBody(isObject(request) && "id" in request ? request.id : null, -32603, "Internal error."));
    }
  };

  const server = tls
    ? createHttpsServer({ cert: tls.cert, key: tls.key }, requestHandler)
    : createHttpServer(requestHandler);

  return {
    server,
    operationLog,
    entitlementStore,
    // Content-free abuse-control state for tests and evidence collection.
    abuseControls: {
      requestLimiter,
      challengeLimiter,
      quotaLimiter,
    },
    listen(listenPort = port, listenHost = host) {
      if (plaintextLoopbackPaddock && !isLoopbackHost(listenHost)) {
        return Promise.reject(new Error("plaintextLoopbackPaddock mode refuses to bind a non-loopback host"));
      }
      return new Promise((resolvePromise, rejectPromise) => {
        server.once("error", rejectPromise);
        server.listen(listenPort, listenHost, () => {
          const address = server.address();
          resolvePromise({ port: typeof address === "object" && address !== null ? address.port : listenPort, host: listenHost });
        });
      });
    },
    async close() {
      // fetch/keep-alive clients hold idle sockets that would otherwise stall
      // server.close(); drop them explicitly where the runtime supports it.
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      if (typeof server.closeIdleConnections === "function") server.closeIdleConnections();
      await new Promise((resolvePromise) => server.close(() => resolvePromise()));
    },
  };
}
