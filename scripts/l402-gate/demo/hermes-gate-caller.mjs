#!/usr/bin/env node

// Hermes-side caller for the reusable L-402 MCP capability gate (WP-M5a;
// plan 15-plan-omega-dvm-marketplace; CALL-CONTRACT.md from WP-M3).
//
// This module implements the Hermes-side responsibilities documented in
// CALL-CONTRACT.md §3:
//   - Hold the L402 proof per user session (one-shot bearer credential,
//     SEC-2026-037): after redemption it cannot be reused, so the caller
//     re-challenges on the next gated call.
//   - Never log or render the macaroon, preimage, or invoice.
//   - Surface the payment step to the founder in the Telegram thread
//     (invoice string / payment link), then retry the call with the proof.
//   - Treat the signed receipt as the delivered-payment record; verify its
//     signature against the service npub before trusting the artifact.
//
// The gate wire contract (CALL-CONTRACT §2):
//   POST <mcpPath> (default /mcp) with a single JSON-RPC 2.0 object.
//   1. tools/call without Authorization -> 402 + WWW-Authenticate:
//      L402 macaroon="...", invoice="SYNTHETIC-INVOICE-1:<hex>" (paddock) /
//      invoice="<BOLT11>" (live at WP-M5).
//   2. Pay: paddock — the synthetic authority settles the challenge id and
//      the caller learns the preimage. Live — the founder pays the LN invoice
//      and the payer learns the preimage from the Lightning network.
//   3. tools/call with Authorization: L402 <macaroon>:<preimage> -> 200 with
//      the tool result and structuredContent.l402_receipt (content-free,
//      signed by the off-serving signer, verifiable against the service npub).
//
// This module is transport/dependency-free (node:fetch only) and works against
// BOTH the paddock gate and (at WP-M5b, under the founder gate) the live TLS
// edge. The payment handler is injected: in paddock it settles with the
// synthetic authority; live it is the founder wallet flow that returns the
// preimage. Never import credential stores or signing keys here.

import { verifyReceiptSignature } from "../receipt.mjs";

const L402_PREFIX = "L402";

function assertOk(value, message) {
  if (!value) throw new Error(message);
}

function parseL402Challenge(wwwAuthenticate) {
  assertOk(
    typeof wwwAuthenticate === "string" && wwwAuthenticate.startsWith(`${L402_PREFIX} `),
    `unexpected challenge header: expected L402 challenge, got ${JSON.stringify(wwwAuthenticate)}`,
  );
  const macaroon = wwwAuthenticate.match(/macaroon="([^"]+)"/)?.[1];
  const invoice = wwwAuthenticate.match(/invoice="([^"]+)"/)?.[1];
  assertOk(macaroon, "L402 challenge missing macaroon");
  assertOk(invoice, "L402 challenge missing invoice");
  return { macaroon, invoice };
}

/**
 * Create a Hermes-side gate caller bound to one gate endpoint.
 *
 * @param {object} opts
 * @param {string} opts.baseUrl - http(s)://host:port of the gate.
 * @param {string} [opts.mcpPath="/mcp"] - JSON-RPC MCP path.
 * @param {string} opts.serviceNpub - pinned service identity the receipt
 *   signature is verified against (64-hex or npub1 form accepted by
 *   verifyReceiptSignature).
 * @param {string} [opts.clientId] - optional opaque client id (derivation
 *   material only on the server side).
 */
export function createHermesGateCaller({ baseUrl, mcpPath = "/mcp", serviceNpub, clientId }) {
  assertOk(baseUrl, "baseUrl is required");
  assertOk(serviceNpub, "serviceNpub is required");

  async function post(body, headers = {}) {
    const response = await fetch(`${baseUrl}${mcpPath}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
    const json = await response.json();
    return { status: response.status, headers: response.headers, json };
  }

  /**
   * Phase 1 — request the L402 challenge for a gated tool call.
   * Returns { invoice, macaroon } — the invoice is surfaced to the founder in
   * the Telegram thread (CALL-CONTRACT §3); the macaroon is held per session
   * and NEVER logged or rendered.
   */
  async function requestChallenge({ toolName, args }) {
    const body = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: toolName, arguments: args } };
    const response = await post(body, clientId ? { "x-opaque-client-id": clientId } : {});
    assertOk(response.status === 402, `expected 402 challenge, got ${response.status}`);
    const { macaroon, invoice } = parseL402Challenge(response.headers.get("www-authenticate"));
    return { invoice, macaroon };
  }

  /**
   * Phase 2 — redeem the paid proof and execute the tool.
   * Returns { result, receipt, receiptVerified }. The receipt signature is
   * ALWAYS verified against the pinned service npub before the result is
   * trusted (CALL-CONTRACT §3).
   */
  async function redeem({ toolName, args, macaroon, preimage }) {
    assertOk(macaroon, "macaroon is required (held per session; never logged)");
    assertOk(preimage, "preimage is required (from the payment settlement)");
    const body = { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: toolName, arguments: args } };
    const response = await post(
      body,
      {
        Authorization: `${L402_PREFIX} ${macaroon}:${preimage}`,
        ...(clientId ? { "x-opaque-client-id": clientId } : {}),
      },
    );
    assertOk(response.status === 200, `expected 200 after redemption, got ${response.status}`);
    const result = response.json.result;
    const receipt = result?.structuredContent?.l402_receipt;
    assertOk(receipt, "gate response missing l402_receipt");
    // The receipt's `signature` field is NOT part of the allowlisted receipt
    // body (RECEIPT_FIELDS in receipt.mjs) — verification signs the digest of
    // the body WITHOUT the signature field. Strip it exactly like the paddock
    // suite's stripSignature helper before verifying.
    const { signature, ...receiptBody } = receipt;
    const receiptVerified = verifyReceiptSignature(receiptBody, signature, serviceNpub);
    return { result, receipt, receiptVerified };
  }

  /**
   * One-shot convenience: challenge -> pay (injected payment handler) ->
   * redeem. The payment handler receives { invoice, macaroon, toolName } and
   * must return the preimage (paddock: authority.settle(challengeId); live:
   * founder wallet). This is the paddock demo path and the reference for a
   * live Hermes integration.
   */
  async function callGated({ toolName, args, pay }) {
    assertOk(typeof pay === "function", "a payment handler is required: paddock settle or founder wallet");
    const { invoice, macaroon } = await requestChallenge({ toolName, args });
    const preimage = await pay({ invoice, macaroon, toolName });
    const outcome = await redeem({ toolName, args, macaroon, preimage });
    if (!outcome.receiptVerified) {
      throw new Error("receipt signature verification FAILED against the service npub");
    }
    return { invoice, ...outcome };
  }

  return {
    requestChallenge,
    redeem,
    callGated,
  };
}