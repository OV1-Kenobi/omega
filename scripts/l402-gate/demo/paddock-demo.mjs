#!/usr/bin/env node

// WP-M5a paddock-mode end-to-end demo: Telegram -> Hermes -> L-402 gate ->
// gated capability -> result returned.
//
// Plan: 15-plan-omega-dvm-marketplace, WP-M5a. Contract: CALL-CONTRACT.md
// (WP-M3). PADDOCK-GRADE ONLY: synthetic in-process payment authority
// (SYNTHETIC-INVOICE-1), in-memory store, in-process off-serving signer over a
// real named pipe, loopback-only, NO TLS material, NO live payments, NO VPS,
// NO cloud egress, NO secrets.
//
// The demo executes the verified source-summarization capability adapter (the
// WP-M3 gate's executor seam). Video-transcription remains deferred from the
// gate per CALL-CONTRACT.md §5 (its worker can trigger a model download and is
// non-deterministic); it becomes a first-class adapter at WP-M5b once the
// model is confirmed cached and the founder authorizes live runs. The demo
// plugin (`plugins/dvm/demo_video_transcription`) carries the
// `video/transcription` DVM service identity through the F-04 pipeline — see
// wp-m5-output/01-demo-plugin-evidence.md.
//
// Output contract (LRN-2026-130): with `--json`, stdout carries ONLY the
// evidence JSON; the human-readable log goes to stderr.

import { randomBytes } from "node:crypto";
import { createCredentialStoreSigner, createInMemoryStorage, provisionSignerIdentity } from "../signer.mjs";
import { ReceiptSignerClient, createRemoteArtifactSigner, receiptSignerPipePath, verifyReceiptSignature } from "../receipt.mjs";
import { createReceiptSignerService } from "../receipt-signer.mjs";
import { createChallengeEntitlementStore, createSyntheticPaymentAuthority } from "../l402-core.mjs";
import { createCapabilityGateServer } from "../gate-server.mjs";
import {
  CAPABILITY,
  VERSION,
  createSourceSummarizationExecutor,
} from "../capabilities/source-summarization.mjs";
import { createHermesGateCaller } from "./hermes-gate-caller.mjs";

const BOOT_SECRET = "synthetic-paddock-boot-secret"; // paddock only; never a live credential
const DERIVATION_SECRET = "synthetic-paddock-derivation-secret";
const PRICING = { summarize_source: 21, ask_source: 5, export_source_analysis: 1 };

const SOURCE_URL = "https://private.example.test/wp-m5a-demo-source";
const SOURCE_CONTENT =
  "Two-machine demo source content. The L-402 gate protects this capability behind a synthetic invoice in paddock mode.";
const SOURCE_TITLE = "WP-M5A paddock demo source";
const MODEL_SUMMARY = "Paddock demo summary: the gate round-trip completed with a signed receipt.";
const MODEL_KEY_POINTS = ["402 challenge issued", "mock payment settled", "capability executed", "receipt verified"];

const args = process.argv.slice(2);
const jsonMode = args.includes("--json");
// Diagnostics ALWAYS go to stderr (LRN-2026-130): stdout carries ONLY the
// evidence JSON in --json mode, never diagnostics.
const log = (...parts) => console.error("[demo]", ...parts);

function assertOk(value, message) {
  if (!value) throw new Error(message);
}

async function runDemo() {
  // -------------------------------------------------------------------------
  // Build the paddock harness (mirrors the WP-M3 paddock test harness).
  // -------------------------------------------------------------------------
  const storage = createInMemoryStorage();
  const npub = await provisionSignerIdentity({ storage });
  const pipePath = receiptSignerPipePath(`wp-m5a-demo-${randomBytes(6).toString("hex")}`);
  const signerService = createReceiptSignerService({
    signer: createCredentialStoreSigner({ storage }),
    pipePath,
    authSecret: BOOT_SECRET,
    allowedPurposes: ["sign_receipt", "artifact_sign"],
  });
  await signerService.listen();
  const client = new ReceiptSignerClient({ pipePath, authSecret: BOOT_SECRET, expectedServiceNpub: npub });
  const authority = createSyntheticPaymentAuthority({ serviceIdentity: npub });
  const executor = createSourceSummarizationExecutor({
    signer: createRemoteArtifactSigner({ client, serviceNpub: npub }),
  });
  const server = createCapabilityGateServer({
    capability: CAPABILITY,
    version: VERSION,
    tools: executor.tools,
    pricing: PRICING,
    executor,
    plaintextLoopbackPaddock: true,
    host: "127.0.0.1",
    port: 0,
    serviceNpub: npub,
    receiptSignerClient: client,
    entitlementStore: createChallengeEntitlementStore(),
    clientIdDerivationSecret: DERIVATION_SECRET,
    authority,
  });
  const address = await server.listen(0, "127.0.0.1");
  const base = `http://127.0.0.1:${address.port}`;
  log("gate listening on", base, "capability", CAPABILITY, "serviceNpub", npub);
  log("pid", process.pid, "pipe", pipePath);

  try {
    // -----------------------------------------------------------------------
    // Step A — health check (LRN-2026-129: /health on every launch).
    // -----------------------------------------------------------------------
    const healthResponse = await fetch(`${base}/health`);
    const health = await healthResponse.json();
    log("health", healthResponse.status, health.configuration_class, health.transport);
    assertOk(healthResponse.status === 200 && health.ok === true, "health check failed");

    // -----------------------------------------------------------------------
    // Step B — discovery: tools/list (the gate's exposed contract).
    // -----------------------------------------------------------------------
    const toolsListResponse = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 0, method: "tools/list" }),
    });
    const toolsList = await toolsListResponse.json();
    log("tools/list", toolsList.result.tools.map((t) => t.name).join(","));
    assertOk(toolsListResponse.status === 200 && Array.isArray(toolsList.result.tools), "tools/list failed");

    // -----------------------------------------------------------------------
    // Step C — Telegram command -> Hermes decision (simulated).
    //
    // Founder sends: "/video-summarize https://private.example.test/wp-m5a-demo-source"
    // Hermes (Company OS harness, WS5) decides the gated capability
    // (source-summarization) is needed for the request, calls the gate over
    // MCP, and holds the L402 proof per session (CALL-CONTRACT §3).
    // -----------------------------------------------------------------------
    const telegramCommand = "/video-summarize https://private.example.test/wp-m5a-demo-source";
    log("telegram command:", telegramCommand);

    const caller = createHermesGateCaller({ baseUrl: base, serviceNpub: npub });

    // Hermes surfaces the payment step to the founder in the Telegram thread
    // (the invoice string), then pays and retries with the proof.
    const { invoice, macaroon } = await caller.requestChallenge({
      toolName: "summarize_source",
      args: {
        url: SOURCE_URL,
        content: SOURCE_CONTENT,
        source_title: SOURCE_TITLE,
        summary: MODEL_SUMMARY,
        key_points: MODEL_KEY_POINTS,
      },
    });
    log("402 challenge received; invoice:", invoice.slice(0, 40) + "…");
    assertOk(invoice.startsWith("SYNTHETIC-INVOICE-1:"), "paddock invoice prefix must be SYNTHETIC-INVOICE-1");

    // -----------------------------------------------------------------------
    // Step D — mock pay: settle with the synthetic authority (paddock). Live:
    // the founder pays the LN invoice; the payer learns the preimage from the
    // Lightning network (never from the operator).
    // -----------------------------------------------------------------------
    const token = JSON.parse(Buffer.from(macaroon, "base64").toString("utf8"));
    const preimage = authority.settle(token.payload.challenge_id);
    log("mock payment settled (SYNTHETIC-INVOICE-1); preimage acquired");
    assertOk(typeof preimage === "string" && preimage.length === 64, "preimage must be 64 hex");

    // -----------------------------------------------------------------------
    // Step E — redeem + capability executes -> signed artifact + signed receipt.
    // -----------------------------------------------------------------------
    const { result, receipt, receiptVerified } = await caller.redeem({
      toolName: "summarize_source",
      args: {
        url: SOURCE_URL,
        content: SOURCE_CONTENT,
        source_title: SOURCE_TITLE,
        summary: MODEL_SUMMARY,
        key_points: MODEL_KEY_POINTS,
      },
      macaroon,
      preimage,
    });
    log("redemption OK; receiptVerified =", receiptVerified);
    assertOk(receiptVerified, "receipt signature verification FAILED against the service npub");

    // summarize_source returns the signed artifact as JSON text in
    // content[0].text (toolJson path in the adapter); the receipt is in
    // structuredContent.l402_receipt (attached by the gate).
    const artifactText = result.content?.[0]?.text;
    const artifact = typeof artifactText === "string" ? JSON.parse(artifactText) : undefined;
    assertOk(artifact, "capability result missing signed artifact");
    assertOk(artifact.integrity && artifact.integrity.artifact_digest_sha256, "artifact missing integrity block");

    // -----------------------------------------------------------------------
    // Step F — single-winner: replaying the SAME proof must get a fresh 402
    // and NO second grant (one-shot bearer credential, SEC-2026-037).
    // -----------------------------------------------------------------------
    const replay = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `L402 ${macaroon}:${preimage}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "summarize_source", arguments: { url: SOURCE_URL, content: SOURCE_CONTENT, summary: MODEL_SUMMARY, key_points: MODEL_KEY_POINTS } },
      }),
    });
    const replayJson = await replay.json();
    log("replay status", replay.status, "-> fresh challenge (single-winner)");
    assertOk(replay.status === 402, "replay must be denied with a fresh 402");

    // -----------------------------------------------------------------------
    // Evidence assembly.
    // -----------------------------------------------------------------------
    const evidence = {
      demo: "wp-m5a-paddock-demo",
      plan: "15-plan-omega-dvm-marketplace",
      date: new Date().toISOString(),
      pid: process.pid,
      transport: "paddock-loopback",
      capability: CAPABILITY,
      capability_version: VERSION,
      service_identity: npub,
      pricing: PRICING,
      telegram_command: telegramCommand,
      steps: {
        health: { status: healthResponse.status, configuration_class: health.configuration_class, transport: health.transport },
        tools_list: toolsList.result.tools.map((t) => t.name),
        challenge: {
          http_status: 402,
          invoice_prefix: invoice.slice(0, 21),
          invoice_redacted: true,
          macaroon_redacted: true,
        },
        mock_payment: { method: "SYNTHETIC-INVOICE-1 settle", preimage_redacted: true },
        redemption: {
          http_status: 200,
          tool: "summarize_source",
          amount_sats: receipt.amount_sats,
          payment_hash: receipt.payment_hash,
          receipt_id: receipt.receipt_id,
          receipt_verified: receiptVerified,
          artifact_digest_sha256: artifact.integrity.artifact_digest_sha256,
          content_digest_sha256: artifact.integrity.content_digest_sha256,
          publisher_npub: artifact.integrity.publisher_npub,
          result_keys: Object.keys(result),
        },
        replay_denial: { http_status: replay.status, single_winner: true, error_code: replayJson.error?.code },
      },
    };

    if (jsonMode) {
      console.log(JSON.stringify(evidence, null, 2));
    } else {
      log("=== WP-M5A PADDOCK DEMO COMPLETE ===");
      log("receipt verified:", receiptVerified);
      log("artifact digest:", artifact.integrity.artifact_digest_sha256);
      log("publisher npub:", artifact.integrity.publisher_npub);
      log("amount sats:", receipt.amount_sats, "payment_hash:", receipt.payment_hash.slice(0, 16) + "…");
      log("replay denied with fresh 402 (single-winner)");
    }

    // Return the evidence for the runner to write out.
    return evidence;
  } finally {
    // Resource hygiene (kill-on-exit): always close the gate server and the
    // signer service. Both are in-process; the server's close() also drops
    // fetch keep-alive sockets so the process exits cleanly.
    await server.close().catch(() => {});
    await signerService.close().catch(() => {});
    log("gate server + signer service closed; pid", process.pid, "reaped");
  }
}

runDemo()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("[demo] FAILED:", error.message);
    process.exit(1);
  });