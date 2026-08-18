// Offline tests for the synthetic backend selector, NWC export threshold
// logic, and credential masking (source-summarization-backend-config.mjs).
// Every credential-shaped value here is an obvious synthetic fixture; nothing
// real is accepted and no sats move.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  BACKEND_ACTIVATION_GATE,
  DEFAULT_NWC_EXPORT_THRESHOLD_SATS,
  classifyPaymentDestination,
  createBackendSelector,
  createNwcExportConfig,
  maskConnectionSecret,
} from "./source-summarization-backend-config.mjs";

const SYNTHETIC_NWC = "nostr+walletconnect://SYNTHETIC-NOT-A-REAL-CONNECTION-000";

test("payment destinations classify into typed states without projecting raw strings", () => {
  assert.deepEqual(classifyPaymentDestination("bolt11:SYNTHETICINVOICEPREFIX").state, "supported");
  assert.deepEqual(classifyPaymentDestination("lnurl:https://wallet.example.test/lnurl").state, "supported");
  assert.deepEqual(classifyPaymentDestination("").state, "malformed");
  assert.deepEqual(classifyPaymentDestination(null).state, "malformed");
  assert.deepEqual(classifyPaymentDestination("user@domain.example").state, "ambiguous");
  assert.deepEqual(classifyPaymentDestination("a@b@c").state, "malformed");
  assert.deepEqual(classifyPaymentDestination("bitcoin:bc1synthetic").state, "unsupported");
  assert.deepEqual(classifyPaymentDestination("totally-unknown-scheme:x").state, "unsupported");
});

test("the selector defaults to the MDK hosted backend and gates the upgrade path", () => {
  const selector = createBackendSelector();
  assert.equal(selector.activeBackend, "mdk-hosted");
  const upgrade = selector.selectBackend("user-ln-node");
  assert.equal(upgrade.status, "pending");
  assert.equal(upgrade.reason, BACKEND_ACTIVATION_GATE);
  assert.equal(upgrade.active_backend, "mdk-hosted");
  assert.equal(selector.activeBackend, "mdk-hosted");

  const reversal = selector.selectBackend("mdk-hosted");
  assert.equal(reversal.status, "switched");

  assert.equal(selector.selectBackend("not-a-backend").status, "rejected");
  const projection = selector.projection();
  assert.deepEqual(projection.available, ["mdk-hosted"]);
  assert.ok(projection.pending_gate.some((pending) => pending.backend === "user-ln-node" && pending.gate === BACKEND_ACTIVATION_GATE));
  // Typed projection only: no connection strings anywhere.
  assert.equal(JSON.stringify(projection).includes("nostr+walletconnect"), false);
});

test("the export threshold default is 100,000 sats; firing is strictly above", () => {
  assert.equal(DEFAULT_NWC_EXPORT_THRESHOLD_SATS, 100000);
  const config = createNwcExportConfig();
  config.configureConnection(SYNTHETIC_NWC);
  assert.equal(config.thresholdSats, 100000);
  const below = config.evaluateExport({ balanceSats: 99999, actor: "operator" });
  const equal = config.evaluateExport({ balanceSats: 100000, actor: "operator" });
  const above = config.evaluateExport({ balanceSats: 100001, actor: "operator" });
  // Recorded implementation choice: equality does NOT fire ("exceeds").
  assert.deepEqual([below.comparison, below.should_export], ["below", false]);
  assert.deepEqual([equal.comparison, equal.should_export], ["equal", false]);
  assert.deepEqual([above.comparison, above.should_export], ["above", true]);

  const lowered = config.setThreshold(1000);
  assert.equal(lowered.status, "ok");
  assert.deepEqual(config.evaluateExport({ balanceSats: 1000, actor: "operator" }), {
    status: "ok",
    comparison: "equal",
    should_export: false,
    threshold_sats: 1000,
    amount_sats: 1000,
  });
  assert.equal(config.setThreshold(0).status, "rejected");
});

test("the export is operator-gated and never autonomous", () => {
  const config = createNwcExportConfig();
  config.configureConnection(SYNTHETIC_NWC);
  const agent = config.evaluateExport({ balanceSats: 500000, actor: "agent" });
  assert.deepEqual([agent.status, agent.reason], ["rejected", "operator_gate_required"]);
  const anonymous = config.evaluateExport({ balanceSats: 500000, actor: "anonymous" });
  assert.equal(anonymous.status, "rejected");
  const unconfigured = createNwcExportConfig().evaluateExport({ balanceSats: 500000, actor: "operator" });
  assert.deepEqual([unconfigured.status, unconfigured.reason], ["rejected", "no_connection_configured"]);
});

test("connection secrets are masked on read-back, rotatable, and never appear in projections or audit", () => {
  const config = createNwcExportConfig();
  const configured = config.configureConnection(SYNTHETIC_NWC);
  assert.equal(configured.configured, true);
  assert.match(configured.preview, /^••••/);
  assert.equal(configured.preview.includes(SYNTHETIC_NWC), false);
  assert.equal(config.connectionProjection.configured, true);

  const rotated = config.rotateConnection("nostr+walletconnect://SYNTHETIC-ROTATED-NOT-REAL-001");
  assert.equal(rotated.configured, true);

  const audit = JSON.stringify(config.auditTrail());
  assert.equal(audit.includes(SYNTHETIC_NWC), false);
  assert.equal(audit.includes("SYNTHETIC-ROTATED"), false);
  for (const entry of config.auditTrail()) {
    assert.deepEqual(Object.keys(entry).sort(), ["at", "event", "outcome"]);
  }
  const masked = maskConnectionSecret(SYNTHETIC_NWC);
  assert.equal(masked.preview.includes("SYNTHETIC"), false);
  assert.deepEqual(maskConnectionSecret(""), { configured: false, preview: null, opaque_reference: null });
});
