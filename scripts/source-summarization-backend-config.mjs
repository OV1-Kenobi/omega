#!/usr/bin/env node

// Synthetic Lightning backend selection, NWC export threshold logic, and
// credential-masking discipline for the WP6 public tier (PRD P3/P5/P6/P7;
// the implementation staging plan slice 7; upgrade-path gate activation
// gate).
//
// SYNTHETIC LOGIC ONLY. No real NWC connection strings, node credentials,
// wallet keys, LNbits URLs, or payment movement are accepted or produced
// anywhere in this module; every credential-shaped value in tests is an
// obvious synthetic fixture. No NWC connection is made and no sats move: the
// export evaluation returns a typed decision that an operator surface acts on.
//
// Threshold semantics — RECORDED IMPLEMENTATION CHOICE: the approved sources
// say the export fires when the balance is "above"/"exceeds" the configured
// threshold and do not define the equality case (design note section 7,
// Requires Verification). This module implements STRICTLY GREATER THAN:
// equality does not fire. below/equal/above are all typed so tests pin the
// chosen rule without claiming it as an approved one.
//
// Capability manifest (agent-and-skill-security-policy section 2):
//   - Files/dirs: none read or written; in-memory configuration state.
//   - Network: none; node:crypto only, and only for opaque masking.
//   - Credentials: connection secrets are held only as opaque references plus
//     a masked preview; the raw value never appears in any projection or audit
//     event this module emits. Rotation replaces the stored value without
//     exposing the old one.
//   - Persistence: none.
//   - Boundaries: operator configuration surface; the public serving process
//     must not import this module. NWC export decisions are operator-gated and
//     never autonomous.
//   - Failure: unknown backends and malformed inputs return typed states, not
//     exceptions, so projections stay raw-string-free.

import { createHash, randomBytes } from "node:crypto";

export const DEFAULT_NWC_EXPORT_THRESHOLD_SATS = 100000;
export const KNOWN_BACKENDS = ["mdk-hosted", "user-ln-node", "self-hosted-lnbits"];
export const BACKEND_ACTIVATION_GATE = "upgrade-path-gate";

const DESTINATION_PREFIXES_SUPPORTED = ["bolt11:", "lnurl:", "lightning:", "lnbits:"];
const DESTINATION_PREFIXES_UNSUPPORTED = ["bitcoin:", "onchain:", "iban:", "swift:"];

export function classifyPaymentDestination(value) {
  // Typed classifier (design note section 4.6): raw payment strings are never
  // stored or projected, only these states. Shape-level classification only —
  // real BOLT11/LNURL validity is provider-bound and Requires Verification.
  if (typeof value !== "string") return { state: "malformed", reason: "not_a_string" };
  const trimmed = value.trim();
  if (trimmed === "") return { state: "malformed", reason: "empty" };
  const lower = trimmed.toLowerCase();
  if (DESTINATION_PREFIXES_UNSUPPORTED.some((prefix) => lower.startsWith(prefix))) {
    return { state: "unsupported", reason: "scheme_outside_lightning_v1" };
  }
  if (DESTINATION_PREFIXES_SUPPORTED.some((prefix) => lower.startsWith(prefix))) {
    if (trimmed.includes(" ") || trimmed.includes("\u0000")) return { state: "malformed", reason: "whitespace_or_control" };
    return { state: "supported", reason: "scheme_shape_ok" };
  }
  const atSigns = (trimmed.match(/@/g) ?? []).length;
  if (atSigns === 1 && /^[^\s@]+@[^\s@]+$/.test(trimmed)) {
    return { state: "ambiguous", reason: "lightning_address_like_needs_provider_check" };
  }
  if (atSigns > 1) return { state: "malformed", reason: "multiple_at_signs" };
  return { state: "unsupported", reason: "unrecognized_scheme" };
}

export function createBackendSelector({ initialBackend = "mdk-hosted", activatedBackends = ["mdk-hosted"] } = {}) {
  if (!KNOWN_BACKENDS.includes(initialBackend)) throw new Error("unknown initial backend");
  let activeBackend = initialBackend;
  const activated = new Set(activatedBackends);

  return {
    get activeBackend() {
      return activeBackend;
    },
    // Per-user stored choice, reversible (design note section 7.3). Selecting
    // a backend that has not passed its activation gate stores the choice as
    // PENDING but never switches the active payment path: upgrade-path gate keeps
    // user-configured node credentials inactive until the credential
    // lifecycle is implemented and verified.
    selectBackend(backend) {
      if (!KNOWN_BACKENDS.includes(backend)) {
        return { status: "rejected", reason: "unknown_backend" };
      }
      if (!activated.has(backend)) {
        return {
          status: "pending",
          reason: BACKEND_ACTIVATION_GATE,
          active_backend: activeBackend,
        };
      }
      const previous = activeBackend;
      activeBackend = backend;
      return { status: "switched", previous_backend: previous, active_backend: activeBackend };
    },
    projection() {
      // Typed projection only: backend names and states, never connection
      // strings or credentials.
      return {
        active_backend: activeBackend,
        available: [...activated],
        pending_gate: KNOWN_BACKENDS.filter((backend) => !activated.has(backend)).map((backend) => ({
          backend,
          gate: BACKEND_ACTIVATION_GATE,
        })),
      };
    },
  };
}

export function maskConnectionSecret(value) {
  if (typeof value !== "string" || value.trim() === "") {
    return { configured: false, preview: null, opaque_reference: null };
  }
  const lastSegment = value.slice(-4);
  const opaqueReference = createHash("sha256").update(`nwc-ref:${randomBytes(16)}`).digest("hex").slice(0, 12);
  return { configured: true, preview: `••••${lastSegment}`, opaque_reference: opaqueReference };
}

export function createNwcExportConfig({
  thresholdSats = DEFAULT_NWC_EXPORT_THRESHOLD_SATS,
  clock = () => new Date(),
} = {}) {
  if (!Number.isInteger(thresholdSats) || thresholdSats <= 0) throw new Error("thresholdSats must be a positive integer");
  let maskedConnection = { configured: false, preview: null, opaque_reference: null };
  const audit = [];

  function record(event, outcome) {
    // Audit trail of outcomes only — never values, never credentials.
    audit.push({ event, outcome, at: clock().toISOString() });
  }

  return {
    get thresholdSats() {
      return thresholdSats;
    },
    get connectionProjection() {
      return { ...maskedConnection };
    },
    configureConnection(secretValue) {
      maskedConnection = maskConnectionSecret(secretValue);
      record("nwc_connection_configured", "ok");
      return { ...maskedConnection };
    },
    rotateConnection(secretValue) {
      maskedConnection = maskConnectionSecret(secretValue);
      record("nwc_connection_rotated", "ok");
      return { ...maskedConnection };
    },
    setThreshold(sats) {
      if (!Number.isInteger(sats) || sats <= 0) {
        record("nwc_threshold_change", "rejected_invalid_threshold");
        return { status: "rejected", reason: "invalid_threshold" };
      }
      thresholdSats = sats;
      record("nwc_threshold_change", "ok");
      return { status: "ok", threshold_sats: thresholdSats };
    },
    // Operator-gated evaluation: returns the typed decision only. Actor must
    // be the operator; an agent or anonymous actor is refused outright.
    evaluateExport({ balanceSats, actor }) {
      if (actor !== "operator") {
        record("nwc_export_evaluated", "rejected_operator_gate");
        return { status: "rejected", reason: "operator_gate_required" };
      }
      if (!Number.isInteger(balanceSats) || balanceSats < 0) {
        record("nwc_export_evaluated", "rejected_invalid_balance");
        return { status: "rejected", reason: "invalid_balance" };
      }
      if (!maskedConnection.configured) {
        record("nwc_export_evaluated", "rejected_no_connection");
        return { status: "rejected", reason: "no_connection_configured" };
      }
      const comparison = balanceSats < thresholdSats ? "below" : balanceSats === thresholdSats ? "equal" : "above";
      const shouldExport = balanceSats > thresholdSats;
      record("nwc_export_evaluated", shouldExport ? "export_due" : "not_due");
      return { status: "ok", comparison, should_export: shouldExport, threshold_sats: thresholdSats, amount_sats: balanceSats };
    },
    auditTrail() {
      return audit.map((entry) => ({ ...entry }));
    },
  };
}
