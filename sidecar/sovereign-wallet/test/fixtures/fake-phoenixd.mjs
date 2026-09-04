#!/usr/bin/env node
//! Fake phoenixd node for the OMEGA-DELTA-0303 sidecar tests. Speaks the
//! verified phoenixd REST surface (Api.kt / ApiType.kt, ACINQ/phoenixd) on
//! 127.0.0.1:FAKE_PHOENIXD_PORT (default 9740): HTTP Basic auth (any
//! username; password must equal FAKE_PHOENIXD_API_KEY), form-encoded
//! request bodies, and the `type` discriminator on the payment envelope.
//! Modes via env:
//!   FAKE_PHOENIXD_CHAIN       signet (default) | mainnet — the getinfo
//!                             `chain` field (the SEC-2026-050 report source;
//!                             fixture-only values — a real node reports
//!                             mainnet/testnet).
//!   FAKE_PHOENIXD_MODE        normal | no-getinfo | pay-failed-timeout |
//!                             over-settle
//!   FAKE_PHOENIXD_PORT        default 9740
//!   FAKE_PHOENIXD_API_KEY     the password accepted on the Basic header
//!   FAKE_PHOENIXD_INVOICE_HRP default lntbs100u (lnbc100u for mainnet tests)
//! The sidecar does NOT spawn this process (the phoenixd rail is client-only);
//! the test harness owns its lifecycle and points OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL
//! at it. Self-cleaning watchdog: exits when the parent test process dies.

import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { buildTestBolt11 } from "./build-bolt11.mjs";

const chain = process.env.FAKE_PHOENIXD_CHAIN ?? "signet";
const mode = process.env.FAKE_PHOENIXD_MODE ?? "normal";
const port = Number.parseInt(process.env.FAKE_PHOENIXD_PORT ?? "9740", 10);
const apiKey = process.env.FAKE_PHOENIXD_API_KEY ?? "fixture-phoenixd-api-key";
const invoiceHrp = process.env.FAKE_PHOENIXD_INVOICE_HRP ?? "lntbs100u";

// Self-cleaning watchdog: when the owning test process dies, this fake exits
// instead of lingering and holding ports. Windows has no parent-death signal,
// so poll tasklist for the parent pid.
const parentPid = process.ppid;
const watchdog = setInterval(() => {
  if (process.platform !== "win32") return;
  const probe = spawnSync("tasklist", ["/FI", `PID eq ${parentPid}`, "/NH"], {
    windowsHide: true,
    encoding: "utf8",
  });
  if (probe.status !== 0 || !probe.stdout.includes(String(parentPid))) {
    clearInterval(watchdog);
    process.exit(0);
  }
}, 2_000);

// The L-402 proof invariant: sha256(preimage) == paymentHash. The fake pays
// with PREIMAGE and reports PAYMENT_HASH = sha256(decoded PREIMAGE), and the
// minted invoice's BOLT11 `p` field carries PAYMENT_HASH so the gateway's
// server-side payment-hash derivation (SEC-2026-055) parses a REAL BOLT11.
const PREIMAGE = "b".repeat(64);
const PAYMENT_HASH = createHash("sha256").update(Buffer.from(PREIMAGE, "hex")).digest("hex");
const MINTED_INVOICE = buildTestBolt11(PAYMENT_HASH, invoiceHrp);

function authOk(req) {
  const header = req.headers.authorization ?? "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) return false;
  // RV-C1: the username is NOT validated by phoenixd (only the password is).
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const password = decoded.includes(":") ? decoded.slice(decoded.indexOf(":") + 1) : "";
  return password === apiKey;
}

function readForm(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk.toString("utf8")));
    req.on("end", () => resolve(new URLSearchParams(body)));
  });
}

function respond(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  if (!authOk(req)) {
    respond(res, 401, { message: "Invalid authentication (use basic auth with the http password set in phoenix.conf)" });
    return;
  }
  if (url.pathname === "/getinfo") {
    if (mode === "no-getinfo") {
      respond(res, 404, { message: "Unknown endpoint (check api doc)" });
      return;
    }
    respond(res, 200, {
      nodeId: "02" + "a".repeat(64),
      channels: [],
      chain,
      blockHeight: 250_000,
      version: "fixture",
    });
    return;
  }
  if (url.pathname === "/createinvoice" && req.method === "POST") {
    const form = await readForm(req);
    const amountSat = Number.parseInt(form.get("amountSat") ?? "0", 10);
    const description = form.get("description") ?? "";
    respond(res, 200, {
      amountSat: Number.isFinite(amountSat) ? amountSat : null,
      paymentHash: PAYMENT_HASH,
      serialized: MINTED_INVOICE,
    });
    return;
  }
  if (url.pathname === "/payinvoice" && req.method === "POST") {
    const form = await readForm(req);
    const invoice = form.get("invoice") ?? "";
    if (mode === "pay-failed-timeout") {
      respond(res, 200, {
        type: "payment_failed",
        paymentHash: PAYMENT_HASH,
        offerId: null,
        reason: "the payment timed out (fixture mode)",
      });
      return;
    }
    if (mode === "over-settle") {
      // OMEGA-DELTA-0300 loss rule: actual (recipient + routing) > expected
      // (invoice amount + 0.4% fee) -> the Rust choke point auto-kills.
      respond(res, 200, {
        type: "payment_sent",
        recipientAmountSat: 10_005,
        routingFeeSat: 0,
        paymentId: "fixture-payment-1",
        paymentHash: PAYMENT_HASH,
        paymentPreimage: PREIMAGE,
      });
      return;
    }
    respond(res, 200, {
      type: "payment_sent",
      recipientAmountSat: 1_000,
      routingFeeSat: 0,
      paymentId: "fixture-payment-1",
      paymentHash: PAYMENT_HASH,
      paymentPreimage: PREIMAGE,
    });
    return;
  }
  respond(res, 404, { message: "Unknown endpoint (check api doc)" });
});

server.listen(port, "127.0.0.1", () => {
  process.stderr.write(`fake-phoenixd listening on 127.0.0.1:${port} chain=${chain} mode=${mode}\n`);
});