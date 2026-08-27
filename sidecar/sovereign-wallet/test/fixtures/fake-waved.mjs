#!/usr/bin/env node
//! Fake waved daemon for WP-3 tests. Speaks the verified WalletService REST
//! surface (api/rest.md + api/wallet/*) on 127.0.0.1:FAKE_WAVED_PORT
//! (default 10031). Modes via env:
//!   FAKE_WAVED_NETWORK  signet (default) | mainnet | regtest
//!   FAKE_WAVED_MODE     normal | unimplemented | flaky
//!   FAKE_WAVED_PORT     default 10031
//!   FAKE_WAVED_DATA_ROOT  when set, writes <root>/wavelength/data/<network>/admin.macaroon
//! It accepts the real waved launch args and ignores them (the sidecar spawns
//! it exactly like the real daemon).

import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { buildTestBolt11 } from "./build-bolt11.mjs";

const network = process.env.FAKE_WAVED_NETWORK ?? "signet";
const mode = process.env.FAKE_WAVED_MODE ?? "normal";
const port = Number.parseInt(process.env.FAKE_WAVED_PORT ?? "10031", 10);
const dataRoot = process.env.FAKE_WAVED_DATA_ROOT;

// Self-cleaning watchdog: when the spawning sidecar dies (abrupt kill paths),
// this fake exits instead of lingering and holding ports/pipes. Windows has no
// parent-death signal, so poll tasklist for the parent pid.
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
// recv invoice's BOLT11 `p` field carries PAYMENT_HASH so the gateway's
// server-side payment-hash derivation (SEC-2026-055) parses a REAL BOLT11.
const PREIMAGE = "b".repeat(64);
const PAYMENT_HASH = createHash("sha256").update(Buffer.from(PREIMAGE, "hex")).digest("hex");
const LNTCBS_INVOICE = buildTestBolt11(PAYMENT_HASH);

const statusBody = () => ({
  ready: true,
  unlocked: true,
  network,
  balance: {
    confirmed_sat: "12345",
    pending_in_sat: "500",
    pending_out_sat: "0",
    credit_available_sat: "0",
    credit_reserved_sat: "0",
  },
  pending_count: 1,
});

const entry = (kind, status, amountSat) => ({
  id: PAYMENT_HASH,
  kind,
  status,
  amount_sat: String(amountSat),
  fee_sat: "0",
  counterparty: "fake",
  created_at_unix: "1700000000",
  updated_at_unix: "1700000001",
  note: "",
  failure_reason: "",
  request: { lightning_invoice: { invoice: LNTCBS_INVOICE, payment_hash: PAYMENT_HASH } },
  progress: { phase: "WALLET_ENTRY_PHASE_CONFIRMED", phase_label: "confirmed", payment_hash: PAYMENT_HASH, preimage: PREIMAGE },
});

const routes = {
  "/v1/wallet/status": () => statusBody(),
  "/v1/wallet/balance": () => statusBody().balance,
  "/v1/wallet/recv": () => ({ invoice: LNTCBS_INVOICE, entry: entry("ENTRY_KIND_RECV", "ENTRY_STATUS_PENDING", 10000) }),
  "/v1/wallet/prepare-send": () => ({
    send_intent_id: "intent-1",
    amount_sat: "10000",
    expected_fee_sat: "50",
    fee_known: true,
    expected_total_outflow_sat: "10050",
    total_outflow_known: true,
    rail: "SEND_RAIL_LIGHTNING",
    quote_status: "SEND_QUOTE_STATUS_COMPLETE",
    destination_summary: "fake",
    invoice_description: "fake",
    payment_hash: PAYMENT_HASH,
    expires_at_unix: "1800000000",
    selected_outpoints: [],
    warning: "",
  }),
  "/v1/wallet/send": () => ({ entry: entry("ENTRY_KIND_SEND", "ENTRY_STATUS_PENDING", -10000), actual_amount_sat: "10050" }),
  "/v1/wallet/list": () => ({
    activity: { entries: [entry("ENTRY_KIND_SEND", "ENTRY_STATUS_COMPLETE", -10000)], total: 1, has_more: false, next_cursor: "" },
  }),
  "/v1/wallet/create": () => ({
    mnemonic: ["abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"],
    identity_pubkey: "02" + "c".repeat(64),
  }),
  "/v1/wallet/unlock": () => ({ identity_pubkey: "02" + "c".repeat(64) }),
};

const server = createServer((req, res) => {
  if (mode === "unimplemented") {
    // grpc-gateway UNIMPLEMENTED shape (code 12) — the wallet-API stub answer.
    res.writeHead(501, { "content-type": "application/json" });
    res.end(JSON.stringify({ code: 12, message: "unknown service wavewalletrpc.WalletService", details: [] }));
    return;
  }
  let body = "";
  req.on("data", (chunk) => (body += chunk.toString("utf8")));
  req.on("end", async () => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const handler = routes[url.pathname];
    if (!handler) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ code: 5, message: "not found", details: [] }));
      return;
    }
    if (dataRoot && url.pathname === "/v1/wallet/status") {
      // Exercise the macaroon-file path once at startup.
      const macaroonPath = path.join(dataRoot, "wavelength", "data", network, "admin.macaroon");
      await fs.mkdir(path.dirname(macaroonPath), { recursive: true });
      await fs.writeFile(macaroonPath, "020103fake-macaroon-hex", "utf8");
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(handler()));
  });
});

server.listen(port, "127.0.0.1", () => {
  process.stderr.write(`fake-waved listening on 127.0.0.1:${port} network=${network} mode=${mode}\n`);
});