#!/usr/bin/env node
//! Operator-exercise path for the sovereign wallet sidecar (Q3 accepted:
//! create/unlock are operator-only and never on the agent channel; WP-5 wires
//! the dashboard ceremony — until then, this small CLI is the operator path).
//!
//! Usage:
//!   node scripts/operator.mjs <data-root> <command> [args...]
//!
//! Commands:
//!   status | identity-status | balance | activity
//!   create-wallet <password>            (operator-only; shows the aezeed once)
//!   unlock <password>                   (operator-only)
//!   lock                                (operator-only)
//!   make-invoice <amt-sat> [memo]
//!   pay-invoice <bolt11>
//!   shutdown
//!
//! Environment: OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN (required),
//! OMEGA_SOVEREIGN_WALLET_WAVED_BIN (required for wallet commands), and the
//! sidecar build must exist (npm run build). This tool NEVER exposes the
//! L-402/agent surface; it talks only to the stdio control plane.

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MAIN_JS = path.join(ROOT, "dist", "main.js");

const [dataRoot, command, ...rest] = process.argv.slice(2);
if (!dataRoot || !command) {
  console.error("usage: node scripts/operator.mjs <data-root> <command> [args...]");
  process.exit(2);
}

const token = process.env.OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN;
if (!token) {
  console.error("OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN is required (the supervisor generates it per launch)");
  process.exit(2);
}

const child = spawn(process.execPath, [MAIN_JS], {
  env: {
    OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
    OMEGA_SOVEREIGN_WALLET_NETWORK: process.env.OMEGA_SOVEREIGN_WALLET_NETWORK ?? "signet",
    OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN: token,
    OMEGA_SOVEREIGN_WALLET_WAVED_BIN: process.env.OMEGA_SOVEREIGN_WALLET_WAVED_BIN ?? "",
    ...(process.env.OMEGA_SOVEREIGN_WALLET_WAVED_REST_PORT
      ? { OMEGA_SOVEREIGN_WALLET_WAVED_REST_PORT: process.env.OMEGA_SOVEREIGN_WALLET_WAVED_REST_PORT }
      : {}),
  },
  stdio: ["pipe", "pipe", "inherit"],
  windowsHide: true,
});

let buffer = "";
const pending = [];
child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk) => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf("\n")) !== -1) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    if (line.trim().length === 0) continue;
    const resolve = pending.shift();
    if (resolve) resolve(JSON.parse(line));
  }
});

function request(id, method, params = {}) {
  return new Promise((resolve) => {
    pending.push(resolve);
    child.stdin.write(
      JSON.stringify({
        schema: "openagents.omega.sovereign-wallet.v1",
        kind: "request",
        id: String(id),
        generation: 1,
        method,
        params,
      }) + "\n",
    );
  });
}

const paramsFor = (command) => {
  switch (command) {
    case "create-wallet":
      return { idempotencyKey: crypto.randomUUID(), password: rest[0] ?? "" };
    case "unlock":
      return { idempotencyKey: crypto.randomUUID(), password: rest[0] ?? "" };
    case "make-invoice":
      return { amtSat: Number.parseInt(rest[0] ?? "0", 10), memo: rest[1] ?? "operator", idempotencyKey: crypto.randomUUID() };
    case "pay-invoice":
      return { invoice: rest[0] ?? "", idempotencyKey: crypto.randomUUID() };
    default:
      return {};
  }
};

const flow = async () => {
  let id = 0;
  const initialize = await request(++id, "initialize");
  if (!initialize.ok) {
    console.error("initialize failed:", initialize.error);
    process.exit(1);
  }
  const result = await request(++id, command, paramsFor(command));
  console.log(JSON.stringify(result, null, 2));
  if (command === "shutdown") {
    await new Promise((resolve) => setTimeout(resolve, 500));
    process.exit(0);
  }
  const shutdown = await request(++id, "shutdown");
  console.log(JSON.stringify(shutdown, null, 2));
  await new Promise((resolve) => setTimeout(resolve, 500));
  process.exit(0);
};

flow().catch((error) => {
  console.error(error);
  process.exit(1);
});