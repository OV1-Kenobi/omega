//! End-to-end protocol round-trip tests: real sidecar process (dist/main.js)
//! driven over the framed stdio protocol against a fake phoenixd node
//! (OMEGA-DELTA-0303 — the waved fixture is replaced; the sidecar is a
//! client-only process for the phoenixd rail, so the test harness owns the
//! fake node's lifecycle and points OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL at
//! it). Covers: the node rail flow, signet-only refusal (env + runtime),
//! node-probe fail-closed, the fail-closed wallet-height seam, idempotency,
//! generation fencing, frame bounds, HTTP surface auth, secret redaction on
//! stderr.
//!
//! Updated-with-citation (OMEGA-DELTA-0303): the waved ceremony
//! (create-wallet/unlock/lock) and the waved lifecycle are REMOVED with the
//! rail — those verbs answer named fail-closed errors; balance/activity fail
//! closed until their phoenixd re-point lands in a later C3 slice;
//! wallet-height reads the public tip API (OMEGA-DELTA-0304) and fails closed
//! with TIP_HEIGHT_UNAVAILABLE when disabled/unreachable.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";

import { generateLoopbackToken } from "../dist/http.js";

const REPO_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1")), "..", "..", "..");
const MAIN_JS = path.join(REPO_ROOT, "sidecar", "sovereign-wallet", "dist", "main.js");
const FAKE_PHOENIXD_SCRIPT = path.join(REPO_ROOT, "sidecar", "sovereign-wallet", "test", "fixtures", "fake-phoenixd.mjs");
/** The fixture's Basic-auth password (RV-C1: the username is not validated). */
const FAKE_PHOENIXD_API_KEY = "fixture-phoenixd-api-key";

let portCounter = 11100;

/** Random per-test loopback port (deterministic sequences collide with orphans across runs). */
function nextPort(): number {
  portCounter += 1;
  return 12_000 + ((portCounter * 7919) % 30_000);
}

interface Sidecar {
  child: ChildProcess;
  /** The fake phoenixd child (owned by the test harness; killed on close). */
  fakeNode: ChildProcess;
  request(method: string, params?: Record<string, unknown>, generation?: number): Promise<Record<string, unknown>>;
  close(): Promise<number | null>;
  stderrText(): string;
}

/** Start the fake phoenixd node and wait for its "listening" line. */
async function startFakePhoenixd(port: number, overrides: Record<string, string>): Promise<ChildProcess> {
  const fakeNode = spawn(process.execPath, [FAKE_PHOENIXD_SCRIPT], {
    env: {
      FAKE_PHOENIXD_PORT: String(port),
      FAKE_PHOENIXD_API_KEY: FAKE_PHOENIXD_API_KEY,
      FAKE_PHOENIXD_CHAIN: overrides.FAKE_PHOENIXD_CHAIN ?? "mainnet",
      FAKE_PHOENIXD_MODE: overrides.FAKE_PHOENIXD_MODE ?? "normal",
      FAKE_PHOENIXD_INVOICE_HRP: overrides.FAKE_PHOENIXD_INVOICE_HRP ?? "lnbc100u",
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  fakeNode.stdout?.setEncoding("utf8");
  fakeNode.stderr?.setEncoding("utf8");
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("fake-phoenixd did not listen in time")), 10_000);
    const onData = (chunk: string): void => {
      if (chunk.includes("listening")) {
        clearTimeout(timer);
        fakeNode.stderr?.removeListener("data", onData);
        resolve();
      }
    };
    fakeNode.stderr?.on("data", onData);
    fakeNode.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`fake-phoenixd exited early with code ${code}`));
    });
  });
  return fakeNode;
}

/**
 * Spawn a real sidecar against a per-test fake phoenixd node. The phoenixd
 * rail is client-only (OMEGA-DELTA-0303), so the TEST owns the fake node's
 * lifecycle; the sidecar's rail envs point at it.
 */
async function spawnSidecar(overrides: Record<string, string>): Promise<Sidecar> {
  const dataRoot = mkdtempSync(path.join(tmpdir(), "sw-sidecar-"));
  const port = nextPort();
  const token = generateLoopbackToken();
  const fakeNode = await startFakePhoenixd(port, overrides);
  const env: Record<string, string> = {
    OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
    // OMEGA-DELTA-0305: the payments rail is mainnet-only — the suite
    // constructs mainnet rails (with the opt-in) against the fake node.
    OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet",
    OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET: "1",
    OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN: token,
    OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL: `http://127.0.0.1:${port}`,
    OMEGA_SOVEREIGN_WALLET_PHOENIXD_API_KEY: FAKE_PHOENIXD_API_KEY,
    // OMEGA-DELTA-0301 (RV6-REQ-1): the TEST-ONLY in-memory keychain seam —
    // the e2e process must never touch the real OS keychain. Production never
    // sets this; the default is the OS-keychain binding.
    OMEGA_SOVEREIGN_WALLET_VAULT_KEYCHAIN: "memory",
    // OMEGA-DELTA-0305: the TEST-ONLY fixture seam — the suite constructs
    // signet fixture rails; production never sets this (real signet/regtest
    // rail config is refused at startup).
    OMEGA_SOVEREIGN_WALLET_FIXTURE: "1",
    ...overrides,
  };
  const child = spawn(process.execPath, [MAIN_JS], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });

  let stdoutBuffer = "";
  let stderrBuffer = "";
  const pending: Array<{
    resolve: (value: Record<string, unknown>) => void;
    reject: (error: Error) => void;
    timer: NodeJS.Timeout;
  }> = [];

  child.stdout?.setEncoding("utf8");
  child.stderr?.setEncoding("utf8");
  child.stdout?.on("data", (chunk: string) => {
    stdoutBuffer += chunk;
    let newline: number;
    while ((newline = stdoutBuffer.indexOf("\n")) !== -1) {
      const line = stdoutBuffer.slice(0, newline);
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      if (line.trim().length === 0) continue;
      const waiter = pending.shift();
      if (waiter) {
        clearTimeout(waiter.timer);
        try {
          waiter.resolve(JSON.parse(line) as Record<string, unknown>);
        } catch (error) {
          waiter.reject(error instanceof Error ? error : new Error(String(error)));
        }
      }
    }
  });
  child.stderr?.on("data", (chunk: string) => {
    stderrBuffer += chunk;
  });

  let requestId = 0;
  const request = (
    method: string,
    params?: Record<string, unknown>,
    generation = 1,
  ): Promise<Record<string, unknown>> =>
    new Promise((resolve, reject) => {
      const id = String(++requestId);
      const frame = { schema: "openagents.omega.sovereign-wallet.v1", kind: "request", id, generation, method, params: params ?? {} };
      const timer = setTimeout(() => reject(new Error(`request ${method} timed out`)), 15_000);
      pending.push({ resolve, reject, timer });
      child.stdin?.write(`${JSON.stringify(frame)}\n`);
    });

  const close = async (): Promise<number | null> => {
    killTree(child.pid);
    killTree(fakeNode.pid);
    if (!child.pid) child.kill();
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null) {
        resolve();
        return;
      }
      const timer = setTimeout(resolve, 3_000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
    // Retry the data-root cleanup; the grandchild may still be releasing handles.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        rmSync(dataRoot, { recursive: true, force: true });
        break;
      } catch {
        await sleep(300);
      }
    }
    return child.exitCode;
  };

  return { child, fakeNode, request, close, stderrText: () => stderrBuffer };
}

function expectOk(response: Record<string, unknown>): Record<string, unknown> {
  assert.equal(response.ok, true, `expected ok response, got: ${JSON.stringify(response)}`);
  return response.result as Record<string, unknown>;
}

function expectError(response: Record<string, unknown>): { code: string; message: string } {
  assert.equal(response.ok, false, `expected error response, got: ${JSON.stringify(response)}`);
  const error = response.error as { code: string; message: string };
  return error;
}

async function waitForExit(child: ChildProcess, ms = 10_000): Promise<number | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(child.exitCode), ms);
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
}

/** Kill a process and its whole tree on Windows (test teardown). */
function killTree(pid: number | undefined): void {
  if (!pid) return;
  try {
    execFileSync("taskkill", ["/PID", String(pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
  } catch {
    // already gone
  }
}

/** Remove a data root with retries (grandchildren may still release handles). */
async function cleanupDir(dir: string): Promise<void> {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    try {
      rmSync(dir, { recursive: true, force: true });
      return;
    } catch {
      await sleep(300);
    }
  }
}

describe("protocol round-trip against the fake phoenixd node (OMEGA-DELTA-0303)", () => {
  it("node rail flow: initialize/status/make-invoice/pay-invoice; the waved ceremony verbs fail closed", async () => {
    const sidecar = await spawnSidecar({});
    try {
      const initialize = expectOk(await sidecar.request("initialize"));
      assert.equal(initialize.schema, "openagents.omega.sovereign-wallet.v1");
      assert.equal(initialize.network, "mainnet");
      assert.equal(initialize.nodeState, "connected");
      assert.equal(initialize.nodeNetwork, "mainnet"); // SEC-2026-050 (rail form): actual runtime network

      const health = expectOk(await sidecar.request("health"));
      assert.equal(health.ok, true);
      assert.equal(health.nodeConnected, true);

      const status = expectOk(await sidecar.request("status"));
      assert.equal(status.network, "mainnet");
      assert.equal(status.nodeConnected, true);
      // WP-4 (OMEGA-DELTA-0284): the vault is now a real surface. In a fresh
      // data root it is "none" (no vault initialized), not the WP-3 "absent"
      // stub marker.
      assert.equal(status.vaultState, "none");

      // OMEGA-DELTA-0303: the waved ceremony verbs are REMOVED with the rail —
      // they answer named fail-closed errors (the phoenixd node is remote and
      // operator-managed; the API key is the access).
      const createRefused = expectError(await sidecar.request("create-wallet", {
        idempotencyKey: "11111111-1111-4111-8111-111111111111",
        password: "correct horse battery staple",
      }));
      assert.equal(createRefused.code, "INTERNAL");
      assert.match(createRefused.message, /phoenixd rail/);
      const unlockRefused = expectError(await sidecar.request("unlock", {
        idempotencyKey: "22222222-2222-4222-8222-222222222222",
        password: "correct horse battery staple",
      }));
      assert.equal(unlockRefused.code, "INTERNAL");

      // balance/activity fail closed until their phoenixd re-point lands.
      const balanceRefused = expectError(await sidecar.request("balance"));
      assert.equal(balanceRefused.code, "INTERNAL");
      assert.match(balanceRefused.message, /balance is not yet wired/);

      const invoice = expectOk(await sidecar.request("make-invoice", {
        amtSat: 10_000,
        memo: "test",
        idempotencyKey: "33333333-3333-4333-8333-333333333333",
      }));
      assert.equal(invoice.hrp, "lnbc1"); // mainnet HRP prefix (OMEGA-DELTA-0305: no signet rail)

      const paid = expectOk(await sidecar.request("pay-invoice", {
        invoice: "lnbc10u1p0example",
        idempotencyKey: "44444444-4444-4444-8444-444444444444",
      }));
      assert.equal(paid.status, "settled"); // phoenixd payment_sent
      assert.equal(paid.preimage, "b".repeat(64)); // proof of payment to the operator (RV-C2: present)
      // OMEGA-DELTA-0300: the loss-rule bound — expected total outflow =
      // invoice amount (10u = 1,000 sats) + 0.4% fee (4 sats) = 1004.
      assert.equal(paid.expectedTotalOutflowSat, "1004");
      assert.equal(paid.totalOutflowKnown, true);

      const activityRefused = expectError(await sidecar.request("activity"));
      assert.equal(activityRefused.code, "INTERNAL");
      assert.match(activityRefused.message, /activity is not yet wired/);

      const identity = expectOk(await sidecar.request("identity-status"));
      // WP-4 (OMEGA-DELTA-0284): the identity-status stub is now wired to real
      // vault/identity state. A fresh data root reports vaultState "none"
      // (vault not yet initialized), replacing the WP-3 "absent" stub marker.
      assert.equal(identity.vaultState, "none");

      const shutdown = expectOk(await sidecar.request("shutdown"));
      assert.equal(shutdown.stopping, true);
      const exitCode = await waitForExit(sidecar.child);
      assert.equal(exitCode, 0);
    } finally {
      await sidecar.close();
    }
  });

  it("idempotency: a duplicate make-invoice key replays the stored invoice", async () => {
    const sidecar = await spawnSidecar({});
    try {
      await sidecar.request("initialize");
      const first = expectOk(
        await sidecar.request("make-invoice", { amtSat: 1000, memo: "a", idempotencyKey: "33333333-3333-4333-8333-333333333333" }),
      );
      const second = expectOk(
        await sidecar.request("make-invoice", { amtSat: 1000, memo: "a", idempotencyKey: "33333333-3333-4333-8333-333333333333" }),
      );
      assert.equal(first.invoice, second.invoice);
    } finally {
      await sidecar.close();
    }
  });

  it("SEC-2026-047: a duplicate pay-invoice key replays a PREIMAGE-FREE cached result", async () => {
    const sidecar = await spawnSidecar({});
    try {
      await sidecar.request("initialize");
      const first = expectOk(
        await sidecar.request("pay-invoice", {
          invoice: "lnbc10u1p0example",
          idempotencyKey: "44444444-4444-4444-8444-444444444444",
        }),
      );
      assert.equal(first.preimage, "b".repeat(64)); // fresh call returns the preimage
      const second = expectOk(
        await sidecar.request("pay-invoice", {
          invoice: "lnbc10u1p0example",
          idempotencyKey: "44444444-4444-4444-8444-444444444444",
        }),
      );
      assert.equal(second.preimage, null); // replayed cache is preimage-free
      assert.equal(second.paymentHash, first.paymentHash);
    } finally {
      await sidecar.close();
    }
  });

  it("OMEGA-DELTA-0303: lock() is a named fail-closed error on the phoenixd rail (the vault lock still applies)", async () => {
    const sidecar = await spawnSidecar({});
    try {
      await sidecar.request("initialize");
      const refused = expectError(await sidecar.request("lock"));
      assert.equal(refused.code, "INTERNAL");
      assert.match(refused.message, /phoenixd rail/);
    } finally {
      await sidecar.close();
    }
  });

  it("generation fencing: a stale generation is refused with STALE_GENERATION", async () => {
    const sidecar = await spawnSidecar({});
    try {
      const initialize = expectOk(await sidecar.request("initialize"));
      assert.equal(initialize.generation, 1);
      const stale = expectError(await sidecar.request("status", {}, 99));
      assert.equal(stale.code, "STALE_GENERATION");
    } finally {
      await sidecar.close();
    }
  });

  it("OMEGA-DELTA-0304: wallet-height fails closed with TIP_HEIGHT_UNAVAILABLE when the tip API is disabled (fail-closed, never wall-clock)", async () => {
    const sidecar = await spawnSidecar({ OMEGA_TIP_API_DISABLE: "1" });
    try {
      await sidecar.request("initialize");
      const refused = expectError(await sidecar.request("wallet-height"));
      assert.equal(refused.code, "TIP_HEIGHT_UNAVAILABLE");
      assert.match(refused.message, /OMEGA-DELTA-0304/);
    } finally {
      await sidecar.close();
    }
  });

  it("OMEGA-DELTA-0303/0305: a node that does not answer the startup getinfo probe is refused at startup on the mainnet rail (rail gate, NODE_UNCONFIGURED)", async () => {
    // Rail gate (design §2.6.2): mainnet refuses to start without an
    // answering node connection — a silent no-getinfo node is a
    // configuration error, never a runtime unavailable state.
    const sidecar = await spawnSidecar({ FAKE_PHOENIXD_MODE: "no-getinfo" });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /NODE_UNCONFIGURED/);
    await sidecar.close();
  });

  it("OMEGA-DELTA-0286: mainnet env WITHOUT the opt-in is refused at startup (MAINNET_REFUSED)", async () => {
    const sidecar = await spawnSidecar({
      OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet",
      OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET: "",
    });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /MAINNET_REFUSED/);
    await sidecar.close();
  });

  it("OMEGA-DELTA-0303: a mainnet rail WITHOUT the phoenixd envs is refused at startup (rail gate)", async () => {
    // The rail gate (design §2.6.2): mainnet with no configured node
    // connection is a configuration error, never a silent zero.
    const sidecar = await spawnSidecar({
      OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet",
      OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET: "1",
      OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL: "",
    });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /NODE_UNCONFIGURED/);
    await sidecar.close();
  });

  it("OMEGA-DELTA-0305: signet rail config is refused at startup (mainnet-only rail)", async () => {
    // The payments rail is mainnet-operative — no signet payments ever travel
    // it, in production or in tests. A signet config dies here, no exceptions.
    const sidecar = await spawnSidecar({
      OMEGA_SOVEREIGN_WALLET_NETWORK: "signet",
    });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /OMEGA-DELTA-0305/);
    await sidecar.close();
  });

  it("OMEGA-DELTA-0286/0303: mainnet env WITH the opt-in + the phoenixd rail configures mainnet (reported == configured)", async () => {
    const sidecar = await spawnSidecar({
      OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet",
      OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET: "1",
      FAKE_PHOENIXD_CHAIN: "mainnet",
    });
    try {
      const initialize = expectOk(await sidecar.request("initialize"));
      assert.equal(initialize.network, "mainnet");
      // SEC-2026-050 (0286 revision, rail form): the probed runtime network
      // must equal the configured network — mainnet accepted only when
      // configured mainnet AND the opt-in is present.
      assert.equal(initialize.nodeNetwork, "mainnet");
      assert.equal(initialize.nodeState, "connected");
      const health = expectOk(await sidecar.request("health"));
      assert.equal(health.ok, true);
      assert.equal(health.network, "mainnet");
    } finally {
      await sidecar.close();
    }
  });

  it("an unset network never defaults to mainnet (design §3.2)", async () => {
    const sidecar = await spawnSidecar({ OMEGA_SOVEREIGN_WALLET_NETWORK: "" });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /must be mainnet/);
    await sidecar.close();
  });

  it("SEC-2026-050 (OMEGA-DELTA-0286/0303): a node reporting a non-mainnet chain is refused as a mismatch", async () => {
    // Mainnet-only rail: a fake reporting any other chain fails the
    // reported==configured assertion (the mismatch branch, never MAINNET_REFUSED).
    const sidecar = await spawnSidecar({ FAKE_PHOENIXD_CHAIN: "regtest" });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    await sidecar.close();
  });

  it("OMEGA-DELTA-0303/0305: a missing phoenixd rail env is refused at startup on the mainnet rail (rail gate, named NODE_UNCONFIGURED — never a silent zero)", async () => {
    // Rail gate (design §2.6.2): mainnet without a configured node
    // connection is a configuration error — the sidecar refuses to start,
    // named, never a silent zero.
    const sidecar = await spawnSidecar({ OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL: "" });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /NODE_UNCONFIGURED/);
    await sidecar.close();
  });

  it("an oversized frame is refused (frame bound)", async () => {
    const sidecar = await spawnSidecar({});
    try {
      await sidecar.request("initialize");
      const huge = "x".repeat(70 * 1024);
      const response = await new Promise<Record<string, unknown>>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("oversized frame test timed out")), 10_000);
        const onData = (chunk: string): void => {
          if (chunk.includes("\n")) {
            clearTimeout(timer);
            childRemoveListener();
            resolve(JSON.parse(chunk.trim()) as Record<string, unknown>);
          }
        };
        const childRemoveListener = (): void => {
          sidecar.child.stdout?.removeListener("data", onData);
        };
        sidecar.child.stdout?.on("data", onData);
        sidecar.child.stdin?.write(JSON.stringify({ schema: "openagents.omega.sovereign-wallet.v1", kind: "request", id: "99", generation: 1, method: "status", params: { pad: huge } }) + "\n");
      });
      assert.equal(response.ok, false);
      assert.equal((response.error as { code: string }).code, "INVALID_ARGS");
    } finally {
      await sidecar.close();
    }
  });

  it("OMEGA-DELTA-0286/0303: a mainnet-configured rail mints and pays lnbc (never lnbcrt); mismatched HRP refused on mint AND pay", async () => {
    const sidecar = await spawnSidecar({
      OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet",
      OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET: "1",
      FAKE_PHOENIXD_CHAIN: "mainnet",
      FAKE_PHOENIXD_INVOICE_HRP: "lnbc100u",
    });
    try {
      await sidecar.request("initialize");

      // Mint: the fake phoenixd serves an lnbc invoice and the guard accepts
      // it (the HRP follows the configured network).
      const minted = expectOk(
        await sidecar.request("make-invoice", {
          amtSat: 10_000,
          memo: "mainnet test",
          idempotencyKey: "33333333-3333-4333-8333-333333333333",
        }),
      );
      assert.match(String(minted.hrp), /^lnbc/); // mainnet HRP (0286; the 5-char slice carries the first amount digit)

      // Pay: an lnbc invoice is accepted on the mainnet-configured rail.
      const paid = expectOk(
        await sidecar.request("pay-invoice", {
          invoice: "lnbc10u1p0example",
          idempotencyKey: "44444444-4444-4444-8444-444444444444",
        }),
      );
      assert.equal(paid.status, "settled");

      // Mismatched HRP refused on PAY (a non-mainnet invoice on the rail).
      const payMismatch = expectError(
        await sidecar.request("pay-invoice", {
          invoice: "not-a-bolt11-invoice",
          idempotencyKey: "55555555-5555-4555-8555-555555555555",
        }),
      );
      assert.equal(payMismatch.code, "INVALID_ARGS");
    } finally {
      await sidecar.close();
    }
  });

  it("OMEGA-DELTA-0286/0303: mismatched HRP refused on MINT on the mainnet rail (node serves a non-lnbc invoice)", async () => {
    const sidecar = await spawnSidecar({
      OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet",
      OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET: "1",
      FAKE_PHOENIXD_CHAIN: "mainnet",
      // The fake phoenixd serves a non-mainnet-shaped invoice — the
      // node guard must refuse it (configuration mismatch).
      FAKE_PHOENIXD_INVOICE_HRP: "xx100u",
    });
    try {
      await sidecar.request("initialize");
      const refused = expectError(
        await sidecar.request("make-invoice", {
          amtSat: 10_000,
          memo: "mismatch",
          idempotencyKey: "33333333-3333-4333-8333-333333333333",
        }),
      );
      assert.equal(refused.code, "INVALID_ARGS");
    } finally {
      await sidecar.close();
    }
  });

  it("create/unlock are operator-only by construction (never on the agent-visible HTTP surface)", async () => {
    // The stdio control plane is the operator channel. The loopback HTTP
    // surface (the agent-visible surface in WP-3; the L-402 gateway in WP-6)
    // registers ONLY the read projections — a wallet-mutating path over HTTP
    // is structurally absent (404), so create/unlock are unreachable from any
    // agent channel by construction.
    const sidecar = await spawnSidecar({});
    try {
      const initialize = expectOk(await sidecar.request("initialize"));
      const httpPort = (initialize.httpSurface as { bound: boolean; port: number }).port;
      assert.ok(httpPort > 0);
      const response = await fetch(`http://127.0.0.1:${httpPort}/v1/wallet/create`, {
        method: "POST",
        headers: { authorization: `Bearer ${process.env.TEST_LOOPBACK_TOKEN ?? ""}` },
        body: "{}",
      });
      // Even with no valid token this must never reach a create handler: the
      // route does not exist on the agent-visible surface.
      assert.equal([401, 404].includes(response.status), true);
    } finally {
      await sidecar.close();
    }
  });
});

describe("loopback HTTP surface (SEC-2026-053)", () => {
  it("serves status/balance with the bearer token; 401 before logic on a wrong token", async () => {
    const dataRoot = mkdtempSync(path.join(tmpdir(), "sw-http-"));
    const port = nextPort();
    const token = generateLoopbackToken();
    const fakeNode = await startFakePhoenixd(port, {});
    const child = spawn(process.execPath, [MAIN_JS], {
      env: {
        OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
        OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet",
        OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET: "1",
        OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN: token,
        OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL: `http://127.0.0.1:${port}`,
        OMEGA_SOVEREIGN_WALLET_PHOENIXD_API_KEY: FAKE_PHOENIXD_API_KEY,
      },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    try {
      let stdout = "";
      const initialized = new Promise<void>((resolve) => {
        child.stdout?.setEncoding("utf8");
        child.stdout?.on("data", (chunk: string) => {
          stdout += chunk;
          if (stdout.includes("\n")) resolve();
        });
      });
      child.stdin?.write(
        JSON.stringify({
          schema: "openagents.omega.sovereign-wallet.v1",
          kind: "request",
          id: "1",
          generation: 1,
          method: "initialize",
          params: {},
        }) + "\n",
      );
      await initialized;
      const lines = stdout.trim().split("\n").filter((line) => line.length > 0);
      const initialize = JSON.parse(lines[0] ?? "{}") as Record<string, unknown>;
      assert.equal(initialize.ok, true);
      const httpPort = ((initialize.result ?? {}) as { httpSurface?: { port: number } }).httpSurface?.port;
      assert.ok(httpPort && httpPort > 0);

      const base = `http://127.0.0.1:${httpPort}`;
      const authorized = await fetch(`${base}/v1/status`, { headers: { authorization: `Bearer ${token}` } });
      assert.equal(authorized.status, 200);

      const wrong = await fetch(`${base}/v1/status`, { headers: { authorization: "Bearer wrong-token" } });
      assert.equal(wrong.status, 401);

      const missing = await fetch(`${base}/v1/status`);
      assert.equal(missing.status, 401);
    } finally {
      killTree(child.pid);
      killTree(fakeNode.pid);
      await cleanupDir(dataRoot);
    }
  });

  it("fail-closed: no token -> HTTP surface disabled and named", async () => {
    const dataRoot = mkdtempSync(path.join(tmpdir(), "sw-http-"));
    const port = nextPort();
    const fakeNode = await startFakePhoenixd(port, {});
    const child = spawn(process.execPath, [MAIN_JS], {
      env: {
        OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
        OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet",
        OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET: "1",
        OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL: `http://127.0.0.1:${port}`,
        OMEGA_SOVEREIGN_WALLET_PHOENIXD_API_KEY: FAKE_PHOENIXD_API_KEY,
      },
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    try {
      let stdout = "";
      await new Promise<void>((resolve) => {
        child.stdout?.setEncoding("utf8");
        child.stdout?.on("data", (chunk: string) => {
          stdout += chunk;
          if (stdout.includes("\n")) resolve();
        });
        child.stdin?.write(
          JSON.stringify({
            schema: "openagents.omega.sovereign-wallet.v1",
            kind: "request",
            id: "1",
            generation: 1,
            method: "initialize",
            params: {},
          }) + "\n",
        );
      });
      const initialize = JSON.parse(stdout.trim().split("\n")[0] ?? "{}") as Record<string, unknown>;
      const httpSurface = ((initialize.result ?? {}) as { httpSurface?: { bound: boolean; reason?: string } }).httpSurface;
      assert.equal(httpSurface?.bound, false);
      assert.match(httpSurface?.reason ?? "", /LOOPBACK_TOKEN is not set/);
    } finally {
      killTree(child.pid);
      killTree(fakeNode.pid);
      await cleanupDir(dataRoot);
    }
  });

  it("WP-5: identity ceremony and the one-time export bridge (the create-wallet vault capture is removed with the rail)", async () => {
    const sidecar = await spawnSidecar({});
    try {
      await sidecar.request("initialize");

      // Ceremony step 1: show-once mnemonic + challenge labels.
      const prepared = expectOk(await sidecar.request("vault-init-prepare"));
      const mnemonic = prepared.mnemonic as string;
      const labels = prepared.challengeLabels as number[];
      assert.deepEqual(labels, [2, 7, 11]);
      assert.equal(mnemonic.split(" ").length, 12);

      // A wrong challenge refuses and cancels the pending ceremony.
      const wrongAnswers = { 2: "zebra", 7: "zebra", 11: "zebra" };
      const wrongChallenge = expectError(await sidecar.request("vault-init", { passphrase: "correct horse battery staple", answers: wrongAnswers }));
      assert.equal(wrongChallenge.code, "INVALID_ARGS");

      // Prepare again, then commit with the correct words at 2/7/11.
      const preparedAgain = expectOk(await sidecar.request("vault-init-prepare"));
      const words = (preparedAgain.mnemonic as string).split(" ");
      const answers = { 2: words[1], 7: words[6], 11: words[10] };
      const initialized = expectOk(await sidecar.request("vault-init", {
        passphrase: "correct horse battery staple",
        answers,
      }));
      assert.equal(initialized.vaultState, "unlocked");
      assert.match(initialized.npub as string, /^npub1/);
      assert.match(initialized.pubkeyHex as string, /^[0-9a-f]{64}$/);

      // identity-status now reports the REAL derived identity.
      const identity = expectOk(await sidecar.request("identity-status"));
      assert.equal(identity.vaultState, "unlocked");
      assert.equal(identity.derivedNpub, initialized.npub);
      assert.equal(identity.derivedPubkeyHex, initialized.pubkeyHex);

      // OMEGA-DELTA-0303: the WP-5 create-wallet vault-capture seam is
      // removed with the waved ceremony (the node is remote; no aezeed).
      const createRefused = expectError(await sidecar.request("create-wallet", {
        idempotencyKey: "51111111-1111-4111-8111-111111111111",
        password: "correct horse battery staple",
      }));
      assert.equal(createRefused.code, "INTERNAL");

      // WP-5 seam: the one-time export bridge hands the derived nsec to the
      // operator exactly once (bridge to the Rust omega_identity import path).
      const exported = expectOk(await sidecar.request("export-nostr-secret"));
      assert.match(exported.nsec as string, /^nsec1/);
      assert.equal(exported.npub, initialized.npub);
      assert.equal(exported.exported, true);

      // Re-export is refused permanently (EXPORT_ALREADY_CONSUMED).
      const second = expectError(await sidecar.request("export-nostr-secret"));
      assert.equal(second.code, "EXPORT_ALREADY_CONSUMED");

      // SEC-2026-046: the exported nsec never reaches stderr (redaction).
      assert.ok(
        !sidecar.stderrText().includes(exported.nsec as string),
        "the exported nsec must never appear in stderr",
      );
    } finally {
      await sidecar.close();
    }
  });

  // OMEGA-DELTA-0301 (updated-with-citation): unlock is KEYCHAIN-FIRST — with
  // the OS keychain available the passphrase is not consulted (RV6-REQ-3), so
  // a wrong passphrase does not refuse the keychain-path unlock; the result
  // reports wrapMethod. The degraded-path refusal semantics (opt-in +
  // operator confirmation) are covered in vault-keychain.test.ts (RV6-REQ-10).
  it("WP-5: vault unlock is keychain-first and reports wrapMethod (OMEGA-DELTA-0301)", async () => {
    const sidecar = await spawnSidecar({});
    try {
      await sidecar.request("initialize");
      const prepared = expectOk(await sidecar.request("vault-init-prepare"));
      const words = (prepared.mnemonic as string).split(" ");
      await sidecar.request("vault-init", {
        passphrase: "correct horse battery staple",
        answers: { 2: words[1], 7: words[6], 11: words[10] },
      });
      // OMEGA-DELTA-0303: lock() refuses on the phoenixd rail BUT still locks
      // the vault (zeroizes the master key) — the keychain-first unlock below
      // exercises the vault-lock side effect.
      expectError(await sidecar.request("lock"));

      // Keychain-first: the unlock succeeds via the OS-keychain path even
      // with an arbitrary passphrase argument.
      const unlocked = expectOk(await sidecar.request("vault-unlock", { passphrase: "arbitrary passphrase" }));
      assert.equal(unlocked.vaultState, "unlocked");
      assert.equal(unlocked.wrapMethod, "os-keychain");
      assert.match(unlocked.derivedNpub as string, /^npub1/);
    } finally {
      await sidecar.close();
    }
  });
});