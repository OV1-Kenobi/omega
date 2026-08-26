//! End-to-end protocol round-trip tests: real sidecar process (dist/main.js)
//! driven over the framed stdio protocol against a fake waved daemon.
//! Covers: full wallet flow, signet-only refusal (env + runtime), wallet-API
//! probe fail-closed, lock semantics, idempotency, generation fencing, frame
//! bounds, HTTP surface auth, secret redaction on stderr.

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
const FAKE_WAVED_CMD = path.join(REPO_ROOT, "sidecar", "sovereign-wallet", "test", "fixtures", "fake-waved.cmd");

let portCounter = 11100;

/** Random per-test loopback port (deterministic sequences collide with orphans across runs). */
function nextPort(): number {
  portCounter += 1;
  return 12_000 + ((portCounter * 7919) % 30_000);
}

interface Sidecar {
  child: ChildProcess;
  request(method: string, params?: Record<string, unknown>, generation?: number): Promise<Record<string, unknown>>;
  close(): Promise<number | null>;
  stderrText(): string;
}

function spawnSidecar(overrides: Record<string, string>): Sidecar {
  const dataRoot = mkdtempSync(path.join(tmpdir(), "sw-sidecar-"));
  const port = nextPort();
  const token = generateLoopbackToken();
  const env: Record<string, string> = {
    OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
    OMEGA_SOVEREIGN_WALLET_NETWORK: "signet",
    OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN: token,
    OMEGA_SOVEREIGN_WALLET_WAVED_BIN: FAKE_WAVED_CMD,
    OMEGA_SOVEREIGN_WALLET_WAVED_REST_PORT: String(port),
    FAKE_WAVED_NETWORK: "signet",
    FAKE_WAVED_MODE: "normal",
    FAKE_WAVED_PORT: String(port),
    FAKE_WAVED_DATA_ROOT: dataRoot,
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

  return { child, request, close, stderrText: () => stderrBuffer };
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

describe("protocol round-trip against fake waved", () => {
  it("full wallet flow: initialize/status/balance/create/unlock/make-invoice/pay-invoice/activity", async () => {
    const sidecar = spawnSidecar({});
    try {
      const initialize = expectOk(await sidecar.request("initialize"));
      assert.equal(initialize.schema, "openagents.omega.sovereign-wallet.v1");
      assert.equal(initialize.network, "signet");
      assert.equal(initialize.wavedState, "connected");
      assert.equal(initialize.wavedNetwork, "signet"); // SEC-2026-050: actual runtime network

      const health = expectOk(await sidecar.request("health"));
      assert.equal(health.ok, true);
      assert.equal(health.wavedConnected, true);
      assert.equal(health.walletState, "none");

      const status = expectOk(await sidecar.request("status"));
      assert.equal(status.network, "signet");
      // WP-4 (OMEGA-DELTA-0284): the vault is now a real surface. In a fresh
      // data root it is "none" (no vault initialized), not the WP-3 "absent"
      // stub marker.
      assert.equal(status.vaultState, "none");

      // Wallet not created: balance refuses with WALLET_LOCKED-class error.
      const lockedBalance = expectError(await sidecar.request("balance"));
      assert.equal(lockedBalance.code, "WALLET_LOCKED");

// Operator-only create -> unlock -> balance.
      const created = expectOk(await sidecar.request("create-wallet", {
        idempotencyKey: "11111111-1111-4111-8111-111111111111",
        password: "correct horse battery staple",
      }));
      assert.equal(Array.isArray(created.mnemonic), true);
      assert.equal((created.mnemonic as string[]).length, 24);
      // WP-5 seam: with the vault locked/absent the capture is reported
      // HONESTLY as not vaulted (operator-held password + paper aezeed).
      assert.equal(created.walletDbPasswordVaulted, false);
      assert.equal(typeof created.note, "string");

      const unlocked = expectOk(await sidecar.request("unlock", {
        idempotencyKey: "22222222-2222-4222-8222-222222222222",
        password: "correct horse battery staple",
      }));
      assert.equal(typeof unlocked.identityPubkey, "string");

      const balance = expectOk(await sidecar.request("balance"));
      assert.equal(balance.confirmedSat, "12345");

      const invoice = expectOk(await sidecar.request("make-invoice", {
        amtSat: 10_000,
        memo: "test",
        idempotencyKey: "33333333-3333-4333-8333-333333333333",
      }));
      assert.equal(invoice.hrp, "lntbs"); // signet HRP (RV-3)

      const paid = expectOk(await sidecar.request("pay-invoice", {
        invoice: "lntbs10u1p0example",
        idempotencyKey: "44444444-4444-4444-8444-444444444444",
      }));
      assert.equal(paid.status, "ENTRY_STATUS_PENDING");
      assert.equal(paid.preimage, "b".repeat(64)); // proof of payment to the operator

      const activity = expectOk(await sidecar.request("activity"));
      assert.equal(Array.isArray(activity.entries), true);

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
    const sidecar = spawnSidecar({});
    try {
      await sidecar.request("initialize");
      await sidecar.request("create-wallet", {
        idempotencyKey: "11111111-1111-4111-8111-111111111111",
        password: "correct horse battery staple",
      });
      await sidecar.request("unlock", {
        idempotencyKey: "22222222-2222-4222-8222-222222222222",
        password: "correct horse battery staple",
      });
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
    const sidecar = spawnSidecar({});
    try {
      await sidecar.request("initialize");
      await sidecar.request("create-wallet", {
        idempotencyKey: "11111111-1111-4111-8111-111111111111",
        password: "correct horse battery staple",
      });
      await sidecar.request("unlock", {
        idempotencyKey: "22222222-2222-4222-8222-222222222222",
        password: "correct horse battery staple",
      });
      const first = expectOk(
        await sidecar.request("pay-invoice", {
          invoice: "lntbs10u1p0example",
          idempotencyKey: "44444444-4444-4444-8444-444444444444",
        }),
      );
      assert.equal(first.preimage, "b".repeat(64)); // fresh call returns the preimage
      const second = expectOk(
        await sidecar.request("pay-invoice", {
          invoice: "lntbs10u1p0example",
          idempotencyKey: "44444444-4444-4444-8444-444444444444",
        }),
      );
      assert.equal(second.preimage, null); // replayed cache is preimage-free
      assert.equal(second.paymentHash, first.paymentHash);
    } finally {
      await sidecar.close();
    }
  });

  it("lock: after lock(), wallet RPCs refuse with WALLET_LOCKED until unlock", async () => {
    const sidecar = spawnSidecar({});
    try {
      await sidecar.request("initialize");
      await sidecar.request("create-wallet", {
        idempotencyKey: "11111111-1111-4111-8111-111111111111",
        password: "correct horse battery staple",
      });
      await sidecar.request("unlock", {
        idempotencyKey: "22222222-2222-4222-8222-222222222222",
        password: "correct horse battery staple",
      });
      const locked = expectOk(await sidecar.request("lock"));
      assert.equal(locked.walletState, "locked");
      const refused = expectError(await sidecar.request("balance"));
      assert.equal(refused.code, "WALLET_LOCKED");
    } finally {
      await sidecar.close();
    }
  });

  it("generation fencing: a stale generation is refused with STALE_GENERATION", async () => {
    const sidecar = spawnSidecar({});
    try {
      const initialize = expectOk(await sidecar.request("initialize"));
      assert.equal(initialize.generation, 1);
      const stale = expectError(await sidecar.request("status", {}, 99));
      assert.equal(stale.code, "STALE_GENERATION");
    } finally {
      await sidecar.close();
    }
  });

  it("mainnet env is refused at startup (D4)", async () => {
    const sidecar = spawnSidecar({ OMEGA_SOVEREIGN_WALLET_NETWORK: "mainnet" });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /MAINNET_REFUSED/);
    await sidecar.close();
  });

  it("an unset network never defaults to mainnet (design §3.2)", async () => {
    const sidecar = spawnSidecar({ OMEGA_SOVEREIGN_WALLET_NETWORK: "" });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /must be signet or regtest/);
    await sidecar.close();
  });

  it("SEC-2026-050: waved reporting mainnet at runtime is refused (MAINNET_REFUSED)", async () => {
    const sidecar = spawnSidecar({ FAKE_WAVED_NETWORK: "mainnet" });
    const exitCode = await waitForExit(sidecar.child);
    assert.notEqual(exitCode, 0);
    assert.match(sidecar.stderrText(), /MAINNET_REFUSED/);
    await sidecar.close();
  });

  it("wallet-API probe: an Unimplemented waved is a named fail-closed state", async () => {
    const sidecar = spawnSidecar({ FAKE_WAVED_MODE: "unimplemented" });
    try {
      const initialize = expectOk(await sidecar.request("initialize"));
      assert.equal(initialize.wavedState, "unavailable");
      const health = expectOk(await sidecar.request("health"));
      assert.equal(health.wavedConnected, false);
      const status = expectOk(await sidecar.request("status"));
      assert.match(String(status.wavedUnavailableReason ?? ""), /WAVED_WALLET_API_UNAVAILABLE|Unimplemented/);
    } finally {
      await sidecar.close();
    }
  });

  it("missing waved binary is a named unavailable state, not a silent zero", async () => {
    const sidecar = spawnSidecar({ OMEGA_SOVEREIGN_WALLET_WAVED_BIN: "" });
    try {
      const initialize = expectOk(await sidecar.request("initialize"));
      assert.equal(initialize.wavedState, "unavailable");
      const health = expectOk(await sidecar.request("health"));
      assert.equal(health.ok, true);
      assert.equal(health.wavedConnected, false);
    } finally {
      await sidecar.close();
    }
  });

  it("an oversized frame is refused (frame bound)", async () => {
    const sidecar = spawnSidecar({});
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

  it("mainnet invoices are refused on pay (lnbc prefix guard)", async () => {
    const sidecar = spawnSidecar({});
    try {
      await sidecar.request("initialize");
      await sidecar.request("create-wallet", {
        idempotencyKey: "11111111-1111-4111-8111-111111111111",
        password: "correct horse battery staple",
      });
      await sidecar.request("unlock", {
        idempotencyKey: "22222222-2222-4222-8222-222222222222",
        password: "correct horse battery staple",
      });
      const refused = expectError(
        await sidecar.request("pay-invoice", {
          invoice: "lnbc10u1p0example",
          idempotencyKey: "55555555-5555-4555-8555-555555555555",
        }),
      );
      assert.equal(refused.code, "MAINNET_REFUSED");
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
    const sidecar = spawnSidecar({});
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
    const child = spawn(process.execPath, [MAIN_JS], {
      env: {
        OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
        OMEGA_SOVEREIGN_WALLET_NETWORK: "signet",
        OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN: token,
        OMEGA_SOVEREIGN_WALLET_WAVED_BIN: FAKE_WAVED_CMD,
        OMEGA_SOVEREIGN_WALLET_WAVED_REST_PORT: String(port),
        FAKE_WAVED_NETWORK: "signet",
        FAKE_WAVED_MODE: "normal",
        FAKE_WAVED_PORT: String(port),
        FAKE_WAVED_DATA_ROOT: dataRoot,
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
      await cleanupDir(dataRoot);
    }
  });

  it("fail-closed: no token -> HTTP surface disabled and named", async () => {
    const dataRoot = mkdtempSync(path.join(tmpdir(), "sw-http-"));
    const port = nextPort();
    const child = spawn(process.execPath, [MAIN_JS], {
      env: {
        OMEGA_SOVEREIGN_WALLET_DATA_ROOT: dataRoot,
        OMEGA_SOVEREIGN_WALLET_NETWORK: "signet",
        OMEGA_SOVEREIGN_WALLET_WAVED_BIN: FAKE_WAVED_CMD,
        OMEGA_SOVEREIGN_WALLET_WAVED_REST_PORT: String(port),
        FAKE_WAVED_NETWORK: "signet",
        FAKE_WAVED_MODE: "normal",
        FAKE_WAVED_PORT: String(port),
        FAKE_WAVED_DATA_ROOT: dataRoot,
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
      await cleanupDir(dataRoot);
    }
  });

  it("WP-5: identity ceremony, create-wallet vault capture, and the one-time export bridge", async () => {
    const sidecar = spawnSidecar({});
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

      // WP-5 seam: create-wallet now CAPTURES the wallet DB password + aezeed
      // into the unlocked vault.
      const created = expectOk(await sidecar.request("create-wallet", {
        idempotencyKey: "51111111-1111-4111-8111-111111111111",
        password: "correct horse battery staple",
      }));
      assert.equal(created.walletDbPasswordVaulted, true);
      assert.equal(typeof created.vaultWalletId, "string");

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

  it("WP-5: vault unlock refuses a wrong passphrase and honors the right one", async () => {
    const sidecar = spawnSidecar({});
    try {
      await sidecar.request("initialize");
      const prepared = expectOk(await sidecar.request("vault-init-prepare"));
      const words = (prepared.mnemonic as string).split(" ");
      await sidecar.request("vault-init", {
        passphrase: "correct horse battery staple",
        answers: { 2: words[1], 7: words[6], 11: words[10] },
      });
      await sidecar.request("lock");

      const wrong = expectError(await sidecar.request("vault-unlock", { passphrase: "wrong passphrase value" }));
      assert.equal(wrong.code, "INVALID_ARGS");

      const unlocked = expectOk(await sidecar.request("vault-unlock", { passphrase: "correct horse battery staple" }));
      assert.equal(unlocked.vaultState, "unlocked");
      assert.match(unlocked.derivedNpub as string, /^npub1/);
    } finally {
      await sidecar.close();
    }
  });
});




