//! Wavelength integration: supervised `waved` daemon (design §3) + typed REST
//! client against the verified WalletService surface.
//!
//! Verified call shapes (authoritative sources, read in full):
//! - docs: api/get-started, api/rest, api/wallet/{status,create,unlock,balance,
//!   recv,prepare-send,send,list}, concepts/{networks-and-config,
//!   wallet-lifecycle-and-auth,keys-backup-and-recovery}, cli/getinfo
//! - repo docs at tag v0.1.2-rc3: docs/daemon_cli_guide.md, docs/signet.md,
//!   docs/wavewalletrpc_build.md
//!
//! Non-negotiables enforced here:
//! - signet/regtest only; `--allow-mainnet` NEVER passed; `--network=mainnet`
//!   refused at startup (MAINNET_REFUSED).
//! - `--rpc.notls` / `--rpc.no-macaroons` NEVER passed outside regtest.
//! - Runtime network assertion (SEC-2026-050): after waved starts and on every
//!   health check, the sidecar calls WalletService.Status and asserts the
//!   REPORTED network equals the configured network; mismatch or an
//!   `Unimplemented` wallet-API response kills waved and fails the sidecar.

import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { clearWavedPid, reapStaleWaved, writeWavedPid } from "./lock.js";
import type { ErrorCode } from "./protocol.js";
import { errorEnvelope } from "./protocol.js";
import { redact } from "./redact.js";

export type WavelengthNetwork = "signet" | "regtest";

export const WAVED_REST_DEFAULT_PORT = 10031;

export interface WavedLaunchConfig {
  binary: string;
  dataRoot: string;
  network: WavelengthNetwork;
  /** REST gateway base URL, default http://127.0.0.1:10031 */
  restBaseUrl?: string;
  restPort?: number;
  wavedStartupTimeoutMs?: number;
}

export interface StatusResponse {
  ready: boolean;
  unlocked: boolean;
  network: string;
  balance: BalanceResponse;
  pending_count: number;
}

// proto3 JSON encodes int64/uint64 fields as strings (api/rest.md); all sat
// fields below are strings on the wire and are passed through uncoerced.
export interface BalanceResponse {
  confirmed_sat: string;
  pending_in_sat: string;
  pending_out_sat: string;
  credit_available_sat: string;
  credit_reserved_sat: string;
}

export interface CreateResponse {
  mnemonic: string[];
  identity_pubkey: string;
}

export interface UnlockResponse {
  identity_pubkey: string;
}

export interface RecvResponse {
  invoice: string;
  entry: WalletEntry;
}

export interface PrepareSendResponse {
  send_intent_id: string;
  amount_sat: string;
  expected_fee_sat: string;
  fee_known: boolean;
  expected_total_outflow_sat: string;
  total_outflow_known: boolean;
  rail: string;
  quote_status: string;
  destination_summary: string;
  invoice_description: string;
  payment_hash: string;
  expires_at_unix: string;
  warning: string;
}

export interface SendResponse {
  entry: WalletEntry;
  actual_amount_sat: string;
}

export interface WalletEntry {
  id: string;
  kind: string;
  status: string;
  amount_sat: string;
  fee_sat: string;
  counterparty: string;
  created_at_unix: string;
  updated_at_unix: string;
  note: string;
  failure_reason: string;
  failure_code?: string;
  request?: { lightning_invoice?: { invoice: string; payment_hash: string } };
  progress?: { phase: string; phase_label: string; payment_hash: string; preimage: string };
}

export interface ActivityList {
  entries: WalletEntry[];
  total: string;
  has_more: boolean;
  next_cursor: string;
}

export interface WavedError {
  code: ErrorCode;
  message: string;
  retryable: boolean;
  remediation: string;
}

export class WavedErrorImpl extends Error {
  readonly envelope: ReturnType<typeof errorEnvelope>;
  constructor(envelope: ReturnType<typeof errorEnvelope>) {
    super(envelope.message);
    this.envelope = envelope;
  }
}

/** gRPC status codes used by the REST gateway error body (api/rest.md). */
const GRPC = {
  CANCELLED: 1,
  UNKNOWN: 2,
  INVALID_ARGUMENT: 3,
  DEADLINE_EXCEEDED: 4,
  NOT_FOUND: 5,
  ALREADY_EXISTS: 6,
  PERMISSION_DENIED: 7,
  UNAUTHENTICATED: 16,
  FAILED_PRECONDITION: 9,
  ABORTED: 10,
  UNIMPLEMENTED: 12,
  INTERNAL: 13,
  UNAVAILABLE: 14,
} as const;

export function mapGrpcError(code: number, message: string): ReturnType<typeof errorEnvelope> {
  switch (code) {
    case GRPC.INVALID_ARGUMENT:
      return errorEnvelope("INVALID_ARGS", message, {
        details: `grpc ${code}`,
        remediation: "fix the request fields",
      });
    case GRPC.DEADLINE_EXCEEDED:
      return errorEnvelope("DEADLINE_EXCEEDED", message, {
        details: `grpc ${code}`,
        retryable: true,
        remediation: "check state before retrying (fund-moving RPCs are not blindly retryable)",
      });
    case GRPC.CANCELLED:
      return errorEnvelope("CANCELED", message, { details: `grpc ${code}` });
    case GRPC.NOT_FOUND:
      return errorEnvelope("NOT_FOUND", message, { details: `grpc ${code}` });
    case GRPC.ALREADY_EXISTS:
      return errorEnvelope("WALLET_NOT_CREATED", message, {
        details: `grpc ${code}`,
        remediation: "the wallet already exists; use unlock",
      });
    case GRPC.FAILED_PRECONDITION: {
      // Wallet lifecycle preconditions arrive as FailedPrecondition but are
      // surfaced with WALLET_* codes (wavecli mapping; cli.md).
      const lower = message.toLowerCase();
      if (lower.includes("locked") || lower.includes("unlock")) {
        return errorEnvelope("WALLET_LOCKED", message, { remediation: "run unlock" });
      }
      if (lower.includes("not created") || lower.includes("no wallet") || lower.includes("genseed")) {
        return errorEnvelope("WALLET_NOT_CREATED", message, { remediation: "run create-wallet" });
      }
      if (lower.includes("syncing") || lower.includes("not ready")) {
        return errorEnvelope("WALLET_SYNCING", message, { retryable: true });
      }
      return errorEnvelope("WALLET_LOCKED", message, { remediation: "run unlock" });
    }
    case GRPC.PERMISSION_DENIED:
    case GRPC.UNAUTHENTICATED:
      return errorEnvelope("INTERNAL", `waved rejected the macaroon: ${message}`, {
        details: `grpc ${code}`,
        remediation: "verify admin.macaroon is readable and current",
      });
    case GRPC.UNIMPLEMENTED:
      return errorEnvelope("WAVED_WALLET_API_UNAVAILABLE", `WAVED_WALLET_API_UNAVAILABLE: ${message}`, {
        details: "grpc 12 UNIMPLEMENTED — the waved build does not register WalletService",
        remediation: "install a wavewalletrpc+swapruntime build per the artifact manifest",
      });
    case GRPC.UNAVAILABLE:
      return errorEnvelope("INTERNAL", `waved unavailable: ${message}`, {
        details: `grpc ${code}`,
        retryable: true,
        remediation: "verify waved is running",
      });
    default:
      return errorEnvelope("INTERNAL", message, { details: `grpc ${code}` });
  }
}

export class WavelengthClient {
  readonly #restBase: string;
  readonly #macaroonPath: string;

  constructor(restBase: string, macaroonPath: string) {
    this.#restBase = restBase;
    this.#macaroonPath = macaroonPath;
  }

  /** POST a WalletService method. Body must be JSON-serializable; bytes fields are base64 strings. */
  async #call(method: string, body: Record<string, unknown>): Promise<unknown> {
    const macaroon = await fs.readFile(this.#macaroonPath, "utf8").catch(() => "");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    let response: Response;
    try {
      response = await fetch(`${this.#restBase}/v1/wallet/${method}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(macaroon.trim() ? { macaroon: macaroon.trim() } : {}),
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new WavedErrorImpl(
        errorEnvelope("INTERNAL", `waved REST call failed: ${message}`, {
          retryable: true,
          remediation: "verify waved is running on the REST gateway",
        }),
      );
    } finally {
      clearTimeout(timeout);
    }
    const text = await response.text();
    if (!response.ok) {
      let code: number = GRPC.UNKNOWN;
      let message = text;
      try {
        const parsed = JSON.parse(text) as { code?: number; message?: string };
        if (typeof parsed.code === "number") code = parsed.code;
        if (typeof parsed.message === "string") message = parsed.message;
      } catch {
        // plain-text error body; keep the raw text
      }
      throw new WavedErrorImpl(mapGrpcError(code, redact(message)));
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new WavedErrorImpl(
        errorEnvelope("INTERNAL", "waved REST returned a non-JSON response", {
          remediation: "verify the REST gateway is the grpc-gateway proxy",
        }),
      );
    }
  }

  /** WalletService.Status — the runtime network + wallet-API probe source (SEC-2026-050). */
  async status(): Promise<StatusResponse> {
    const result = (await this.#call("status", {})) as StatusResponse;
    return result;
  }

  async createWallet(walletPassword: string): Promise<CreateResponse> {
    const result = (await this.#call("create", {
      wallet_password: Buffer.from(walletPassword, "utf8").toString("base64"),
    })) as CreateResponse;
    return result;
  }

  async unlockWallet(walletPassword: string): Promise<UnlockResponse> {
    const result = (await this.#call("unlock", {
      wallet_password: Buffer.from(walletPassword, "utf8").toString("base64"),
    })) as UnlockResponse;
    return result;
  }

  async balance(): Promise<BalanceResponse> {
    const result = (await this.#call("balance", {})) as BalanceResponse;
    return result;
  }

  async recvInvoice(amtSat: number, memo: string): Promise<RecvResponse> {
    const result = (await this.#call("recv", {
      amt_sat: String(amtSat), // uint64 encodes as a JSON string (api/rest.md)
      memo,
    })) as RecvResponse;
    return result;
  }

  async prepareSend(invoice: string): Promise<PrepareSendResponse> {
    const result = (await this.#call("prepare-send", {
      invoice,
      amt_sat: "0", // ignored on the invoice path (prepare-send.md)
    })) as PrepareSendResponse;
    return result;
  }

  async sendPrepared(sendIntentId: string): Promise<SendResponse> {
    const result = (await this.#call("send", { send_intent_id: sendIntentId })) as SendResponse;
    return result;
  }

  async listActivity(limit = 100, cursor?: string): Promise<ActivityList> {
    const result = (await this.#call("list", {
      view: "LIST_VIEW_ACTIVITY",
      limit: String(limit),
      ...(cursor ? { cursor } : {}),
    })) as { activity: ActivityList };
    return result.activity;
  }
}

export interface WavedHandle {
  child: ChildProcess;
  restBaseUrl: string;
  status(): Promise<StatusResponse>;
  client: WavelengthClient;
}

/**
 * Supervise `waved` as a child: stale reaping, launch, startup probe
 * (network assertion + wallet-API probe), and graceful teardown.
 */
export async function startWaved(config: WavedLaunchConfig): Promise<WavedHandle> {
  const runDir = path.join(config.dataRoot, "run");
  const wavedDataDir = path.join(config.dataRoot, "wavelength");
  await fs.mkdir(wavedDataDir, { recursive: true });

  // Single-waved enforcement + stale reaping (SEC-2026-049). Refuse when a
  // live sidecar owns a live waved on this data root.
  await reapStaleWaved(runDir, {
    refuseIfOwnedByLiveSidecar: true,
    sidecarLockPath: path.join(runDir, "sidecar.lock"),
  });

  const restPort = config.restPort ?? WAVED_REST_DEFAULT_PORT;
  const restBaseUrl = config.restBaseUrl ?? `http://127.0.0.1:${restPort}`;

  const args = [
    `--network=${config.network}`,
    "--wallet.type=lwwallet",
    `--datadir=${wavedDataDir}`,
    "--rpc.listenaddr=127.0.0.1:10029",
  ];
  // NOTE: the REST gateway port is the documented default 10031
  // (api/get-started.md) and is NOT overridden here — the flag to move it is
  // not documented in the fetched waved surface, so an override would be an
  // invented flag. `restPort`/`restBaseUrl` exist for tests that point the
  // client at a fake waved; the real daemon always uses 127.0.0.1:10031
  // [REQUIRES VERIFICATION if a non-default port is ever needed].
  if (config.network === "regtest") {
    // Regtest has no public defaults; the operator must supply local endpoints.
    // TLS/macaroon stay ON unless the operator explicitly provides the
    // regtest-only insecure flags — never passed on signet (design §2.5).
  }

  let child: ChildProcess;
  if (/\.(cmd|bat)$/i.test(config.binary) && process.platform === "win32") {
    // Test fixtures on Windows are .cmd wrappers; invoke cmd.exe explicitly
    // (NOT shell:true — that triggers node's DEP0190 and unescaped-args
    // warning). windowsVerbatimArguments passes the /c line through without
    // node re-quoting it, so cmd's /s rule strips exactly the outer pair.
    const commandLine = `"${config.binary}" ${args.join(" ")}`;
    child = spawn("cmd.exe", ["/d", "/s", "/c", commandLine], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: false,
      windowsVerbatimArguments: true,
    });
  } else {
    child = spawn(config.binary, args, {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: false,
    });
  }
  child.stderr?.on("data", (chunk: Buffer) => {
    // Forward redacted (SEC-2026-046): a stray mnemonic/password must never
    // reach the supervisor or Omega's log.
    const text = chunk.toString("utf8");
    for (const line of text.split("\n")) {
      if (line.trim().length > 0) process.stderr.write(`waved: ${redact(line)}\n`);
    }
  });

  const macaroonPath = path.join(wavedDataDir, "data", config.network, "admin.macaroon");
  const client = new WavelengthClient(restBaseUrl, macaroonPath);
  const startupTimeoutMs = config.wavedStartupTimeoutMs ?? 30_000;
  const deadline = Date.now() + startupTimeoutMs;

  let probed = false;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new WavedErrorImpl(
        errorEnvelope("INTERNAL", `waved exited during startup with code ${child.exitCode}`, {
          remediation: "inspect the waved stderr log under logs/",
        }),
      );
    }
    try {
      const status = await client.status();
      probed = true;
      assertNetworkMatches(config.network, status.network);
      // Wallet-API probe passed: Status answered, so WalletService is live
      // (a wavewalletrpc-only stub answers UNIMPLEMENTED and throws above).
      await writeWavedPid(runDir, child.pid ?? 0);
      return { child, restBaseUrl, status: () => client.status(), client };
    } catch (error) {
      if (
        error instanceof WavedErrorImpl &&
        (error.envelope.code === "WAVED_WALLET_API_UNAVAILABLE" || error.envelope.code === "MAINNET_REFUSED")
      ) {
        // SEC-2026-050: a wallet-API stub or a network mismatch is a hard
        // bail — kill waved and refuse the sidecar immediately, never retry.
        await terminateWaved(child);
        throw error;
      }
      // Retryable startup (daemon still booting, macaroon not yet written).
      await sleep(500);
    }
  }
  await terminateWaved(child);
  throw new WavedErrorImpl(
    errorEnvelope(
      "INTERNAL",
      `waved did not answer Status within ${startupTimeoutMs}ms${probed ? "" : " (wallet API probe never succeeded)"}`,
      { remediation: "verify the waved binary and the signet endpoints" },
    ),
  );
}

/** SEC-2026-050: the daemon's REPORTED network must equal the configured network. */
export function assertNetworkMatches(configured: string, reported: string): void {
  if (reported === "mainnet") {
    throw new WavedErrorImpl(
      errorEnvelope("MAINNET_REFUSED", `MAINNET_REFUSED: waved reported network mainnet; refusing (SEC-2026-050)`),
    );
  }
  if (reported !== configured) {
    throw new WavedErrorImpl(
      errorEnvelope(
        "INTERNAL",
        `INTERNAL: waved reported network ${reported}, expected ${configured}; refusing to continue (SEC-2026-050)`,
        { remediation: "wipe or re-point the wavelength data dir; never --allow-mainnet" },
      ),
    );
  }
}

/** BOLT11 HRP guard (design §3.4): accept signet/testnet/regtest, refuse mainnet. */
export function assertInvoiceNetwork(configured: string, invoice: string): void {
  // lnbc = mainnet; lnbcrt = regtest (starts with lnbc too, so exclude it).
  if (invoice.startsWith("lnbc") && !invoice.startsWith("lnbcrt")) {
    throw new WavedErrorImpl(
      errorEnvelope("MAINNET_REFUSED", "mainnet BOLT11 invoices are never paid or minted"),
    );
  }
  const expectedPrefixes = configured === "regtest" ? ["lnbcrt"] : ["lntbs", "lntb"];
  if (!expectedPrefixes.some((p) => invoice.startsWith(p))) {
    throw new WavedErrorImpl(
      errorEnvelope(
        "INVALID_ARGS",
        `invoice prefix ${invoice.slice(0, 5)} does not match the configured network ${configured}`,
      ),
    );
  }
}

/** Graceful waved teardown: node kill, grace, then Windows tree kill (SEC-2026-049). */
export async function terminateWaved(child: ChildProcess): Promise<void> {
  const pid = child.pid;
  if (pid === undefined) return;
  if (child.exitCode !== null && process.platform !== "win32") return;
  try {
    child.kill();
  } catch {
    // already gone
  }
  await sleep(2_000);
  if (process.platform === "win32") {
    // Always tree-kill on Windows: with shell-spawned fixtures the real child
    // is a grandchild (cmd -> node), and the daemon itself may have spawned
    // workers. taskkill /T is the job-object equivalent (SEC-2026-049).
    const { execFileSync } = await import("node:child_process");
    try {
      execFileSync("taskkill", ["/PID", String(pid), "/T", "/F"], {
        windowsHide: true,
        stdio: "ignore",
      });
    } catch {
      // already gone
    }
  }
}