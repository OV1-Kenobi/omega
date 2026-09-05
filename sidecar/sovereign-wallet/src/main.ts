//! Sovereign wallet sidecar — main program (design §1, §2, §3).
//!
//! Effect-composed Node 24 service supervised by `crates/sovereign_wallet`:
//! stdio control plane (newline-framed JSON, bounded frames, generation
//! fencing), the phoenixd node rail (client-only — OMEGA-DELTA-0303),
//! loopback HTTP projections (bearer-token protected), idempotency ledger,
//! owner-only data-root ACLs.
//!
//! OMEGA-DELTA-0303 (rail swap): `wavelength.ts` / the waved daemon are
//! REMOVED. The sidecar is a CLIENT-ONLY process for the phoenixd rail: no
//! daemon child is spawned, supervised, or tree-killed (design §2, §8.1).
//! make-invoice/pay-invoice re-point to phoenixd (createinvoice/payinvoice);
//! wallet-height fails closed with TIP_HEIGHT_UNAVAILABLE until the C3-2
//! slice wires the public tip API (0304); balance/activity/create-wallet/
//! unlock/lock fail closed with named errors (their phoenixd re-point is
//! later-slice [REQUIRES VERIFICATION] work; the waved wallet ceremony is
//! removed with the rail).
//!
//! Environment (injected by the supervisor; never secrets in args):
//!   OMEGA_SOVEREIGN_WALLET_DATA_ROOT        (required)
//!   OMEGA_SOVEREIGN_WALLET_NETWORK          mainnet (the payments rail is
//!     mainnet-operative — OMEGA-DELTA-0305; signet/regtest rail config is
//!     refused at startup. mainnet requires OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET=1 — 0286)
//!   OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET    the explicit mainnet opt-in (=1)
//!   OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN   32-byte hex, per launch
//!   OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL     the phoenixd REST base over
//!     Tailscale/SSH (design §9.3; required for the mainnet rail — 0303)
//!   OMEGA_SOVEREIGN_WALLET_PHOENIXD_API_KEY the phoenixd full-access
//!     http-password (env-only; redaction-registered; never repo/log/settings)

import { Effect } from "effect";
import fs from "node:fs/promises";
import path from "node:path";

import { getTipHeight } from "./tip-api.js";
import { lockdownTree } from "./acl.js";
import { ClinkListener, CLINK_LAYER_ENV, CLINK_RELAY_ENV, CLINK_SERVICE_KEY_ENV, type RelayAdapter } from "./clink.js";
import { SimplePool } from "@shocknet/clink-sdk";
import { LoopbackHttpServer, validateLoopbackToken } from "./http.js";
import { IdempotencyStore } from "./idempotency.js";
import { L402Gateway, DEMO_ECHO_PATH, DEMO_MCP_PATH_PREFIX } from "./l402.js";
import { L402Store } from "./l402-store.js";
import { acquireLock, type LockHandle } from "./lock.js";
import type { ErrorCode } from "./protocol.js";
import { PROTOCOL_SCHEMA, PROTOCOL_VERSION, SERVICE_VERSION, encodeResponse, errorEnvelope } from "./protocol.js";
import { clearRegisteredSecrets, redact, registerSecret } from "./redact.js";
import { MIN_PASSPHRASE_LEN, VAULT_FALLBACK_OPT_IN_ENV, Vault } from "./vault/vault.js";
import { InMemoryKeychainBackend } from "./vault/keychain.js";
import { listPrimaryIdentity } from "./identity/index.js";
import { deriveFromMnemonic, encodeNsec, generateMnemonic12 } from "./identity/keygen.js";
import { challengeLabels, verifyChallenge } from "./identity/ceremony.js";
import {
  PHOENIXD_API_KEY_ENV,
  PHOENIXD_URL_ENV,
  PhoenixdClient,
  assertInvoiceNetwork,
  assertNetworkMatches,
  expectedFeeSat,
  expectedTotalOutflowSat,
  type PhoenixdNetwork,
} from "./phoenixd.js";

const MAX_FRAME_BYTES = 64 * 1024;
const HEALTH_TIMEOUT_MS = 5_000;
const PAY_TIMEOUT_MS = 180_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const SHUTDOWN_GRACE_MS = 2_000;

/**
 * OMEGA-DELTA-0286: the explicit mainnet opt-in env name. `mainnet` is
 * accepted ONLY when this is "1" (the allow-mainnet authority; the exact
 * name is bound by the 0286 delta check).
 */
export const ALLOW_MAINNET_ENV = "OMEGA_SOVEREIGN_WALLET_ALLOW_MAINNET";

/**
 * OMEGA-DELTA-0300 (kill closure): the environment-level spend kill env
 * name. The L-402 gateway's HTTP mint path is sidecar-internal (a direct
 * phoenixd createinvoice call — OMEGA-DELTA-0303) and does NOT traverse the
 * Rust spend_policy choke point, so the sidecar reads the kill itself on that
 * mint path — a halted surface creates no new invoices at the HTTP surface
 * either. Mirrors the Rust-side constant
 * (crates/sovereign_wallet/src/spend_policy.rs).
 */
export const SPEND_KILL_ENV = "OMEGA_SPEND_KILL";

export type WalletState = "none" | "locked" | "syncing" | "ready" | "error";

export interface SidecarConfig {
  dataRoot: string;
  network: PhoenixdNetwork;
  /**
   * OMEGA-DELTA-0286: the allow-mainnet authority. True only when the
   * configured network is mainnet AND the explicit opt-in env is set at the
   * process level (parseEnvironment). The rail accepts no other network.
   */
  allowMainnet: boolean;
  loopbackToken: string | undefined;
  /**
   * OMEGA-DELTA-0303: the phoenixd REST base over Tailscale/SSH (design
   * §9.3) and the full-access API key (the http-password; env-only,
   * redaction-registered). A rail without both is a configuration
   * error refused at startup (the rail gate, design §2.6.2).
   */
  phoenixdUrl: string | undefined;
  phoenixdApiKey: string | undefined;
  generation: number;
  /**
   * OS-keychain backend selection (OMEGA-DELTA-0301 / RV6-REQ-1): `"os"` (the
   * default — Windows Credential Manager / macOS Keychain Services via the
   * typed keychain seam) or `"memory"` — a TEST-ONLY seam selected by
   * `OMEGA_SOVEREIGN_WALLET_VAULT_KEYCHAIN=memory`; never set in production.
   */
  vaultKeychain?: "os" | "memory";
  /**
   * OMEGA-DELTA-0306 (design §3, WP-C4): the CLINK Offers/Debits layer.
   * Enabled ONLY by `OMEGA_CLINK_LAYER=1` (default OFF = phoenixd-rail-only,
   * zero Nostr interaction). When ON, the relay URL and the service signing
   * key (env-injected, redaction-registered) are required.
   */
  clinkEnabled: boolean;
  clinkRelayUrl: string | undefined;
  clinkServiceKey: string | undefined;
}

export interface WalletMarker {
  /** Wallet-created marker (non-secret). */
  created?: boolean;
  /** One-time export marker: the npub whose nsec was exported (non-secret). */
  exported?: string;
}

// ---------------------------------------------------------------------------
// Sidecar core
// ---------------------------------------------------------------------------

export interface HealthProjection {
  ok: boolean;
  status: string;
  generation: number;
  dataRoot: string;
  walletState: WalletState;
  nodeConnected: boolean;
  network: PhoenixdNetwork;
  note: string;
}

export interface SidecarHandle {
  readonly core: SidecarCore;
  stop(): Promise<void>;
}

export class SidecarCore {
  readonly #config: SidecarConfig;
  readonly #runDir: string;
  #lock: LockHandle | null = null;
  /**
   * OMEGA-DELTA-0303: the phoenixd rail client (client-only — no daemon child
   * is spawned). Non-null when the phoenixd envs are configured AND the
   * startup getinfo probe answered (the rail gate, design §2.6.2).
   */
  #phoenixd: PhoenixdClient | null = null;
  #nodeUnavailableReason = "";
  #idempotency: IdempotencyStore | null = null;
  #http: LoopbackHttpServer | null = null;
  #httpReason: string | undefined;
  #walletState: WalletState = "none";
  #generation: number;
  #syncWatcher: ReturnType<typeof setInterval> | null = null;
  /** WP-4: satnam-derived identity/vault root. Absent-vs-locked-vs-unlocked. */
  #vault: Vault | null = null;
  #vaultState: "none" | "locked" | "unlocked" = "none";
  /**
   * WP-5 ceremony: the show-once mnemonic held in memory between
   * `vault-init-prepare` and `vault-init` (never persisted; registered for
   * redaction; cleared on completion, on lock, and on teardown).
   */
  #pendingMnemonic: string | null = null;
  /** WP-6: the MDK-protocol L-402 gateway (design §5; D3/D5) — the ONLY paid boundary. */
  #l402Gateway: L402Gateway | null = null;
  #l402Store: L402Store | null = null;
  /**
   * OMEGA-DELTA-0306 (design §3, WP-C4): the CLINK Offers/Debits listener.
   * Constructed ONLY when `OMEGA_CLINK_LAYER=1`; the listener is transport
   * only — it queues Debits and never pays (the Rust `pay_debit_invoice`
   * wrapper authorizes before any phoenixd call).
   */
  #clink: ClinkListener | null = null;

  constructor(config: SidecarConfig) {
    this.#config = config;
    this.#runDir = path.join(config.dataRoot, "run");
    this.#generation = config.generation;
  }

  get network(): PhoenixdNetwork {
    return this.#config.network;
  }

  get generation(): number {
    return this.#generation;
  }

  get dataRoot(): string {
    return this.#config.dataRoot;
  }

  get nodeConnected(): boolean {
    return this.#phoenixd !== null;
  }

  get walletState(): WalletState {
    return this.#walletState;
  }

  get httpSurface(): { bound: boolean; port: number; reason?: string } {
    return this.#http ? { bound: true, port: this.#http.port() } : { bound: false, port: 0, reason: this.#httpReason };
  }

  /** Record the generation negotiated at initialize (generation fencing). */
  setGeneration(generation: number): void {
    this.#generation = generation;
  }

  /** Full startup: data root, ACLs, lock, idempotency, phoenixd rail, HTTP, gateway. */
  async start(): Promise<void> {
    const { dataRoot, network } = this.#config;
    await fs.mkdir(dataRoot, { recursive: true });
    await fs.mkdir(this.#runDir, { recursive: true });
    await fs.mkdir(path.join(dataRoot, "logs"), { recursive: true });

    // SEC-2026-045: owner-only ACLs on the whole data root, fail closed.
    try {
      lockdownTree(dataRoot);
    } catch (error) {
      throw new Error(
        `data-root ACL lockdown failed; refusing to start (SEC-2026-045): ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    // Sidecar lock (design §1.6): ALREADY_RUNNING on contention.
    this.#lock = await acquireLock(path.join(this.#runDir, "sidecar.lock"), "sovereign-wallet");

    this.#idempotency = IdempotencyStore.open(dataRoot);

    // WP-4 vault: satnam-derived identity/vault root at <data_root>/vault.
    // WP-3a (OMEGA-DELTA-0301 / RV6-REQ-1..9): the master key is wrapped by
    // K_os in the OS keychain; the passphrase is the degraded/portable
    // fallback (opt-in `OMEGA_VAULT_ALLOW_PASSPHRASE_FALLBACK=1`). The
    // `memory` backend is the test seam (OMEGA_SOVEREIGN_WALLET_VAULT_KEYCHAIN
    // =memory); production defaults to the OS keychain.
    const vaultKeychain = this.#config.vaultKeychain === "memory" ? new InMemoryKeychainBackend() : null;
    this.#vault = new Vault(
      {
        vaultRoot: "vault",
        idleTimeoutMs: 900_000,
        // RV6-REQ-5: every degraded unlock is a security-relevant event —
        // logged redacted (no secrets) here; surfaced on the operator surface
        // by WP-7.
        onSecurityEvent: () => {
          console.error("vault security event: degraded unlock occurred (OMEGA-DELTA-0301)");
        },
      },
      dataRoot,
      vaultKeychain,
    );
    this.#vaultState = (await this.#vault.existsOnDisk()) ? "locked" : "none";

    // WP-6: the L-402 gateway state store (SQLite; survives restarts by
    // construction — design §5.5). The gateway itself is constructed after
    // the rail so its mint path can reach the node engine.
    this.#l402Store = L402Store.open(path.join(dataRoot, "l402"));

    // HTTP surface: fail-closed on a missing/malformed token (SEC-2026-053).
    this.#httpReason = validateLoopbackToken(this.#config.loopbackToken) ?? undefined;
    if (!this.#httpReason && this.#config.loopbackToken) {
      this.#http = await LoopbackHttpServer.bind({
        token: this.#config.loopbackToken,
        onStatus: () => this.statusProjection(),
        onBalance: () => this.balance(),
        // WP-6: the L-402 gateway routes (the ONLY paid boundary). The
        // gateway is constructed after the rail below; the handler is bound
        // lazily through `this.#l402Gateway`.
        onL402: (method, pathname, headers, body) => {
          const gateway = this.#l402Gateway;
          if (!gateway) {
            return Promise.resolve({
              status: 503,
              headers: { "cache-control": "no-store" },
              body: { error: { code: "gateway_unavailable", message: "the L-402 gateway is not initialized" } },
            });
          }
          return gateway.handleRequest(method, pathname, headers, body);
        },
      });
    }

    // OMEGA-DELTA-0303: the phoenixd rail — client-only. A configured rail
    // (URL + API key) runs the startup getinfo probe: the network assertion
    // (SEC-2026-050 rail form) hard-bails on a mismatch; a failed probe is a
    // named node-unreachable state (retryable; health re-probes), except on a
    // MAINNET rail where the rail gate (design §2.6.2) refuses to start
    // without an answering node connection. An absent phoenixd env is the
    // named NODE_UNCONFIGURED state (never a silent zero).
    if (this.#config.phoenixdUrl && this.#config.phoenixdApiKey) {
      this.#phoenixd = new PhoenixdClient({
        baseUrl: this.#config.phoenixdUrl,
        apiKey: this.#config.phoenixdApiKey,
        network,
        allowMainnet: this.#config.allowMainnet,
      });
      try {
        const chain = await this.#phoenixd.probeChain();
        assertNetworkMatches(this.#config.network, chain, this.#config.allowMainnet);
        this.#walletState = "ready";
        this.#nodeUnavailableReason = "";
      } catch (error) {
        const envelope = error instanceof Error && "envelope" in error
          ? (error as { envelope: { code: ErrorCode; message: string } }).envelope
          : null;
        if (envelope?.code === "MAINNET_REFUSED") {
          // The node reported a network the config refuses: hard bail.
          await this.#releaseAll();
          throw error;
        }
        if (network === "mainnet") {
          // Rail gate (design §2.6.2): a mainnet rail without an answering
          // node connection is a configuration error, never a silent zero.
          await this.#releaseAll();
          throw envelopeError(
            "NODE_UNCONFIGURED",
            `NODE_UNCONFIGURED: the mainnet rail requires an answering phoenixd connection (${PHOENIXD_URL_ENV} present and the startup getinfo probe answering; OMEGA-DELTA-0303)`,
            { details: envelope?.message ?? String(error), remediation: "verify the phoenixd node + the Tailscale/SSH path" },
          );
        }
        this.#nodeUnavailableReason = envelope?.message ?? (error instanceof Error ? error.message : String(error));
        this.#phoenixd = null;
        this.#walletState = "error";
      }
    } else {
      this.#nodeUnavailableReason =
        `NODE_UNCONFIGURED: the phoenixd rail is not configured (${PHOENIXD_URL_ENV} and ${PHOENIXD_API_KEY_ENV} are required for the rail; OMEGA-DELTA-0303)`;
      this.#walletState = "error";
    }

    // WP-6: construct the L-402 gateway (design §5). The gateway mints via
    // the phoenixd rail (createinvoice) and refuses mainnet everywhere; the
    // node-ready gate is the sidecar's own `#requireNodeReady`.
    if (this.#l402Store) {
      this.#l402Gateway = new L402Gateway({
        network,
        store: this.#l402Store,
        vault: this.#vault,
        walletReady: async () => this.#requireNodeReady(),
        mintInvoice: async (amtSat, memo) => {
          // OMEGA-DELTA-0300 (kill closure): the gateway mint is
          // sidecar-internal (a direct phoenixd createinvoice) and does not
          // traverse the Rust spend_policy choke point — the sidecar reads the
          // environment-level kill itself so a killed surface refuses to
          // mint at the HTTP surface too (C2: ALL-VALUE-TOUCHING; a halted
          // surface creates no new invoices either). The typed code mirrors
          // the Rust-side SpendHalted shape; only the founder re-enables.
          // OMEGA-DELTA-0303: the kill check must PRECEDE the phoenixd
          // createinvoice call (the 0300 check's re-anchored ordering anchor).
          if (process.env[SPEND_KILL_ENV] === "1") {
            throw envelopeError(
              "SPEND_HALTED",
              `SPEND_HALTED: the spend kill is set (${SPEND_KILL_ENV}=1); the gateway refuses to mint until the founder re-enables (OMEGA-DELTA-0300)`,
            );
          }
          const created = await this.#phoenixd!.createInvoice(amtSat, memo);
          assertInvoiceNetwork(network, created.serialized);
          return {
            invoice: created.serialized,
            entryPaymentHash: created.paymentHash ?? null,
          };
        },
        nowMs: () => Date.now(),
      });
    }

    // OMEGA-DELTA-0306 (design §3, WP-C4): the CLINK Offers/Debits layer.
    // Enabled ONLY by OMEGA_CLINK_LAYER=1; the listener is transport-only —
    // it subscribes to kinds 21001/21002 addressed to the app's service
    // pubkey, validates + queues Debits, and NEVER pays (the Rust
    // `pay_debit_invoice` wrapper authorizes before any phoenixd call).
    // OFF (default) = no Nostr pool is ever constructed (tested).
    if (this.#config.clinkEnabled) {
      if (!this.#config.clinkRelayUrl || !this.#config.clinkServiceKey) {
        throw envelopeError(
          "INVALID_ARGS",
          `INVALID_ARGS: ${CLINK_LAYER_ENV}=1 requires ${CLINK_RELAY_ENV} and ${CLINK_SERVICE_KEY_ENV} (OMEGA-DELTA-0306)`,
        );
      }
      this.#clink = new ClinkListener({
        serviceKeyHex: this.#config.clinkServiceKey,
        relayUrls: [this.#config.clinkRelayUrl],
        mintInvoice: async (amtSat, memo) => {
          // OMEGA-DELTA-0306: the Offer mint reuses the SAME one-mint-surface
          // as the L-402 gateway (design §3.3 step 2: "the SAME make-invoice
          // path") — the kill closure reads the environment kill BEFORE the
          // phoenixd createinvoice call (0300 ordering anchor, re-anchored).
          if (process.env[SPEND_KILL_ENV] === "1") {
            throw envelopeError(
              "SPEND_HALTED",
              `SPEND_HALTED: the spend kill is set (${SPEND_KILL_ENV}=1); the CLINK offer mint refuses until the founder re-enables (OMEGA-DELTA-0300/0306)`,
            );
          }
          const created = await this.#phoenixd!.createInvoice(amtSat, memo);
          assertInvoiceNetwork(this.#config.network, created.serialized);
          return { invoice: created.serialized, paymentHash: created.paymentHash ?? "" };
        },
        payInvoice: async (invoice) => {
          // OMEGA-DELTA-0306: the Debit settlement calls the SAME phoenixd
          // pay path; the 0300 kill is read here too (ALL-VALUE-TOUCHING — a
          // halted rail refuses debits at the transport too; the Rust wrapper
          // is the primary gate, this is defense-in-depth at the sidecar).
          if (process.env[SPEND_KILL_ENV] === "1") {
            throw envelopeError(
              "SPEND_HALTED",
              `SPEND_HALTED: the spend kill is set (${SPEND_KILL_ENV}=1); the CLINK debit settlement refuses until the founder re-enables (OMEGA-DELTA-0300/0306)`,
            );
          }
          assertInvoiceNetwork(this.#config.network, invoice);
          const sent = await this.#phoenixd!.payInvoice(invoice);
          const preimage = sent.paymentPreimage;
          if (preimage) registerSecret(preimage);
          return { preimage, actualAmountSat: String(sent.recipientAmountSat + sent.routingFeeSat) };
        },
        isKilled: () => process.env[SPEND_KILL_ENV] === "1",
        relay: new SimplePoolClinkRelayAdapter(this.#config.clinkRelayUrl),
        log: (message) => {
          console.error(`sovereign-wallet: ${redact(message)}`);
        },
      });
      this.#clink.start();
    }
  }

  /** Ordered teardown: rail, HTTP, idempotency, lock (OMEGA-DELTA-0303). */
  async stop(): Promise<void> {
    await this.#releaseAll();
  }

  async #releaseAll(): Promise<void> {
    if (this.#syncWatcher) {
      clearInterval(this.#syncWatcher);
      this.#syncWatcher = null;
    }
    // WP-4: lock the vault (zeroize the master key) on any teardown, so a
    // crash/restart never leaves key material in a lingering process's heap.
    if (this.#vault) {
      this.#vault.lock();
      this.#vaultState = "locked";
      this.#vault = null;
    }
    // Drop any pending identity ceremony mnemonic.
    this.#pendingMnemonic = null;
    // WP-6: zeroize the L-402 gateway's in-memory HMAC key and close the
    // gateway state store (SEC-2026-044 "zeroized on shutdown").
    if (this.#l402Gateway) {
      this.#l402Gateway.shutdown();
      this.#l402Gateway = null;
    }
    if (this.#l402Store) {
      this.#l402Store.close();
      this.#l402Store = null;
    }
    // OMEGA-DELTA-0306: stop the CLINK listener (close the relay subscription
    // + clear the pending-debit queue) on any teardown.
    if (this.#clink) {
      this.#clink.stop();
      this.#clink = null;
    }
    // OMEGA-DELTA-0303: the phoenixd rail is client-only — nothing to
    // terminate; the client object is dropped (its API key lives in the
    // process heap until the registered-secret clear below).
    this.#phoenixd = null;
    if (this.#http) {
      await this.#http.close().catch(() => {});
      this.#http = null;
    }
    if (this.#idempotency) {
      this.#idempotency.close();
      this.#idempotency = null;
    }
    if (this.#lock) {
      await this.#lock.release().catch(() => {});
      this.#lock = null;
    }
    clearRegisteredSecrets();
  }

/** Periodic health: re-probe the phoenixd rail + re-assert the runtime network (SEC-2026-050, 0286 rail form). */
  async health(): Promise<HealthProjection> {
    if (this.#phoenixd) {
      try {
        const chain = await this.#phoenixd.probeChain();
        assertNetworkMatches(this.#config.network, chain, this.#config.allowMainnet);
        this.#walletState = "ready";
      } catch (error) {
        if (isMainnetRefused(error)) {
          // The node drifted to mainnet at runtime: hard bail.
          await this.stop();
          return this.healthProjection(false, "mainnet drift detected; sidecar stopped");
        }
        // Node unreachable at health time: named unavailable state (the
        // wallet-state surfaces honestly; the next health re-probes).
        this.#walletState = "error";
      }
    }
    return this.healthProjection(true, "");
  }

  healthProjection(ok: boolean, note: string): HealthProjection {
    return {
      ok,
      status: ok ? "ready" : "unhealthy",
      generation: this.#generation,
      dataRoot: this.#config.dataRoot,
      walletState: this.#walletState,
      nodeConnected: this.nodeConnected,
      network: this.#config.network,
      note,
    };
  }

  /** status projection: full read-only status (design §2.2). */
  statusProjection(): Record<string, unknown> {
    return {
      schema: PROTOCOL_SCHEMA,
      protocolVersion: PROTOCOL_VERSION,
      serviceVersion: SERVICE_VERSION,
      network: this.#config.network,
      nodeConnected: this.nodeConnected,
      nodeUnavailableReason: this.#nodeUnavailableReason,
      walletState: this.#walletState,
      // WP-4: the satnam-derived vault state — none (absent), locked, or unlocked.
      vaultState: this.#vaultState,
      // WP-6: the MDK L-402 gateway state (real — ready/locked/unavailable/absent).
      l402GatewayState: this.#l402Gateway?.state().state ?? "absent",
      httpSurface: this.httpSurface,
      dataRoot: this.#config.dataRoot,
    };
  }

  async initialize(): Promise<Record<string, unknown>> {
    let nodeNetwork: string | null = null;
    if (this.#phoenixd) {
      try {
        nodeNetwork = await this.#phoenixd.probeChain();
      } catch {
        nodeNetwork = null;
      }
    }
    return {
      schema: PROTOCOL_SCHEMA,
      protocolVersion: PROTOCOL_VERSION,
      serviceVersion: SERVICE_VERSION,
      generation: this.#generation,
      capabilities: [
        "status",
        "balance",
        "wallet-height",
        "create-wallet",
        "unlock",
        "lock",
        "make-invoice",
        "pay-invoice",
        "activity",
        "identity-status",
        "vault-init-prepare",
        "vault-init",
        "vault-unlock",
        "export-nostr-secret",
        "mcp-identity-map-get",
        "mcp-identity-map-set",
        "shutdown",
        // OMEGA-DELTA-0306 (design §9.2): the CLINK methods are advertised
        // ONLY when the layer is enabled — OFF = zero Nostr interaction, and
        // the stdio surface honestly does not claim them. `clink-status` is
        // always advertised (a read-only projection that reports the layer
        // state honestly, including disabled).
        ...(this.#config.clinkEnabled
          ? ["pay-debit", "debit-refuse", "pending-debits", "clink-status"]
          : ["clink-status"]),
      ],
      dataRoot: this.#config.dataRoot,
      network: this.#config.network,
      // SEC-2026-050 (rail form, 0303): initialize reports the node's ACTUAL
      // runtime network (the getinfo chain field when present), never the env
      // value alone. `null` when the rail is unconfigured or getinfo exposes
      // no chain field (the assertion is then carried by the env gate + HRP
      // guard — design §2.6.3).
      nodeNetwork,
      nodeState: this.nodeConnected ? "connected" : "unavailable",
      httpSurface: this.httpSurface,
    };
  }

  async balance(): Promise<Record<string, unknown>> {
    // OMEGA-DELTA-0303: the phoenixd balance re-point (getbalance —
    // RV-C3: the shape was verified in the phoenixd source) is later-slice
    // work; until it lands, balance fails closed with a named error. The
    // The credit fields (OQ-6, founder 2026-09-04) stay PRESERVED in the
    // protocol shape — never removed; the honest-zero + note reporting lands
    // with the balance re-point (a later C3 slice).
    throw envelopeError(
      "INTERNAL",
      "INTERNAL: balance is not yet wired on the phoenixd rail (OMEGA-DELTA-0303); the getbalance re-point lands in a later C3 slice",
      { remediation: "use the node operator surfaces (getbalance) until the re-point lands" },
    );
  }

  /**
   * OMEGA-DELTA-0303/0304: the wallet-height seam returns the observed
   * chain tip height from the public tip-API (mempool.space primary,
   * blockstream.info fallback). Fails closed with TIP_HEIGHT_UNAVAILABLE
   * (never wall-clock). The escrow timeout gate consumes this via
   * `observe_wallet_height` -> `timeout_window_open`.
   */
  async walletHeight(): Promise<Record<string, unknown>> {
    try {
      const height = await getTipHeight();
      return { block_height: height };
    } catch (error) {
      // The tip client already shapes the fail-closed error; re-throw with
      // the typed envelope so the Rust side observes TIP_HEIGHT_UNAVAILABLE
      // (never a bare INTERNAL and never a guessed height).
      throw envelopeError(
        "TIP_HEIGHT_UNAVAILABLE",
        `TIP_HEIGHT_UNAVAILABLE: ${(error as Error)?.message ?? String(error)} (OMEGA-DELTA-0304)`,
        { retryable: true, remediation: "check public tip API reachability (mempool.space / blockstream.info); the escrow timeout gate fails closed on this error" },
      );
    }
  }

/**
 * OMEGA-DELTA-0303: the waved wallet ceremony (create/unlock/lock) is REMOVED
 * with the rail. The phoenixd node is remote and operator-managed — the
 * sidecar never creates, unlocks, or locks it (the API key IS the access;
 * design §2.1). These methods fail closed with a named error; the protocol
 * surface stays so the stdio seam is stable (the Rust client still references
 * them; a later slice decides their final disposition).
 */
  async createWallet(idempotencyKey: string, password: string): Promise<Record<string, unknown>> {
    throw envelopeError(
      "INTERNAL",
      "INTERNAL: create-wallet is not available on the phoenixd rail (OMEGA-DELTA-0303): the node is remote and operator-managed; the waved wallet ceremony is removed",
      { remediation: "manage the phoenixd node on the Lunanode (the API key is the access)" },
    );
  }

  /**
   * Operator-only: the wallet unlock seam is removed with the waved ceremony
   * (OMEGA-DELTA-0303); the phoenixd node is remote and operator-managed.
   */
  async unlock(idempotencyKey: string, password: string): Promise<Record<string, unknown>> {
    throw envelopeError(
      "INTERNAL",
      "INTERNAL: unlock is not available on the phoenixd rail (OMEGA-DELTA-0303): the node is remote and operator-managed; the waved wallet ceremony is removed",
      { remediation: "manage the phoenixd node on the Lunanode (the API key is the access)" },
    );
  }

  /** Operator-only: lock the wallet surface and the vault (design §2.2). */
  async lock(): Promise<Record<string, unknown>> {
    // The vault lock still applies (zeroizes the master key); the waved
    // wallet lock boundary is removed with the rail.
    if (this.#vault) {
      this.#vault.lock();
      this.#vaultState = "locked";
    }
    this.#pendingMnemonic = null;
    throw envelopeError(
      "INTERNAL",
      "INTERNAL: the wallet lock is not available on the phoenixd rail (OMEGA-DELTA-0303): the node is remote and operator-managed; the waved wallet ceremony is removed (the vault was locked)",
      { remediation: "manage the phoenixd node on the Lunanode (the API key is the access)" },
    );
  }

  /** Mint a BOLT11 invoice via phoenixd (design §2.2/§2.4; prefix guard §3.4). */
  async makeInvoice(amtSat: number, memo: string, idempotencyKey: string): Promise<Record<string, unknown>> {
    await this.#requireNodeReady();
    const stored = this.#idempotency?.fetch("make-invoice", idempotencyKey);
    if (stored) return stored.result as Record<string, unknown>;
    if (!Number.isSafeInteger(amtSat) || amtSat <= 0) {
      throw envelopeError("INVALID_ARGS", "amtSat must be a positive integer");
    }
    const created = await this.#phoenixd!.createInvoice(amtSat, memo);
    assertInvoiceNetwork(this.#config.network, created.serialized);
    const result = {
      invoice: created.serialized,
      paymentHash: created.paymentHash,
      amountSat: amtSat,
      memo,
      // The invoice HRP follows the configured network (OMEGA-DELTA-0286):
      // lnbc on mainnet; the guard refuses any mismatch.
      hrp: created.serialized.slice(0, 5),
    };
    this.#idempotency?.store("make-invoice", idempotencyKey, result);
    return result;
  }

  /**
   * Pay a BOLT11 invoice via phoenixd (design §2.2/§2.5; the mandate gate is
   * enforced Rust-side in WP-5). The loss-rule bound (OMEGA-DELTA-0300 /
   * SEC-2026-098): the sidecar computes the expected total outflow
   * (BOLT11 amount + phoenixd's 0.4% pay fee, rounded up) and reports the
   * actual outflow (recipientAmountSat + routingFeeSat) + the preimage so the
   * Rust-side expected-vs-actual settle comparison has both sides.
   */
  async payInvoice(invoice: string, idempotencyKey: string): Promise<Record<string, unknown>> {
    await this.#requireNodeReady();
    assertInvoiceNetwork(this.#config.network, invoice);
    const stored = this.#idempotency?.fetch("pay-invoice", idempotencyKey);
    if (stored) return stored.result as Record<string, unknown>;
    const sent = await this.#phoenixd!.payInvoice(invoice);
    const actualAmountSat = sent.recipientAmountSat + sent.routingFeeSat;
    const { expected, known } = expectedTotalOutflowSat(invoice);
    const preimage = sent.paymentPreimage;
    if (preimage) registerSecret(preimage);
    // SEC-2026-047: the idempotency result cache NEVER persists the preimage.
    const result = {
      paymentHash: sent.paymentHash,
      status: "settled",
      activityId: sent.paymentId,
      actualAmountSat: String(actualAmountSat),
      expectedFeeSat: String(expectedFeeSat(invoice)),
      feeKnown: known,
      // OMEGA-DELTA-0300 (loss rule, SEC-2026-098): the expected total
      // outflow (invoice amount + expected fee) is reported so the Rust-side
      // expected-vs-actual settle comparison has the expected bound — a
      // payment settling for MORE than this auto-sets the spend kill.
      expectedTotalOutflowSat: String(expected),
      totalOutflowKnown: known,
      warning: known ? "" : "the invoice amount is unknown (pay-any); the loss rule cannot fire (total_outflow_known=false)",
      preimage,
    };
    const cached = { ...result, preimage: null };
    this.#idempotency?.store("pay-invoice", idempotencyKey, cached);
    return result;
  }

  /**
   * OMEGA-DELTA-0306 (design §3.4, WP-C4): host-initiated Debit settlement.
   * The Rust `pay_debit_invoice` wrapper runs `authorize_sovereign_spend` +
   * the spend policy BEFORE calling this — the sidecar never pays a Debit on
   * its own (SEC-2026-106: transport only). The principal MUST be the
   * verified event author (the signature's pubkey — never a content field).
   */
  async payDebit(debitId: string, principal: string): Promise<Record<string, unknown>> {
    if (!this.#clink) {
      throw envelopeError(
        "METHOD_NOT_FOUND",
        `METHOD_NOT_FOUND: pay-debit requires the CLINK layer (${CLINK_LAYER_ENV}=1; OMEGA-DELTA-0306)`,
      );
    }
    const { outcome, debit } = await this.#clink.payDebit(debitId, principal);
    if (outcome.status === "ok") {
      return {
        status: "ok",
        preimage: outcome.preimage ?? null,
        debitId,
        authorPubkey: debit?.authorPubkey ?? principal,
      };
    }
    return {
      status: "GFY",
      gfyCode: outcome.gfyCode ?? 2,
      gfyError: outcome.gfyError ?? "debit refused",
      debitId,
    };
  }

  /**
   * OMEGA-DELTA-0306 (design §3.4): host-initiated refusal WITHOUT paying —
   * the Rust wrapper calls this when `authorize_sovereign_spend` or the
   * spend policy refuses a queued Debit (GFY code 1 denied / 4 rate limited).
   */
  async refuseDebit(debitId: string, code: number, error: string): Promise<Record<string, unknown>> {
    if (!this.#clink) {
      throw envelopeError(
        "METHOD_NOT_FOUND",
        `METHOD_NOT_FOUND: debit-refuse requires the CLINK layer (${CLINK_LAYER_ENV}=1; OMEGA-DELTA-0306)`,
      );
    }
    const refused = await this.#clink.refuseDebit(debitId, code, error);
    return { refused, debitId };
  }

  /** Read-only view of the pending-debit queue (the host poller's input). */
  async pendingDebits(): Promise<Record<string, unknown>> {
    if (!this.#clink) {
      throw envelopeError(
        "METHOD_NOT_FOUND",
        `METHOD_NOT_FOUND: pending-debits requires the CLINK layer (${CLINK_LAYER_ENV}=1; OMEGA-DELTA-0306)`,
      );
    }
    const status = this.#clink.status();
    const debits = [];
    for (const debit of this.#clink.pendingDebits()) {
      debits.push({
        debitId: debit.debitId,
        authorPubkey: debit.authorPubkey,
        invoice: debit.invoice,
        amountSat: debit.amountSat ?? null,
        description: debit.description ?? null,
      });
    }
    return { enabled: status.enabled, pendingDebits: debits, count: debits.length };
  }

  /** Read-only CLINK layer status for the operator surface. */
  async clinkStatus(): Promise<Record<string, unknown>> {
    if (!this.#clink) {
      return { enabled: false, pendingDebits: 0, servicePubkey: null, note: `CLINK layer OFF (${CLINK_LAYER_ENV} unset)` };
    }
    const status = this.#clink.status();
    return { enabled: status.enabled, pendingDebits: status.pendingDebits, servicePubkey: status.servicePubkey };
  }

  /** Merged wallet activity feed (design §2.2). */
  async activity(limit = 100, cursor?: string): Promise<Record<string, unknown>> {
    // OMEGA-DELTA-0303: the phoenixd payments-surface re-point is later-slice
    // work; until it lands, activity fails closed with a named error.
    throw envelopeError(
      "INTERNAL",
      "INTERNAL: activity is not yet wired on the phoenixd rail (OMEGA-DELTA-0303); the payments-surface re-point lands in a later C3 slice",
      { remediation: "use the node operator surfaces (payments/incoming|outgoing) until the re-point lands" },
    );
  }

  /**
   * Identity/vault projection (design §2.2 `identity-status`). Read-only,
   * public projection only — never key material. Reports real vault/identity
   * state: created (none/locked/unlocked), the derived npub, and the derived
   * pubkey hex (WP-5: the principal for pubkey-keyed spending authorizations).
   */
  async identityStatus(): Promise<Record<string, unknown>> {
    if (!this.#vault) {
      return {
        vaultState: "none",
        derivedNpub: null,
        derivedPubkeyHex: null,
        recoveryArtifactState: "absent",
        note: "vault not initialized",
      };
    }
    // The vault state is derived from both the on-disk marker and the in-memory
    // master key (a locked-on-disk vault is "locked" until unlocked).
    const onDisk = await this.#vault.existsOnDisk();
    const state: "none" | "locked" | "unlocked" = !onDisk
      ? "none"
      : this.#vault.isUnlocked()
        ? "unlocked"
        : "locked";
    let derivedNpub: string | null = null;
    let derivedPubkeyHex: string | null = null;
    if (this.#vault.isUnlocked()) {
      const identity = await listPrimaryIdentity(this.#vault).catch(() => null);
      derivedNpub = identity?.npub ?? null;
      derivedPubkeyHex = identity?.pubkeyHex ?? null;
    }
    return {
      vaultState: state,
      derivedNpub,
      derivedPubkeyHex,
      recoveryArtifactState: onDisk ? "absent" : "absent", // operator-exported; not auto-persisted
      note: "WP-4: satnam-derived identity/vault (BIP-39/NIP-06 root, OMEGA-DELTA-0284)",
    };
  }

  /**
   * Operator-only identity ceremony step 1 (design §4.3; WP-5 renders the
   * ceremony): generate a fresh 12-word BIP-39 mnemonic, show it ONCE, and
   * hold it in memory pending the word-challenge commit. Never persisted;
   * registered for redaction; cleared on commit/lock/teardown.
   */
  async vaultInitPrepare(): Promise<Record<string, unknown>> {
    if (!this.#vault) {
      throw envelopeError("INTERNAL", "the vault is not initialized");
    }
    if (await this.#vault.existsOnDisk()) {
      throw envelopeError("INVALID_ARGS", "a vault already exists; the identity ceremony runs once");
    }
    const mnemonic = generateMnemonic12();
    registerSecret(mnemonic);
    this.#pendingMnemonic = mnemonic;
    return {
      mnemonic,
      challengeLabels: challengeLabels(),
      note: "show-once: record these 12 words; they are never shown again (lost words = lost identity unless a NIP-49 recovery artifact was exported)",
    };
  }

  /**
   * Operator-only identity ceremony step 2 (design §4.3): commit the pending
   * ceremony — verify the operator recorded the mnemonic (word challenge at
   * positions 2/7/11), initialize the vault under the passphrase, and store
   * the derived identity. The mnemonic is then dropped. A lost passphrase
   * makes the vault unrecoverable without a recovery artifact (SEC-2026-052
   * consequence, stated in the dashboard ceremony copy).
   */
  async vaultInit(
    passphrase: string,
    answers: Record<number, string>,
  ): Promise<Record<string, unknown>> {
    if (!this.#vault) {
      throw envelopeError("INTERNAL", "the vault is not initialized");
    }
    if (await this.#vault.existsOnDisk()) {
      throw envelopeError("INVALID_ARGS", "a vault already exists; the identity ceremony runs once");
    }
    if (!this.#pendingMnemonic) {
      throw envelopeError("INVALID_ARGS", "no pending identity ceremony; run vault-init-prepare first");
    }
    if (passphrase.length < MIN_PASSPHRASE_LEN) {
      throw envelopeError(
        "INVALID_ARGS",
        `the vault passphrase must be at least ${MIN_PASSPHRASE_LEN} characters (SEC-2026-052)`,
      );
    }
    if (!verifyChallenge(this.#pendingMnemonic, answers)) {
      throw envelopeError("INVALID_ARGS", "the word challenge failed; the ceremony is canceled", {
        remediation: "run vault-init-prepare again and record the words exactly",
      });
    }
    registerSecret(passphrase);
    const mnemonic = this.#pendingMnemonic;
    this.#pendingMnemonic = null;
    try {
      await this.#vault.initialize(passphrase);
      const derived = deriveFromMnemonic(mnemonic);
      try {
        await this.#vault.storeNsec(derived.publicPart.npub, derived.secret);
      } finally {
        derived.secret.fill(0);
      }
      this.#vaultState = "unlocked";
      return {
        vaultState: "unlocked",
        npub: derived.publicPart.npub,
        pubkeyHex: derived.publicPart.pubkeyHex,
        note: "identity ceremony complete; the mnemonic is dropped",
      };
    } catch (error) {
      this.#vault?.lock();
      this.#vaultState = "locked";
      throw error;
    }
  }

  /**
   * Operator-only vault unlock (design §4.2; the ceremony's passphrase step).
   * WP-3a (OMEGA-DELTA-0301 / RV6-REQ-3/5): unlock is keychain-first — the
   * passphrase is used only on the degraded path, which requires the explicit
   * fallback opt-in (OMEGA_VAULT_ALLOW_PASSPHRASE_FALLBACK=1) and, on a
   * mainnet-configured wallet, an explicit operator confirmation (the
   * loopback bearer token alone is not sufficient). The result reports
   * `wrapMethod` so callers surface degradation honestly; `migrated` is true
   * when a pre-0301 argon2id-only vault migrated in place.
   */
  async vaultUnlock(
    passphrase: string,
    opts?: { operatorConfirmed?: boolean },
  ): Promise<Record<string, unknown>> {
    if (!this.#vault) {
      throw envelopeError("INTERNAL", "the vault is not initialized");
    }
    if (!(await this.#vault.existsOnDisk())) {
      throw envelopeError("INVALID_ARGS", "no vault exists; run the identity ceremony first");
    }
    registerSecret(passphrase);
    try {
      const result = await this.#vault.unlock(passphrase, {
        allowPassphraseFallback: process.env[VAULT_FALLBACK_OPT_IN_ENV] === "1",
        // "Mainnet-configured" (RV6-REQ-5) reads the configured network env
        // directly: the network enum cannot express "mainnet" until
        // the 0286 grammar lands (WP-3), and this seam must exist before it.
        mainnetConfigured: process.env.OMEGA_SOVEREIGN_WALLET_NETWORK === "mainnet",
        operatorConfirmed: opts?.operatorConfirmed === true,
      });
      this.#vaultState = "unlocked";
      const identity = await listPrimaryIdentity(this.#vault).catch(() => null);
      return {
        vaultState: "unlocked",
        derivedNpub: identity?.npub ?? null,
        derivedPubkeyHex: identity?.pubkeyHex ?? null,
        wrapMethod: result.wrapMethod,
        migrated: result.migrated ?? false,
      };
    } catch (error) {
      if (error instanceof Error && "vaultError" in error && error.vaultError === "DecryptionFailed") {
        throw envelopeError("INVALID_ARGS", "vault decryption failed (wrong passphrase on the fallback path, wrong keychain entry, or corrupted master.key)", {
          remediation: "a lost passphrase is unrecoverable without a recovery artifact",
        });
      }
      throw error;
    }
  }

  /**
   * Operator-only one-time Nostr-secret export (design §2.2
   * `export-nostr-secret`; WP-5 seam — the bridge into the Rust
   * `omega_identity` import path, §4.6). Refused unless the vault is
   * unlocked and an identity exists; refused permanently after the first
   * export (`EXPORT_ALREADY_CONSUMED`). The nsec is registered for redaction
   * and never logged (SEC-2026-046).
   */
  async exportNostrSecret(): Promise<Record<string, unknown>> {
    if (!this.#vault || !this.#vault.isUnlocked()) {
      throw envelopeError("WALLET_LOCKED", "the vault is locked; export-nostr-secret requires an unlocked vault", {
        remediation: "unlock the vault first (operator-only)",
      });
    }
    const identity = await listPrimaryIdentity(this.#vault).catch(() => null);
    if (!identity) {
      throw envelopeError("NOT_FOUND", "no identity exists in the vault; initialize the identity first");
    }
    // One-time bridge: a durable marker under run/ (non-secret; the nsec is
    // never persisted). Re-export is refused permanently.
    const markerPath = path.join(this.#runDir, "export-nostr-secret.done");
    try {
      await fs.access(markerPath);
      throw envelopeError(
        "EXPORT_ALREADY_CONSUMED",
        "export-nostr-secret has already been consumed; the bridge is one-time (design §2.2)",
      );
    } catch (error) {
      if (error instanceof Error && "envelope" in error) throw error;
      // marker absent → first export
    }
    const secret = await this.#vault.getNsec(identity.npub);
    const nsec = encodeNsec(secret);
    secret.fill(0);
    registerSecret(nsec);
    await writeMarker(markerPath, { exported: identity.npub });
    return { nsec, npub: identity.npub, exported: true };
  }

  /**
   * WP-6: the MCP-server -> Nostr-identity mapping (design §6.4 / §5.4). Read
   * projection of the L-402 gateway's attribution map — server id -> principal
   * pubkey (64-hex, public). Never key material.
   */
  async mcpIdentityMapGet(): Promise<Record<string, unknown>> {
    if (!this.#l402Store) {
      throw envelopeError("INTERNAL", "the L-402 gateway store is not initialized");
    }
    return { entries: this.#l402Store.mcpIdentityMapGet() };
  }

  /**
   * WP-6: set (or unset) the MCP-server -> Nostr-identity mapping. The
   * principal is a public 64-hex Nostr pubkey (the pubkey-keyed L-402
   * entitlement attribution). Operator/stdio surface only; the HTTP surface
   * registers read projections only.
   */
  async mcpIdentityMapSet(serverId: string, principalPubkey: string | null): Promise<Record<string, unknown>> {
    if (!this.#l402Store) {
      throw envelopeError("INTERNAL", "the L-402 gateway store is not initialized");
    }
    const id = serverId.trim();
    if (id.length === 0 || /[\s"']/.test(id) || /[\u0000-\u001f]/.test(id)) {
      throw envelopeError("INVALID_ARGS", "serverId must be a non-empty id without whitespace, quotes, or control characters");
    }
    if (principalPubkey !== null && !/^[0-9a-fA-F]{64}$/.test(principalPubkey)) {
      throw envelopeError("INVALID_ARGS", "principalPubkey must be 64-hex (a public Nostr pubkey) or null");
    }
    this.#l402Store.mcpIdentityMapSet(id, principalPubkey?.toLowerCase() ?? null);
    return { serverId: id, principalPubkey: principalPubkey?.toLowerCase() ?? null, updated: true };
  }

  /**
   * Engine-owned state refresh (OMEGA-DELTA-0303): the phoenixd rail's node
   * state derives from the getinfo probe — "ready" when the probe answers,
   * "error" when it fails. The waved-era lifecycle states (none/locked/
   * syncing) no longer apply to a remote operator-managed node
   * (OMEGA-DELTA-0303).
   */
  async #refreshWalletState(): Promise<void> {
    if (!this.#phoenixd) return;
    try {
      const chain = await this.#phoenixd.probeChain();
      assertNetworkMatches(this.#config.network, chain, this.#config.allowMainnet);
      this.#walletState = "ready";
      this.#stopSyncWatcher();
    } catch {
      this.#walletState = "error";
      // keep the current state; the health check owns node-failure handling
    }
  }

  #startSyncWatcher(): void {
    if (this.#syncWatcher) return;
    this.#syncWatcher = setInterval(() => {
      void this.#refreshWalletState();
    }, 2_000);
  }

  #stopSyncWatcher(): void {
    if (this.#syncWatcher) {
      clearInterval(this.#syncWatcher);
      this.#syncWatcher = null;
    }
  }

  /**
   * OMEGA-DELTA-0303: the node-ready gate for the funded verbs. The phoenixd
   * client must be configured AND the startup probe must have answered (the
   * rail gate, design §2.6.2); a missing rail env is the named
   * NODE_UNCONFIGURED state, a failed probe the named node-unreachable state.
   */
  #requireNodeReady(): void {
    if (!this.#phoenixd) {
      throw envelopeError(
        "NODE_UNCONFIGURED",
        this.#nodeUnavailableReason || "the phoenixd rail is not connected (OMEGA-DELTA-0303)",
        { retryable: false, remediation: "verify the phoenixd node + the Tailscale/SSH path and restart the sidecar" },
      );
    }
  }

  async dispatch(method: string, params: Record<string, unknown>, requestId: string, generation: number): Promise<unknown> {
    if (generation !== this.#generation) {
      throw envelopeError("STALE_GENERATION", `generation ${generation} does not match active generation ${this.#generation}`);
    }
    switch (method) {
      case "initialize":
        return this.initialize();
      case "health":
        return this.health();
      case "status":
        return this.statusProjection();
      case "balance":
        return this.balance();
      case "wallet-height":
        // WP-4b timeout observation (SEC-2026-087): the daemon-level block
        // height probe. Read-only; needs the daemon, not an unlocked wallet.
        return this.walletHeight();
      case "create-wallet":
        return this.createWallet(requireString(params, "idempotencyKey"), requireString(params, "password"));
      case "unlock":
        return this.unlock(requireString(params, "idempotencyKey"), requireString(params, "password"));
      case "lock":
        return this.lock();
      case "make-invoice":
        return this.makeInvoice(
          requireNumber(params, "amtSat"),
          stringOr(params, "memo", "") ?? "",
          requireString(params, "idempotencyKey"),
        );
      case "pay-invoice":
        return this.payInvoice(requireString(params, "invoice"), requireString(params, "idempotencyKey"));
      case "pay-debit":
        // OMEGA-DELTA-0306 (design §3.4): host-initiated Debit settlement.
        // The Rust wrapper authorizes BEFORE calling; the sidecar verifies the
        // principal is the verified event author and then pays.
        return this.payDebit(requireString(params, "debitId"), requireString(params, "principal"));
      case "debit-refuse":
        // OMEGA-DELTA-0306: host-initiated refusal WITHOUT paying (GFY).
        return this.refuseDebit(
          requireString(params, "debitId"),
          requireNumber(params, "code"),
          requireString(params, "error"),
        );
      case "pending-debits":
        // OMEGA-DELTA-0306: read-only queue view (the host poller's input).
        return this.pendingDebits();
      case "clink-status":
        // OMEGA-DELTA-0306: read-only CLINK layer state.
        return this.clinkStatus();
      case "activity":
        return this.activity(numberOr(params, "limit", 100), stringOr(params, "cursor", undefined));
case "identity-status":
        return this.identityStatus();
      case "vault-init-prepare":
        // Operator-only ceremony step 1 (never the agent channel).
        return this.vaultInitPrepare();
      case "vault-init":
        return this.vaultInit(
          requireString(params, "passphrase"),
          requireAnswers(params, "answers"),
        );
      case "vault-unlock":
        // RV6-REQ-5: the operator confirmation is passed through for
        // mainnet-configured wallets (WP-7 wires the stdio prompt).
        return this.vaultUnlock(requireString(params, "passphrase"), {
          operatorConfirmed: params.operatorConfirmed === true,
        });
      case "export-nostr-secret":
        // Operator-only: reachable only on the stdio control plane. The HTTP
        // surface registers read projections only, so this method is
        // unreachable from the agent channel by construction (tested).
        return this.exportNostrSecret();
      case "mcp-identity-map-get":
        // Read projection of the L-402 attribution map (public pubkeys only).
        return this.mcpIdentityMapGet();
      case "mcp-identity-map-set":
        // Operator/stdio surface: set or unset a server -> Nostr-identity
        // mapping (design §6.4). Never the agent HTTP channel.
        return this.mcpIdentityMapSet(
          requireString(params, "serverId"),
          stringOrNull(params, "principalPubkey"),
        );
      case "shutdown": {
        void this.stop().then(() => process.exit(0));
        return { stopping: true };
      }
      default:
        throw envelopeError("METHOD_NOT_FOUND", `unknown method ${method}`);
    }
  }
}

// ---------------------------------------------------------------------------
// CLINK relay transport (OMEGA-DELTA-0306, design §3.2)
// ---------------------------------------------------------------------------

/**
 * The real relay adapter: subscribes to kinds 21001/21002 addressed to the
 * service pubkey and publishes service replies via nostr-tools SimplePool
 * (re-exported by the pinned @shocknet/clink-sdk — never a second copy).
 * Tests inject a fake adapter (CI never touches a live relay).
 */
export class SimplePoolClinkRelayAdapter implements RelayAdapter {
  readonly #pool = new SimplePool();
  readonly #relayUrls: string[];

  constructor(relayUrl: string) {
    this.#relayUrls = [relayUrl];
  }

  subscribe(
    kinds: number[],
    toPubkey: string,
    onEvent: (event: import("nostr-tools").Event) => void,
  ): () => void {
    const sub = this.#pool.subscribeMany(
      this.#relayUrls,
      [{ kinds, "#p": [toPubkey] }],
      { onevent: onEvent },
    );
    return () => sub.close();
  }

  async publish(event: import("nostr-tools").Event): Promise<void> {
    await Promise.allSettled(this.#pool.publish(this.#relayUrls, event));
  }

  close(): void {
    this.#pool.close(this.#relayUrls);
  }
}

// ---------------------------------------------------------------------------
// Frame loop (bounded newline-framed JSON over stdio)
// ---------------------------------------------------------------------------

export async function runFrameLoop(core: SidecarCore): Promise<void> {
  const stdin = process.stdin;
  stdin.resume();
  stdin.setEncoding("utf8");

  let buffer = "";
  let generation = 0;

  const respond = (frame: string): void => {
    process.stdout.write(frame);
  };

  const processLine = async (line: string): Promise<void> => {
    let frame: { id?: unknown; method?: unknown; generation?: unknown; kind?: unknown; params?: unknown };
    try {
      frame = JSON.parse(line) as typeof frame;
    } catch {
      respond(encodeResponse({
        schema: PROTOCOL_SCHEMA,
        kind: "response",
        id: "0",
        generation,
        ok: false,
        error: errorEnvelope("INVALID_ARGS", "frame is not valid JSON"),
      }));
      return;
    }
    if (frame.kind !== "request" || typeof frame.method !== "string") {
      respond(encodeResponse({
        schema: PROTOCOL_SCHEMA,
        kind: "response",
        id: typeof frame.id === "string" ? frame.id : "0",
        generation,
        ok: false,
        error: errorEnvelope("INVALID_ARGS", "frame is not a request"),
      }));
      return;
    }
    const id = frame.id as string;
    const method = frame.method;
    const requestGeneration = typeof frame.generation === "number" ? frame.generation : 0;
    if (method === "initialize") {
      generation = requestGeneration;
      core.setGeneration(requestGeneration);
    }
    const params = (frame.params ?? {}) as Record<string, unknown>;
    try {
      const result = await core.dispatch(method, params, id, requestGeneration);
      respond(encodeResponse({
        schema: PROTOCOL_SCHEMA,
        kind: "response",
        id,
        generation,
        ok: true,
        result,
      }));
    } catch (error) {
      const envelope = error instanceof Error && "envelope" in error
        ? (error as { envelope: { code: ErrorCode; message: string; details: string; retryable: boolean; remediation: string } }).envelope
        : errorEnvelope("INTERNAL", error instanceof Error ? error.message : String(error), { retryable: true });
      // Never echo request secrets in error envelopes (SEC-2026-046).
      respond(encodeResponse({
        schema: PROTOCOL_SCHEMA,
        kind: "response",
        id,
        generation,
        ok: false,
        error: { ...envelope, message: redact(envelope.message), details: redact(envelope.details) },
      }));
    }
  };

  for await (const chunk of stdin) {
    buffer += chunk;
    let newlineIndex: number;
    while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newlineIndex);
      buffer = buffer.slice(newlineIndex + 1);
      if (line.length > MAX_FRAME_BYTES) {
        respond(encodeResponse({
          schema: PROTOCOL_SCHEMA,
          kind: "response",
          id: "0",
          generation,
          ok: false,
          error: errorEnvelope("INVALID_ARGS", `frame exceeds ${MAX_FRAME_BYTES} bytes`),
        }));
        continue;
      }
      if (line.trim().length === 0) continue;
      await processLine(line);
    }
    if (buffer.length > MAX_FRAME_BYTES * 2) {
      respond(encodeResponse({
        schema: PROTOCOL_SCHEMA,
        kind: "response",
        id: "0",
        generation,
        ok: false,
        error: errorEnvelope("INVALID_ARGS", "frame buffer exceeds the byte budget"),
      }));
      buffer = "";
    }
  }
}

// ---------------------------------------------------------------------------
// Startup / entry
// ---------------------------------------------------------------------------

export function parseEnvironment(): SidecarConfig {
  const networkRaw = process.env.OMEGA_SOVEREIGN_WALLET_NETWORK;
  // OMEGA-DELTA-0286: mainnet is accepted ONLY with the explicit opt-in.
  // Without it: MAINNET_REFUSED exactly as before (D4). An unset network
  // never defaults to mainnet.
  if (networkRaw === "mainnet" && process.env[ALLOW_MAINNET_ENV] !== "1") {
    throw envelopeError(
      "MAINNET_REFUSED",
      `MAINNET_REFUSED: OMEGA_SOVEREIGN_WALLET_NETWORK=mainnet requires ${ALLOW_MAINNET_ENV}=1 (OMEGA-DELTA-0286)`,
    );
  }
  if (networkRaw !== "mainnet") {
    if (networkRaw === "signet" || networkRaw === "regtest") {
      throw envelopeError(
        "INVALID_ARGS",
        "INVALID_ARGS: the payments rail is mainnet-operative (CLINK/phoenixd); signet/regtest rail configuration is refused at startup (OMEGA-DELTA-0305)",
      );
    }
    throw envelopeError(
      "INVALID_ARGS",
      `INVALID_ARGS: OMEGA_SOVEREIGN_WALLET_NETWORK must be mainnet (mainnet only with ${ALLOW_MAINNET_ENV}=1); an unset network never defaults to mainnet (design §3.2)`,
    );
  }
  const dataRoot = process.env.OMEGA_SOVEREIGN_WALLET_DATA_ROOT;
  if (!dataRoot) {
    throw envelopeError("INVALID_ARGS", "OMEGA_SOVEREIGN_WALLET_DATA_ROOT is required");
  }
  const loopbackToken = process.env.OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN;
  // OMEGA-DELTA-0303: the phoenixd rail envs (design §9.3). The API key is
  // env-only and registered for redaction at load (SEC-2026-046) so it can
  // never reach a log or an error envelope.
  const phoenixdUrl = process.env[PHOENIXD_URL_ENV];
  const phoenixdApiKey = process.env[PHOENIXD_API_KEY_ENV];
  if (phoenixdApiKey) registerSecret(phoenixdApiKey);
  // The rail gate (design §2.6.2, 0303): a MAINNET rail without a configured
  // phoenixd connection is a configuration error, never a silent zero.
  if (networkRaw === "mainnet" && (!phoenixdUrl || !phoenixdApiKey)) {
    throw envelopeError(
      "NODE_UNCONFIGURED",
      `NODE_UNCONFIGURED: the mainnet rail requires ${PHOENIXD_URL_ENV} and ${PHOENIXD_API_KEY_ENV} (rail gate; OMEGA-DELTA-0303)`,
      { remediation: "set the phoenixd URL + API key (env-only) for the mainnet rail" },
    );
  }
  const generation = Number.parseInt(process.env.OMEGA_SOVEREIGN_WALLET_GENERATION ?? "1", 10) || 1;
  // OMEGA-DELTA-0301 / RV6-REQ-1: "memory" is the TEST-ONLY keychain seam
  // (never set in production); the production default is the OS keychain.
  const vaultKeychainRaw = process.env.OMEGA_SOVEREIGN_WALLET_VAULT_KEYCHAIN;
  const vaultKeychain = vaultKeychainRaw === "memory" ? "memory" : undefined;
  // OMEGA-DELTA-0306 (design §9.2/§9.3): the CLINK layer flag + envs. Default
  // OFF; ON requires the relay URL + the service signing key (env-injected,
  // redaction-registered — the 64-hex shape is already covered by redact.ts).
  const clinkEnabled = process.env[CLINK_LAYER_ENV] === "1";
  const clinkRelayUrl = process.env[CLINK_RELAY_ENV];
  const clinkServiceKey = process.env[CLINK_SERVICE_KEY_ENV];
  if (clinkEnabled && clinkServiceKey) registerSecret(clinkServiceKey);
  return {
    dataRoot,
    network: networkRaw as PhoenixdNetwork,
    allowMainnet: networkRaw === "mainnet" && process.env[ALLOW_MAINNET_ENV] === "1",
    loopbackToken,
    phoenixdUrl,
    phoenixdApiKey,
    generation,
    vaultKeychain,
    clinkEnabled,
    clinkRelayUrl,
    clinkServiceKey,
  };
}

export async function main(): Promise<void> {
  process.on("SIGINT", () => {
    void coreStopAndExit();
  });
  process.on("SIGTERM", () => {
    void coreStopAndExit();
  });

  let core: SidecarCore | null = null;
  const coreStopAndExit = async (): Promise<void> => {
    if (core) await core.stop().catch(() => {});
    process.exit(0);
  };

  const program = Effect.gen(function* () {
    const config = parseEnvironment();
    core = new SidecarCore(config);
    yield* Effect.tryPromise({
      try: () => core!.start(),
      catch: (error) => error as Error,
    });
    // Health checkpoint immediately after startup: a node network mismatch at
    // startup already hard-bailed in start(); this re-asserts on the live state.
    const health = yield* Effect.tryPromise({ try: () => core!.health(), catch: (error) => error as Error });
    if (!health.ok) {
      yield* Effect.fail(new Error(`sidecar unhealthy at startup: ${String(health.note ?? "")}`));
    }
    return core!;
  });

  try {
    const started = await Effect.runPromise(program);
    core = started;
    await runFrameLoop(started);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // Hard-bail paths (MAINNET_REFUSED, ACL failure, lock held) exit non-zero
    // with the error on stderr; the supervisor surfaces the named state.
    if (core) await core.stop().catch(() => {});
    process.stderr.write(`sovereign-wallet: ${redact(message)}\n`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function envelopeError(
  code: ErrorCode,
  message: string,
  opts: { details?: string; retryable?: boolean; remediation?: string } = {},
): Error & { envelope: ReturnType<typeof errorEnvelope> } {
  const envelope = errorEnvelope(code, message, opts);
  const error = new Error(message) as Error & { envelope: ReturnType<typeof errorEnvelope> };
  error.envelope = envelope;
  return error;
}

function isMainnetRefused(error: unknown): boolean {
  return (
    error instanceof Error &&
    "envelope" in error &&
    (error as { envelope: { code: string } }).envelope.code === "MAINNET_REFUSED"
  );
}

function requireString(params: Record<string, unknown>, key: string): string {
  const value = params[key];
  if (typeof value !== "string" || value.length === 0) {
    throw envelopeError("INVALID_ARGS", `${key} must be a non-empty string`);
  }
  return value;
}

function requireNumber(params: Record<string, unknown>, key: string): number {
  const value = params[key];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw envelopeError("INVALID_ARGS", `${key} must be a number`);
  }
  return value;
}

function stringOr(params: Record<string, unknown>, key: string, fallback: string | undefined): string | undefined {
  const value = params[key];
  return typeof value === "string" ? value : fallback;
}

/** A string param that may be null (e.g. an unset principal mapping). */
function stringOrNull(params: Record<string, unknown>, key: string): string | null {
  const value = params[key];
  if (value === null || value === undefined) return null;
  return typeof value === "string" ? value : null;
}

function numberOr(params: Record<string, unknown>, key: string, fallback: number): number {
  const value = params[key];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

/** The identity ceremony's word-challenge answers: {"2": word, "7": word, "11": word}. */
function requireAnswers(
  params: Record<string, unknown>,
  key: string,
): Record<number, string> {
  const value = params[key];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw envelopeError("INVALID_ARGS", `${key} must be an object of word answers`);
  }
  const answers: Record<number, string> = {};
  for (const [label, word] of Object.entries(value as Record<string, unknown>)) {
    const index = Number.parseInt(label, 10);
    if (!Number.isInteger(index) || typeof word !== "string" || word.length === 0) {
      throw envelopeError("INVALID_ARGS", `${key} entries must map 1-based positions to words`);
    }
    answers[index - 1] = word; // 1-based labels → 0-indexed challenge indexes
  }
  return answers;
}

async function writeMarker(path: string, marker: WalletMarker): Promise<void> {
  await fs.writeFile(path, JSON.stringify(marker), { mode: 0o600 });
}

// Run when executed directly.
if (import.meta.url === pathToFileUrl(path.resolve(process.argv[1] ?? "")).href) {
  void main();
}

function pathToFileUrl(filePath: string): URL {
  return new URL(`file:///${filePath.replace(/\\/g, "/")}`);
}
