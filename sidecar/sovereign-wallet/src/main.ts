//! Sovereign wallet sidecar — main program (design §1, §2, §3).
//!
//! Effect-composed Node 24 service supervised by `crates/sovereign_wallet`:
//! stdio control plane (newline-framed JSON, bounded frames, generation
//! fencing), supervised `waved` child (signet), loopback HTTP projections
//! (bearer-token protected), idempotency ledger, owner-only data-root ACLs.
//!
//! Environment (injected by the supervisor; never secrets in args):
//!   OMEGA_SOVEREIGN_WALLET_DATA_ROOT        (required)
//!   OMEGA_SOVEREIGN_WALLET_NETWORK          signet | regtest (mainnet refused)
//!   OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN   32-byte hex, per launch
//!   OMEGA_SOVEREIGN_WALLET_WAVED_BIN        path to the pinned waved artifact

import { Effect } from "effect";
import fs from "node:fs/promises";
import path from "node:path";

import { lockdownTree } from "./acl.js";
import { LoopbackHttpServer, validateLoopbackToken } from "./http.js";
import { IdempotencyStore } from "./idempotency.js";
import { L402Gateway, DEMO_ECHO_PATH, DEMO_MCP_PATH_PREFIX } from "./l402.js";
import { L402Store } from "./l402-store.js";
import { acquireLock, type LockHandle } from "./lock.js";
import type { ErrorCode } from "./protocol.js";
import { PROTOCOL_SCHEMA, PROTOCOL_VERSION, SERVICE_VERSION, encodeResponse, errorEnvelope } from "./protocol.js";
import { clearRegisteredSecrets, redact, registerSecret } from "./redact.js";
import { MIN_PASSPHRASE_LEN, Vault } from "./vault/vault.js";
import { listPrimaryIdentity } from "./identity/index.js";
import { deriveFromMnemonic, encodeNsec, generateMnemonic12 } from "./identity/keygen.js";
import { challengeLabels, verifyChallenge } from "./identity/ceremony.js";
import {
  WavelengthClient,
  assertInvoiceNetwork,
  assertNetworkMatches,
  startWaved,
  terminateWaved,
  type WavelengthNetwork,
  type WavedHandle,
} from "./wavelength.js";

const MAX_FRAME_BYTES = 64 * 1024;
const HEALTH_TIMEOUT_MS = 5_000;
const PAY_TIMEOUT_MS = 180_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const SHUTDOWN_GRACE_MS = 2_000;

export type WalletState = "none" | "locked" | "syncing" | "ready" | "error";

export interface SidecarConfig {
  dataRoot: string;
  network: WavelengthNetwork;
  loopbackToken: string | undefined;
  wavedBin: string | undefined;
  generation: number;
  /**
   * Test/dev-only knob: where the sidecar's REST client points. The real waved
   * daemon always serves the REST gateway on the documented default
   * 127.0.0.1:10031 (api/get-started.md); the flag to move it is not
   * documented, so this only redirects the CLIENT (used by tests that run a
   * fake waved on a per-test port).
   */
  wavedRestPort?: number;
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
  wavedConnected: boolean;
  network: WavelengthNetwork;
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
  #waved: WavedHandle | null = null;
  #wavedUnavailableReason = "";
  #idempotency: IdempotencyStore | null = null;
  #http: LoopbackHttpServer | null = null;
  #httpReason: string | undefined;
  #walletPassword: string | null = null;
  #operatorLocked = false;
  #walletCreated = false;
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

  constructor(config: SidecarConfig) {
    this.#config = config;
    this.#runDir = path.join(config.dataRoot, "run");
    this.#generation = config.generation;
  }

  get network(): WavelengthNetwork {
    return this.#config.network;
  }

  get generation(): number {
    return this.#generation;
  }

  get dataRoot(): string {
    return this.#config.dataRoot;
  }

  get wavedConnected(): boolean {
    return this.#waved !== null;
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

  /** Full startup: data root, ACLs, lock, idempotency, waved, HTTP, marker. */
  async start(): Promise<void> {
    const { dataRoot, network } = this.#config;
    await fs.mkdir(dataRoot, { recursive: true });
    await fs.mkdir(this.#runDir, { recursive: true });
    await fs.mkdir(path.join(dataRoot, "logs"), { recursive: true });
    await fs.mkdir(path.join(dataRoot, "wavelength"), { recursive: true });

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

    // Wallet-created marker (non-secret; distinguishes none/locked within the
    // REST-only surface — getinfo is gRPC-only and not on the REST gateway).
    const markerPath = path.join(this.#runDir, "wallet-state.json");
    const marker = await readMarker(markerPath);
    this.#walletCreated = marker?.created ?? false;
    this.#walletState = this.#walletCreated ? "locked" : "none";

    // WP-4 vault: satnam-derived identity/vault root at <data_root>/vault.
    // The vault is the sidecar's authority for the BIP-39 identity/vault root
    // and the Wavelength wallet secrets (Q1: aezeed vaulted, not derived).
    this.#vault = new Vault({ vaultRoot: "vault", idleTimeoutMs: 900_000 }, dataRoot);
    this.#vaultState = (await this.#vault.existsOnDisk()) ? "locked" : "none";

    // WP-6: the L-402 gateway state store (SQLite; survives restarts by
    // construction — design §5.5). The gateway itself is constructed after
    // waved so its mint path can reach the wallet engine.
    this.#l402Store = L402Store.open(path.join(dataRoot, "l402"));

    // HTTP surface: fail-closed on a missing/malformed token (SEC-2026-053).
    this.#httpReason = validateLoopbackToken(this.#config.loopbackToken) ?? undefined;
    if (!this.#httpReason && this.#config.loopbackToken) {
      this.#http = await LoopbackHttpServer.bind({
        token: this.#config.loopbackToken,
        onStatus: () => this.statusProjection(),
        onBalance: () => this.balance(),
        // WP-6: the L-402 gateway routes (the ONLY paid boundary). The
        // gateway is constructed after waved below; the handler is bound
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

    // waved: only when a pinned binary is configured. A missing binary is a
    // named, surfaced state (never a silent zero); a network mismatch is a
    // hard bail (SEC-2026-050).
    if (this.#config.wavedBin) {
      try {
        this.#waved = await startWaved({
          binary: this.#config.wavedBin,
          dataRoot,
          network,
          restPort: this.#config.wavedRestPort,
        });
      } catch (error) {
        const envelope = error instanceof Error && "envelope" in error
          ? (error as { envelope: { code: ErrorCode; message: string } }).envelope
          : null;
        if (envelope?.code === "MAINNET_REFUSED") {
          await this.#releaseAll();
          throw error;
        }
        this.#wavedUnavailableReason = envelope?.message ?? (error instanceof Error ? error.message : String(error));
        this.#waved = null;
        this.#walletState = "error";
      }
    } else {
      this.#wavedUnavailableReason = "OMEGA_SOVEREIGN_WALLET_WAVED_BIN is not set";
    }

    // WP-6: construct the L-402 gateway (design §5). The gateway mints via
    // the Wavelength engine (Recv) and refuses mainnet everywhere; the
    // wallet-ready gate is the sidecar's own `#requireWalletReady`
    // (SEC-2026-054 locked-wallet fail-closed mint).
    if (this.#l402Store) {
      this.#l402Gateway = new L402Gateway({
        network,
        store: this.#l402Store,
        vault: this.#vault,
        walletReady: () => this.#requireWalletReady(),
        mintInvoice: async (amtSat, memo) => {
          const received = await this.#waved!.client.recvInvoice(amtSat, memo);
          assertInvoiceNetwork(network, received.invoice);
          return {
            invoice: received.invoice,
            entryPaymentHash:
              received.entry.request?.lightning_invoice?.payment_hash ??
              received.entry.progress?.payment_hash ??
              null,
          };
        },
        nowMs: () => Date.now(),
      });
    }
  }

  /** Ordered teardown: waved first, then HTTP, then idempotency, then lock. */
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
    if (this.#waved) {
      await terminateWaved(this.#waved.child).catch(() => {});
      this.#waved = null;
    }
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

  /** Periodic health: re-assert waved's runtime network (SEC-2026-050). */
  async health(): Promise<HealthProjection> {
    if (this.#waved) {
      try {
        const status = await this.#waved.status();
        assertNetworkMatches(this.#config.network, status.network);
      } catch (error) {
        if (isMainnetRefused(error)) {
          // The daemon drifted to mainnet at runtime: hard bail.
          await this.stop();
          return this.healthProjection(false, "mainnet drift detected; sidecar stopped");
        }
        if (this.#waved.child.exitCode !== null) {
          this.#waved = null;
          this.#wavedUnavailableReason = "waved exited";
          this.#walletState = "error";
        }
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
      wavedConnected: this.wavedConnected,
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
      wavedConnected: this.wavedConnected,
      wavedUnavailableReason: this.#wavedUnavailableReason,
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
    return {
      schema: PROTOCOL_SCHEMA,
      protocolVersion: PROTOCOL_VERSION,
      serviceVersion: SERVICE_VERSION,
      generation: this.#generation,
capabilities: [
        "status",
        "balance",
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
      ],
      dataRoot: this.#config.dataRoot,
      network: this.#config.network,
      // SEC-2026-050: initialize reports waved's ACTUAL runtime network from
      // the probe, never the env value alone.
      wavedNetwork: this.#waved ? (await this.#waved.status()).network : null,
      wavedState: this.wavedConnected ? "connected" : "unavailable",
      httpSurface: this.httpSurface,
    };
  }

  async balance(): Promise<Record<string, unknown>> {
    await this.#requireWalletReady();
    const balance = await this.#waved!.client.balance();
    return {
      confirmedSat: balance.confirmed_sat,
      pendingInSat: balance.pending_in_sat,
      pendingOutSat: balance.pending_out_sat,
      creditAvailableSat: balance.credit_available_sat,
      creditReservedSat: balance.credit_reserved_sat,
    };
  }

/** Operator-only: create the Wavelength wallet (never the agent channel). */
  async createWallet(idempotencyKey: string, password: string): Promise<Record<string, unknown>> {
    this.#requireWaved();
    const stored = this.#idempotency?.fetch("create-wallet", idempotencyKey);
    if (stored) return stored.result as Record<string, unknown>;
    registerSecret(password);
    try {
      const created = await this.#waved!.client.createWallet(password);
      // Show-once aezeed; capture for the vault seam (WP-4) then register for
      // redaction so it can never reach a log.
      const mnemonic = created.mnemonic.join(" ");
      registerSecret(mnemonic);
      await writeMarker(path.join(this.#runDir, "wallet-state.json"), { created: true });
      this.#walletCreated = true;
      this.#walletState = "syncing";
      this.#startSyncWatcher();

      // WP-5 seam (design §4.2 `wallet/` entry, §4.3): capture the wallet DB
      // password + aezeed into the vault immediately at create. The vault must
      // be unlocked; otherwise the capture is honestly reported as not
      // vaulted (the operator holds the password + paper aezeed).
      let walletDbPasswordVaulted = false;
      let vaultWalletId: string | null = null;
      let note = "";
      const walletId = created.identity_pubkey ?? "default";
      if (this.#vault && this.#vault.isUnlocked()) {
        try {
          await this.#vault.storeWalletEntry({
            walletId,
            walletDbPassword: password,
            aezeed: mnemonic,
            createdAt: new Date().toISOString(),
          });
          walletDbPasswordVaulted = true;
          vaultWalletId = walletId;
        } catch (error) {
          // The vault write failed (e.g. locked mid-flight): never fail the
          // wallet creation on a capture problem; report the honest state.
          note = `vault capture failed: ${error instanceof Error ? error.message : String(error)}`;
        }
      } else {
        note =
          "the vault is not unlocked; the wallet DB password and aezeed were NOT vaulted (operator-held only)";
      }
      const result = {
        mnemonic: created.mnemonic,
        identityPubkey: created.identity_pubkey,
        walletDbPasswordVaulted,
        vaultWalletId,
        note,
      };
      this.#idempotency?.store("create-wallet", idempotencyKey, result);
      return result;
    } finally {
      // The password is consumed by the daemon; drop our copy.
      this.#walletPassword = null;
    }
  }

  /** Operator-only: unlock the Wavelength wallet (never the agent channel). */
  async unlock(idempotencyKey: string, password: string): Promise<Record<string, unknown>> {
    this.#requireWaved();
    const stored = this.#idempotency?.fetch("unlock", idempotencyKey);
    if (stored) return stored.result as Record<string, unknown>;
    registerSecret(password);
    try {
const unlocked = await this.#waved!.client.unlockWallet(password);
      this.#walletPassword = password;
      this.#operatorLocked = false;
      this.#walletState = "syncing";
      this.#startSyncWatcher();
      const result = { identityPubkey: unlocked.identity_pubkey, walletState: this.#walletState };
      this.#idempotency?.store("unlock", idempotencyKey, result);
      return result;
    } catch (error) {
      // Wrong password: the daemon consumed our copy; keep nothing.
      this.#walletPassword = null;
      throw error;
    }
  }

  /** Operator-only: lock the wallet surface and the vault (design §2.2). */
  async lock(): Promise<Record<string, unknown>> {
    // WP-3 seam: waved has no documented remote lock RPC, so the sidecar
    // enforces the lock boundary in memory (wallet RPCs refuse until unlock).
    // WP-4: the vault locks here too (zeroizes the master key).
    this.#walletPassword = null;
    this.#operatorLocked = true;
    this.#walletState = "locked";
    if (this.#vault) {
      this.#vault.lock();
      this.#vaultState = "locked";
    }
    // Drop any pending identity ceremony (the show-once mnemonic never
    // survives a lock; the operator restarts the ceremony).
    this.#pendingMnemonic = null;
    this.#stopSyncWatcher();
    return { walletState: this.#walletState, vaultState: this.#vaultState };
  }

  /** Mint a signet BOLT11 invoice (design §2.2; prefix guard §3.4). */
  async makeInvoice(amtSat: number, memo: string, idempotencyKey: string): Promise<Record<string, unknown>> {
    await this.#requireWalletReady();
    const stored = this.#idempotency?.fetch("make-invoice", idempotencyKey);
    if (stored) return stored.result as Record<string, unknown>;
    if (!Number.isSafeInteger(amtSat) || amtSat <= 0) {
      throw envelopeError("INVALID_ARGS", "amtSat must be a positive integer");
    }
    const received = await this.#waved!.client.recvInvoice(amtSat, memo);
    assertInvoiceNetwork(this.#config.network, received.invoice);
    const paymentHash =
      received.entry.progress?.payment_hash ??
      received.entry.request?.lightning_invoice?.payment_hash ??
      null;
    const result = {
      invoice: received.invoice,
      paymentHash,
      amountSat: amtSat,
      memo,
      // Signet invoices use the lntbs HRP (RV-3 verified against a live
      // daemon at staging; the guard accepts lntbs/lntb/lnbcrt, never lnbc).
      hrp: received.invoice.slice(0, 5),
    };
    this.#idempotency?.store("make-invoice", idempotencyKey, result);
    return result;
  }

  /** Pay a BOLT11 invoice (design §2.2; mandate gate is enforced Rust-side in WP-5). */
  async payInvoice(invoice: string, idempotencyKey: string): Promise<Record<string, unknown>> {
    await this.#requireWalletReady();
    assertInvoiceNetwork(this.#config.network, invoice);
    const stored = this.#idempotency?.fetch("pay-invoice", idempotencyKey);
    if (stored) return stored.result as Record<string, unknown>;
    const prepared = await this.#waved!.client.prepareSend(invoice);
    const sent = await this.#waved!.client.sendPrepared(prepared.send_intent_id);
    const entry = sent.entry;
    const preimage = entry.progress?.preimage ?? null;
    if (preimage) registerSecret(preimage);
    // SEC-2026-047: the idempotency result cache NEVER persists the preimage.
    const result = {
      paymentHash: entry.progress?.payment_hash ?? prepared.payment_hash ?? null,
      status: entry.status,
      activityId: entry.id,
      actualAmountSat: sent.actual_amount_sat,
      expectedFeeSat: prepared.expected_fee_sat,
      feeKnown: prepared.fee_known,
      warning: prepared.warning,
      preimage,
    };
    const cached = { ...result, preimage: null };
    this.#idempotency?.store("pay-invoice", idempotencyKey, cached);
    return result;
  }

  /** Merged wallet activity feed (design §2.2). */
  async activity(limit = 100, cursor?: string): Promise<Record<string, unknown>> {
    this.#requireWaved();
    const list = await this.#waved!.client.listActivity(limit, cursor);
    for (const entry of list.entries) {
      if (entry.progress?.preimage) registerSecret(entry.progress.preimage);
    }
    return {
      entries: list.entries,
      total: list.total,
      hasMore: list.has_more,
      nextCursor: list.next_cursor,
    };
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
   * Wrong passphrase is refused; a lost passphrase is unrecoverable without a
   * recovery artifact (SEC-2026-052 consequence).
   */
  async vaultUnlock(passphrase: string): Promise<Record<string, unknown>> {
    if (!this.#vault) {
      throw envelopeError("INTERNAL", "the vault is not initialized");
    }
    if (!(await this.#vault.existsOnDisk())) {
      throw envelopeError("INVALID_ARGS", "no vault exists; run the identity ceremony first");
    }
    registerSecret(passphrase);
    try {
      await this.#vault.unlock(passphrase);
    } catch (error) {
      if (error instanceof Error && "vaultError" in error && error.vaultError === "DecryptionFailed") {
        throw envelopeError("INVALID_ARGS", "wrong vault passphrase", {
          remediation: "a lost passphrase is unrecoverable without a recovery artifact",
        });
      }
      throw error;
    }
    this.#vaultState = "unlocked";
    const identity = await listPrimaryIdentity(this.#vault).catch(() => null);
    return {
      vaultState: "unlocked",
      derivedNpub: identity?.npub ?? null,
      derivedPubkeyHex: identity?.pubkeyHex ?? null,
    };
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
   * Engine-owned syncing→ready advance (design §1.4 / wallet-lifecycle docs:
   * "automatically advances syncing to ready" by polling until ready).
   * Lazy refresh on demand plus a 2s background watcher while syncing.
   */
  async #refreshWalletState(): Promise<void> {
    if (!this.#waved) return;
    try {
      const status = await this.#waved.status();
      if (status.ready) {
        this.#walletState = "ready";
        this.#stopSyncWatcher();
      } else if (status.unlocked) {
        this.#walletState = "syncing";
      } else {
        this.#walletState = "locked";
      }
    } catch {
      // keep the current state; the health check owns waved-failure handling
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

  #requireWaved(): void {
    if (!this.#waved) {
      throw envelopeError(
        "INTERNAL",
        this.#wavedUnavailableReason || "waved is not running",
        { retryable: false, remediation: "install the pinned waved artifact (see waved-artifact.manifest.json)" },
      );
    }
  }

  async #requireWalletReady(): Promise<void> {
    this.#requireWaved();
    if (this.#operatorLocked || !this.#walletPassword) {
      throw envelopeError("WALLET_LOCKED", "the wallet is locked; run unlock", {
        remediation: "run unlock (operator-only)",
      });
    }
    if (!this.#walletCreated) {
      throw envelopeError("WALLET_NOT_CREATED", "no wallet exists yet; run create-wallet", {
        remediation: "run create-wallet (operator-only)",
      });
    }
    if (this.#walletState === "syncing") {
      // One real poll before refusing: the daemon may have reached ready.
      await this.#refreshWalletState();
      if (this.#walletState === "syncing") {
        throw envelopeError("WALLET_SYNCING", "the wallet is syncing; wait for ready", { retryable: true });
      }
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
        return this.vaultUnlock(requireString(params, "passphrase"));
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
  if (networkRaw === "mainnet") {
    throw envelopeError("MAINNET_REFUSED", "MAINNET_REFUSED: OMEGA_SOVEREIGN_WALLET_NETWORK=mainnet is refused (D4)");
  }
  if (networkRaw !== "signet" && networkRaw !== "regtest") {
    throw envelopeError(
      "INVALID_ARGS",
      "INVALID_ARGS: OMEGA_SOVEREIGN_WALLET_NETWORK must be signet or regtest; an unset network never defaults to mainnet (design §3.2)",
    );
  }
  const dataRoot = process.env.OMEGA_SOVEREIGN_WALLET_DATA_ROOT;
  if (!dataRoot) {
    throw envelopeError("INVALID_ARGS", "OMEGA_SOVEREIGN_WALLET_DATA_ROOT is required");
  }
  const loopbackToken = process.env.OMEGA_SOVEREIGN_WALLET_LOOPBACK_TOKEN;
  const wavedBin = process.env.OMEGA_SOVEREIGN_WALLET_WAVED_BIN;
  const generation = Number.parseInt(process.env.OMEGA_SOVEREIGN_WALLET_GENERATION ?? "1", 10) || 1;
  const wavedRestPortRaw = process.env.OMEGA_SOVEREIGN_WALLET_WAVED_REST_PORT;
  const wavedRestPort = wavedRestPortRaw ? Number.parseInt(wavedRestPortRaw, 10) : undefined;
  return {
    dataRoot,
    network: networkRaw as WavelengthNetwork,
    loopbackToken,
    wavedBin,
    generation,
    wavedRestPort,
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
    // Health checkpoint immediately after startup: a waved network mismatch at
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

async function readMarker(path: string): Promise<WalletMarker | null> {
  try {
    const raw = await fs.readFile(path, "utf8");
    return JSON.parse(raw) as WalletMarker;
  } catch {
    return null;
  }
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
