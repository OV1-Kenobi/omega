//! Sovereign wallet vault (WP-4 + WP-3a) — desktop file-store adaptation of
//! satnam's OPFS vault. The sole permitted storage location for secret key
//! material in the sidecar.
//!
//! ## Architecture (envelope identical to satnam; backend adapted to files)
//!
//! ```text
//! <data_root>/sovereign-wallet/vault/
//!   master.key          — AES-256-GCM(K_os, masterKey) — K_os from the OS keychain
//!   wrapping.kek        — AES-256-GCM(argon2id(passphrase, salt), K_os) — degraded path
//!   passphrase.salt     — 32-byte random salt (not secret)
//!   wrapping.meta       — JSON WrappingKeyMeta (not secret; method "os-keychain" | "passphrase")
//!   identities/
//!     {npub}.nsec       — XChaCha20-Poly1305(masterKey, nsecBytes)
//!   wallet/
//!     {walletId}.entry  — XChaCha20-Poly1305(masterKey, wallet secret entry)
//! ```
//!
//! ## Key derivation
//!
//! Primary wrap: K_os (32 random bytes, generated once per data root) lives in
//! the OS keychain (Windows Credential Manager / macOS Keychain Services via
//! the typed seam in `keychain.ts` / `os-keychain.ts`). `master.key` at rest
//! is AES-256-GCM `[nonce(12) | ciphertext+tag]` under K_os. Degraded/portable
//! wrap: argon2id(passphrase, salt, { m: 65536, t: 3, p: 4 }) protects K_os via
//! `wrapping.kek` — the passphrase NEVER wraps the master key directly. Every
//! entry is XChaCha20-Poly1305 with a fresh random 24-byte nonce prepended.
//!
//! ## OS-keychain master-key wrapping (RV6-REQ-1..12; OMEGA-DELTA-0301)
//!
//! Node 24.19.0 has NO built-in OS-keychain/DPAPI API (`node:safeStorage` is
//! Electron-only and is not present in a plain Node process — verified
//! `ERR_UNKNOWN_BUILTIN_MODULE`). WP-3a therefore adds a native binding
//! package (`@napi-rs/keyring` 2.0.0, exact pin + committed lockfile;
//! install-gate evidence in
//! planning/2026-08-31-omega-mainnet-transition/evidence/05-wp3a-evidence.md)
//! behind the typed seam: Windows Credential Manager generic credentials
//! (CRED_TYPE_GENERIC, DPAPI under the user account) and macOS Keychain
//! Services (kSecClassGenericPassword).
//!
//! The master-key wrap is now layered (RV6-REQ-2/3): the OS keychain holds
//! ONLY a per-data-root 32-byte random K_os; `master.key` stays
//! AES-256-GCM(K_os, masterKey); `wrapping.kek` is
//! AES-256-GCM(argon2id(passphrase, salt), K_os) so the passphrase protects
//! K_os as the degraded/portable path. No seed material (aezeed), no nsecs,
//! no L-402 key, and no NWC secret ever enters the OS keychain — they remain
//! XChaCha20-Poly1305 under the master key inside the vault.
//!
//! Unlock order (RV6-REQ-3/5): (1) primary — read K_os from the OS keychain,
//! decrypt `master.key`; (2) degraded — ONLY when the keychain path fails AND
//! the explicit fallback opt-in is present (`OMEGA_VAULT_ALLOW_PASSPHRASE_
//! FALLBACK=1`, see `VAULT_FALLBACK_OPT_IN_ENV`), derive argon2id(passphrase,
//! salt), unwrap K_os from `wrapping.kek`, decrypt `master.key`. Keychain
//! unavailable is FAIL CLOSED (`VaultError.KeychainUnavailable`) — never a
//! silent fallback. On a mainnet-configured wallet, degraded unlock also
//! requires an explicit operator confirmation (`OperatorConfirmationRequired`
//! otherwise), and every unlock reports `wrapMethod` so the caller surfaces
//! the degradation honestly. K_os lives in memory ONLY during unlock/re-key
//! and is zeroized immediately after master-key decryption (RV6-REQ-6) —
//! unlike the L-402 HMAC key (SEC-2026-054), K_os has no locked-state use, so
//! retention is neither needed nor permitted. `lock()` and idle-lock behavior
//! are unchanged. The backup envelope moves to v3 (RV6-REQ-7); argon2id-only
//! vaults migrate in place at the first successful unlock, leaving the old
//! path intact on failure (RV6-REQ-8); re-key and keychain-revocation paths
//! exist (RV6-REQ-9).
//!
//! The argon2id path is RETAINED as the degraded/portable fallback — this is
//! additive hardening, not a removal. (Supersedes the signet-phase
//! argon2id-only posture that SEC-2026-052 recorded as the accepted minimum;
//! this change registers OMEGA-DELTA-0301 per SEC-2026-099 and the founder's
//! RV-1b ruling.)

import { gcm } from "@noble/ciphers/aes.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from "@noble/hashes/utils.js";
import path from "node:path";

import { FileBackend, type StorageBackend } from "./store.js";
import { keychainCredentialId, type KeychainBackend } from "./keychain.js";

// noble-hashes 2.3.0 does not export `bytesToUtf8` (satnam relied on an older
// version); decode UTF-8 with the Node built-in decoder instead.
const decoder = new TextDecoder();
function bytesToUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** AES-256-GCM nonce length (bytes). */
const AES_GCM_NONCE_LEN = 12;
/** XChaCha20-Poly1305 nonce length (bytes). */
const XCHACHA_NONCE_LEN = 24;
/** argon2id parameters per satnam SPECIFICATION §2.2 (retained for the degraded path). */
const ARGON2_PARAMS = { m: 65536, t: 3, p: 4 } as const;
/** Master key size (bytes). */
const MASTER_KEY_LEN = 32;
/** Minimum passphrase length enforced client-side (satnam spec §2.2 floor; SEC-2026-052). */
export const MIN_PASSPHRASE_LEN = 12;

/** Idle-lock bounds (ms): clamped to [5 min, 60 min], default 15 min. */
const IDLE_MIN_MS = 300_000;
const IDLE_MAX_MS = 3_600_000;
const IDLE_DEFAULT_MS = 900_000;

/**
 * The degraded-path opt-in env name (RV6-REQ-5): passphrase fallback unlocks
 * are permitted ONLY when `OMEGA_VAULT_ALLOW_PASSPHRASE_FALLBACK=1` is set.
 * Recorded in WP-3a evidence; pinned by the OMEGA-DELTA-0301 programmatic
 * check.
 */
export const VAULT_FALLBACK_OPT_IN_ENV = "OMEGA_VAULT_ALLOW_PASSPHRASE_FALLBACK";

/** Vault file names (RV6-REQ-3). */
const MASTER_KEY_FILE = "master.key";
const KEK_FILE = "wrapping.kek";
const META_FILE = "wrapping.meta";
const SALT_FILE = "passphrase.salt";

// ---------------------------------------------------------------------------
// Typed Vault Errors
// ---------------------------------------------------------------------------

export enum VaultError {
  VaultLocked = "VaultLocked",
  IdentityNotFound = "IdentityNotFound",
  DecryptionFailed = "DecryptionFailed",
  /** RV6-REQ-5: the OS keychain is unavailable (service down, entry missing, binding error, headless session). */
  KeychainUnavailable = "KeychainUnavailable",
  /** RV6-REQ-5: degraded unlock on a mainnet-configured wallet without operator confirmation. */
  OperatorConfirmationRequired = "OperatorConfirmationRequired",
}

function vaultErr(variant: VaultError): Error {
  return Object.assign(new Error(variant), { vaultError: variant });
}

export interface VaultConfig {
  /** Idle timeout before auto-lock (zeroes the master key). Clamped. */
  idleTimeoutMs: number;
  /** Vault directory root. */
  vaultRoot: string;
  /**
   * Security-relevant event hook (RV6-REQ-5): fired on every passphrase-path
   * unlock (degraded or migration). The event carries NO secrets; the caller
   * (WP-7 operator surface) logs and surfaces it.
   */
  onSecurityEvent?: (event: VaultSecurityEvent) => void;
}

export const DEFAULT_VAULT_CONFIG: VaultConfig = {
  idleTimeoutMs: IDLE_DEFAULT_MS,
  vaultRoot: "sovereign-wallet/vault",
};

/** RV6-REQ-5: the unlock wrap method, reported so the caller surfaces degradation honestly. */
export type WrapMethod = "os-keychain" | "passphrase-fallback";

/** RV6-REQ-5: options for `unlock`. */
export interface UnlockOptions {
  /** Explicit opt-in for the degraded passphrase path (env `OMEGA_VAULT_ALLOW_PASSPHRASE_FALLBACK=1`). */
  allowPassphraseFallback?: boolean;
  /** True when the wallet is mainnet-configured (0286 grammar active) — degraded unlock then needs operator confirmation. */
  mainnetConfigured?: boolean;
  /** Operator confirmation on the operator stdio channel (RV6-REQ-5); the loopback bearer token alone is not sufficient. */
  operatorConfirmed?: boolean;
}

/** RV6-REQ-5: the unlock result. */
export interface UnlockResult {
  wrapMethod: WrapMethod;
  /** True when this unlock migrated an argon2id-only vault in place (RV6-REQ-8). */
  migrated?: boolean;
}

/** RV6-REQ-5: a redacted security-relevant event (no secrets in any field). */
export interface VaultSecurityEvent {
  type: "passphrase-fallback-unlock";
  at: string;
  wrapMethod: "passphrase-fallback";
  mainnetConfigured: boolean;
}

export interface WrappingKeyMeta {
  /**
   * Wrap method: `"os-keychain"` (primary; K_os in the OS keychain,
   * `wrapping.kek` as the degraded blob) or `"passphrase"` (the pre-0301
   * argon2id-only scheme, migrated at the first successful unlock).
   */
  method: "passphrase" | "os-keychain";
  /** RV6-REQ-4: the OS-keychain credential id (recorded for audit and the revoke path). */
  credentialId: string;
  argon2Params?: { m: number; t: number; p: number; keyLen: number };
  createdAt: string;
  /** RV6-REQ-8: set when an argon2id-only vault migrated in place. */
  migratedAt?: string;
  /** RV6-REQ-9: set on re-key. */
  rotatedAt?: string;
}

/** A Wavelength wallet secret entry (wallet DB password + aezeed backup phrase). */
export interface WalletSecretEntry {
  walletId: string;
  walletDbPassword: string;
  /** 24-word Wavelength aezeed backup phrase, captured once at create (Q1). */
  aezeed: string;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/** Encrypt bytes under XChaCha20-Poly1305: `[nonce(24) | ciphertext+tag]`. */
function encryptEntry(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = randomBytes(XCHACHA_NONCE_LEN);
  const ciphertext = xchacha20poly1305(key, nonce).encrypt(plaintext);
  const result = new Uint8Array(XCHACHA_NONCE_LEN + ciphertext.length);
  result.set(nonce, 0);
  result.set(ciphertext, XCHACHA_NONCE_LEN);
  return result;
}

function decryptEntry(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (data.length < XCHACHA_NONCE_LEN) throw vaultErr(VaultError.DecryptionFailed);
  const nonce = data.slice(0, XCHACHA_NONCE_LEN);
  const ciphertext = data.slice(XCHACHA_NONCE_LEN);
  try {
    return xchacha20poly1305(key, nonce).decrypt(ciphertext);
  } catch {
    throw vaultErr(VaultError.DecryptionFailed);
  }
}

/** Encrypt a 32-byte key under a wrapping key (AES-256-GCM) — reused for master.key and wrapping.kek. */
function encryptMasterKey(wrappingKey: Uint8Array, masterKey: Uint8Array): Uint8Array {
  const nonce = randomBytes(AES_GCM_NONCE_LEN);
  const ciphertext = gcm(wrappingKey, nonce).encrypt(masterKey);
  const result = new Uint8Array(AES_GCM_NONCE_LEN + ciphertext.length);
  result.set(nonce, 0);
  result.set(ciphertext, AES_GCM_NONCE_LEN);
  return result;
}

function decryptMasterKey(wrappingKey: Uint8Array, data: Uint8Array): Uint8Array {
  if (data.length < AES_GCM_NONCE_LEN) throw vaultErr(VaultError.DecryptionFailed);
  const nonce = data.slice(0, AES_GCM_NONCE_LEN);
  const ciphertext = data.slice(AES_GCM_NONCE_LEN);
  try {
    return gcm(wrappingKey, nonce).decrypt(ciphertext);
  } catch {
    throw vaultErr(VaultError.DecryptionFailed);
  }
}

function derivePassphraseWrappingKey(passphrase: string, salt: Uint8Array): Uint8Array {
  return argon2id(utf8ToBytes(passphrase), salt, { ...ARGON2_PARAMS, dkLen: MASTER_KEY_LEN });
}

/** Zero a Uint8Array in-place (satnam zeroBytes discipline). */
function zeroBytes(buf: Uint8Array): void {
  buf.fill(0);
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

export class Vault {
  readonly #config: VaultConfig;
  #storage: StorageBackend;
  #rootDir: string;
  #keychain: KeychainBackend | null;
  /** Master key held in memory while unlocked; zeroed on lock(). */
  #masterKey: Uint8Array | null = null;
  #idleTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(config?: Partial<VaultConfig>, root?: string, keychain?: KeychainBackend | null) {
    this.#config = {
      ...DEFAULT_VAULT_CONFIG,
      ...config,
      idleTimeoutMs: Math.min(IDLE_MAX_MS, Math.max(IDLE_MIN_MS, config?.idleTimeoutMs ?? IDLE_DEFAULT_MS)),
    };
    // The resolved data root (the constructor's absolute root when given):
    // this is the identity anchor for the OS-keychain credential (RV6-REQ-4).
    this.#rootDir = path.resolve(root ?? this.#config.vaultRoot);
    this.#storage = new FileBackend(this.#rootDir);
    // `null` → the production OS-keychain backend, created lazily on first use
    // (never at construction, so importing the vault does not touch the
    // native binding). Tests inject InMemoryKeychainBackend here.
    this.#keychain = keychain ?? null;
  }

  private path(dir: string, filename: string): string {
    return `${this.#config.vaultRoot}/${dir}/${filename}`;
  }

  /** RV6-REQ-4: the OS-keychain credential id, derived from the data root. */
  private credentialId(): string {
    return keychainCredentialId(this.#rootDir);
  }

  /** The production OS-keychain backend, created lazily (dynamic import — vault.ts never imports the provider). */
  private async getKeychain(): Promise<KeychainBackend> {
    if (!this.#keychain) {
      const { createOsKeychainBackend } = await import("./os-keychain.js");
      this.#keychain = createOsKeychainBackend();
    }
    return this.#keychain;
  }

  private requireUnlocked(): Uint8Array {
    if (!this.#masterKey) throw vaultErr(VaultError.VaultLocked);
    return this.#masterKey;
  }

  private resetIdleTimer(): void {
    if (this.#idleTimer !== null) clearTimeout(this.#idleTimer);
    this.#idleTimer = setTimeout(() => {
      this.lock();
    }, this.#config.idleTimeoutMs);
    if (typeof this.#idleTimer.unref === "function") this.#idleTimer.unref();
  }

  private async writeEncrypted(key: Uint8Array, p: string, plaintext: Uint8Array): Promise<void> {
    await this.#storage.write(p, encryptEntry(key, plaintext));
  }

  private async readDecrypted(key: Uint8Array, p: string): Promise<Uint8Array> {
    const data = await this.#storage.read(p);
    if (!data) throw vaultErr(VaultError.IdentityNotFound);
    return decryptEntry(key, data);
  }

  private async deriveWrappingKey(
    credential: string,
  ): Promise<{ wrappingKey: Uint8Array; salt: Uint8Array }> {
    if (credential.length < MIN_PASSPHRASE_LEN) {
      throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`);
    }
    const saltPath = `${this.#config.vaultRoot}/${SALT_FILE}`;
    let salt = await this.#storage.read(saltPath);
    if (!salt) {
      salt = randomBytes(32);
      await this.#storage.write(saltPath, salt);
    }
    const wrappingKey = derivePassphraseWrappingKey(credential, salt);
    return { wrappingKey, salt };
  }

  private async readMeta(): Promise<WrappingKeyMeta | null> {
    const raw = await this.#storage.read(`${this.#config.vaultRoot}/${META_FILE}`);
    if (!raw) return null;
    try {
      return JSON.parse(bytesToUtf8(raw)) as WrappingKeyMeta;
    } catch {
      return null;
    }
  }

  private async writeMeta(meta: WrappingKeyMeta): Promise<void> {
    await this.#storage.write(`${this.#config.vaultRoot}/${META_FILE}`, utf8ToBytes(JSON.stringify(meta)));
  }

  private setUnlocked(masterKey: Uint8Array): void {
    if (this.#masterKey) zeroBytes(this.#masterKey);
    this.#masterKey = masterKey;
    this.resetIdleTimer();
  }

  private emitSecurityEvent(mainnetConfigured: boolean): void {
    const event: VaultSecurityEvent = {
      type: "passphrase-fallback-unlock",
      at: new Date().toISOString(),
      wrapMethod: "passphrase-fallback",
      mainnetConfigured,
    };
    this.#config.onSecurityEvent?.(event);
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /**
   * Initialize a fresh vault (RV6-REQ-3): generate masterKey + K_os; write
   * `master.key` (K_os-wrapped), `wrapping.kek` (argon2id-wrapped K_os), and
   * `wrapping.meta` (method `"os-keychain"`, credentialId, argon2Params,
   * createdAt). The OS-keychain store is the anchor: a keychain failure at
   * initialize is FAIL CLOSED (`KeychainUnavailable`) — no vault is created
   * without the OS-keychain layer.
   */
  async initialize(credential: string): Promise<void> {
    for (const dir of ["identities", "wallet", "agents", "nip46", "l402"]) {
      const sentinel = `${this.#config.vaultRoot}/${dir}/.keep`;
      if (!(await this.#storage.exists(sentinel))) {
        await this.#storage.write(sentinel, new Uint8Array(0));
      }
    }

    if (credential.length < MIN_PASSPHRASE_LEN) {
      throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`);
    }
    const { wrappingKey } = await this.deriveWrappingKey(credential);
    try {
      const masterKey = randomBytes(MASTER_KEY_LEN);
      const kos = randomBytes(MASTER_KEY_LEN);
      const credentialId = this.credentialId();
      const kekBlob = encryptMasterKey(wrappingKey, kos);
      const encryptedMasterKey = encryptMasterKey(kos, masterKey);
      try {
        await (await this.getKeychain()).set(credentialId, kos);
      } catch {
        throw vaultErr(VaultError.KeychainUnavailable);
      }
      zeroBytes(kos);
      await this.#storage.write(`${this.#config.vaultRoot}/${MASTER_KEY_FILE}`, encryptedMasterKey);
      await this.#storage.write(`${this.#config.vaultRoot}/${KEK_FILE}`, kekBlob);

      const meta: WrappingKeyMeta = {
        method: "os-keychain",
        credentialId,
        argon2Params: { m: ARGON2_PARAMS.m, t: ARGON2_PARAMS.t, p: ARGON2_PARAMS.p, keyLen: MASTER_KEY_LEN },
        createdAt: new Date().toISOString(),
      };
      await this.writeMeta(meta);

      this.setUnlocked(masterKey);
    } finally {
      zeroBytes(wrappingKey);
    }
  }

  /**
   * Unlock an existing vault (RV6-REQ-3/5/8). Primary: K_os from the OS
   * keychain → `master.key`. Degraded (only when the keychain path fails AND
   * the explicit fallback opt-in is present): argon2id(passphrase, salt) →
   * unwrap K_os from `wrapping.kek` → `master.key`; on a mainnet-configured
   * wallet this additionally requires `operatorConfirmed`. A vault still on
   * the pre-0301 argon2id-only scheme (meta `"passphrase"`) unlocks via the
   * passphrase and migrates in place, leaving the old path intact on failure.
   * Every result reports `wrapMethod` (RV6-REQ-5).
   */
  async unlock(credential?: string, opts?: UnlockOptions): Promise<UnlockResult> {
    const encryptedMasterKey = await this.#storage.read(`${this.#config.vaultRoot}/${MASTER_KEY_FILE}`);
    if (!encryptedMasterKey) throw vaultErr(VaultError.DecryptionFailed);
    const meta = await this.readMeta();
    if (!meta) throw vaultErr(VaultError.DecryptionFailed);

    if (meta.method === "passphrase") {
      // Pre-0301 argon2id-only vault: the passphrase is the vault's PRIMARY
      // method (it has no keychain entry yet), so no fallback opt-in is
      // required to use it. Wrong passphrase → DecryptionFailed.
      if (!credential || credential.length < MIN_PASSPHRASE_LEN) {
        throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`);
      }
      const { wrappingKey } = await this.deriveWrappingKey(credential);
      try {
        let masterKey: Uint8Array | null = null;
        let migrated = false;
        try {
          masterKey = decryptMasterKey(wrappingKey, encryptedMasterKey);
        } catch {
          // Recovery for a migration that crashed between the master.key
          // rewrite and the meta flip (RV6-REQ-8 "no lockout"): the
          // K_os-wrapped master.key is readable through wrapping.kek.
          const kekBlob = await this.#storage.read(`${this.#config.vaultRoot}/${KEK_FILE}`);
          if (!kekBlob) throw vaultErr(VaultError.DecryptionFailed);
          const kos = decryptMasterKey(wrappingKey, kekBlob);
          try {
            masterKey = decryptMasterKey(kos, encryptedMasterKey);
            migrated = true;
            // Best-effort: a failed meta flip must not lock the vault — the
            // next unlock retries the recovery path.
            await this.finishMigration(meta).catch(() => {});
          } finally {
            zeroBytes(kos);
          }
        }
        if (masterKey === null) throw vaultErr(VaultError.DecryptionFailed);
        if (!migrated) {
          migrated = await this.migrate(meta, wrappingKey, masterKey, encryptedMasterKey);
        }
        this.setUnlocked(masterKey);
        this.emitSecurityEvent(opts?.mainnetConfigured ?? false);
        return { wrapMethod: "passphrase-fallback", migrated };
      } finally {
        zeroBytes(wrappingKey);
      }
    }

    if (meta.method !== "os-keychain") {
      // Unknown/unsupported wrap method → fail closed (RV6-REQ-10 negative 6).
      throw vaultErr(VaultError.DecryptionFailed);
    }

    // Primary path: the OS keychain.
    let kos: Uint8Array | null = null;
    let keychainUnavailable = false;
    try {
      kos = await (await this.getKeychain()).get(meta.credentialId);
      if (kos === null) keychainUnavailable = true;
    } catch {
      keychainUnavailable = true;
    }

    if (!keychainUnavailable) {
      try {
        const masterKey = decryptMasterKey(kos!, encryptedMasterKey);
        // RV6-REQ-6: K_os is zeroized immediately after master-key
        // decryption; it is NOT retained while unlocked.
        zeroBytes(kos!);
        kos = null;
        this.setUnlocked(masterKey);
        return { wrapMethod: "os-keychain" };
      } catch (error) {
        if (kos) zeroBytes(kos);
        // Wrong keychain entry / corrupted master.key: DecryptionFailed with
        // NO argon2id attempt (RV6-REQ-10 negatives 4/5).
        throw error;
      }
    }

    // Degraded path — ONLY with the explicit opt-in, a wrapping.kek, and (on
    // a mainnet-configured wallet) the operator confirmation (RV6-REQ-5).
    if (!opts?.allowPassphraseFallback) throw vaultErr(VaultError.KeychainUnavailable);
    const kekBlob = await this.#storage.read(`${this.#config.vaultRoot}/${KEK_FILE}`);
    if (!kekBlob) throw vaultErr(VaultError.KeychainUnavailable);
    if (opts?.mainnetConfigured && !opts?.operatorConfirmed) {
      throw vaultErr(VaultError.OperatorConfirmationRequired);
    }
    if (!credential || credential.length < MIN_PASSPHRASE_LEN) {
      throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`);
    }
    const { wrappingKey } = await this.deriveWrappingKey(credential);
    try {
      kos = decryptMasterKey(wrappingKey, kekBlob); // wrong passphrase → DecryptionFailed
      const masterKey = decryptMasterKey(kos, encryptedMasterKey);
      zeroBytes(kos);
      kos = null;
      this.setUnlocked(masterKey);
      this.emitSecurityEvent(opts?.mainnetConfigured ?? false);
      return { wrapMethod: "passphrase-fallback" };
    } finally {
      zeroBytes(wrappingKey);
      if (kos) zeroBytes(kos);
    }
  }

  /**
   * RV6-REQ-8: migrate an argon2id-only vault in place at the first
   * successful unlock. New files are written and the meta is flipped LAST;
   * on any failure the old path stays intact (master.key is restored if it
   * was already rewritten) and the unlock still succeeds via the old path.
   * Idempotent: only reachable while meta says "passphrase".
   */
  private async migrate(
    oldMeta: WrappingKeyMeta,
    argon2Key: Uint8Array,
    masterKey: Uint8Array,
    oldMasterKeyBlob: Uint8Array,
  ): Promise<boolean> {
    const kos = randomBytes(MASTER_KEY_LEN);
    const credentialId = this.credentialId();
    try {
      try {
        await (await this.getKeychain()).set(credentialId, kos);
      } catch {
        return false; // old path untouched (master.key not yet rewritten)
      }
      const kekBlob = encryptMasterKey(argon2Key, kos);
      await this.#storage.write(`${this.#config.vaultRoot}/${KEK_FILE}`, kekBlob);
      const newBlob = encryptMasterKey(kos, masterKey);
      await this.#storage.write(`${this.#config.vaultRoot}/${MASTER_KEY_FILE}`, newBlob);
      const newMeta: WrappingKeyMeta = {
        method: "os-keychain",
        credentialId,
        argon2Params: oldMeta.argon2Params,
        createdAt: oldMeta.createdAt,
        migratedAt: new Date().toISOString(),
      };
      try {
        await this.writeMeta(newMeta);
      } catch {
        // Restore the old argon2id-wrapped master.key so the old path still
        // unlocks (meta was not flipped).
        await this.#storage.write(`${this.#config.vaultRoot}/${MASTER_KEY_FILE}`, oldMasterKeyBlob);
        return false;
      }
      return true;
    } finally {
      zeroBytes(kos);
    }
  }

  /** Complete a migration whose master.key was already rewritten (crash-window recovery). */
  private async finishMigration(oldMeta: WrappingKeyMeta): Promise<void> {
    const newMeta: WrappingKeyMeta = {
      method: "os-keychain",
      credentialId: this.credentialId(),
      argon2Params: oldMeta.argon2Params,
      createdAt: oldMeta.createdAt,
      migratedAt: new Date().toISOString(),
    };
    await this.writeMeta(newMeta);
  }

  /** Lock the vault: zero the master key and clear the idle timer. Unchanged (RV6-REQ-6). */
  lock(): void {
    if (this.#masterKey) {
      zeroBytes(this.#masterKey);
      this.#masterKey = null;
    }
    if (this.#idleTimer !== null) {
      clearTimeout(this.#idleTimer);
      this.#idleTimer = null;
    }
  }

  isUnlocked(): boolean {
    return this.#masterKey !== null;
  }

  /** True when a vault has been initialized on disk (master.key present). */
  async existsOnDisk(): Promise<boolean> {
    return this.#storage.exists(`${this.#config.vaultRoot}/${MASTER_KEY_FILE}`);
  }

  /**
   * RV6-REQ-9: re-key the vault (operator-triggered). Requires an unlocked
   * vault and the passphrase (which is validated against `wrapping.kek`).
   * Generates K_os', updates the keychain entry (the stable credential id is
   * overwritten — the old credential value is removed by the update),
   * rewrites `master.key` + `wrapping.kek`, and stamps `rotatedAt` in the
   * meta. Order is keychain-first so every crash point leaves at least one
   * working unlock path (see WP-3a evidence).
   */
  async rekey(credential: string): Promise<void> {
    const masterKey = this.requireUnlocked();
    const meta = await this.readMeta();
    if (!meta || meta.method !== "os-keychain") {
      // An argon2id-only vault re-keys through its migration at unlock.
      throw vaultErr(VaultError.DecryptionFailed);
    }
    if (credential.length < MIN_PASSPHRASE_LEN) {
      throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`);
    }
    const { wrappingKey } = await this.deriveWrappingKey(credential);
    try {
      const kekBlob = await this.#storage.read(`${this.#config.vaultRoot}/${KEK_FILE}`);
      if (!kekBlob) throw vaultErr(VaultError.KeychainUnavailable);
      // Validates the passphrase against the current wrapping.kek; a wrong
      // passphrase → DecryptionFailed before anything rotates.
      const currentKos = decryptMasterKey(wrappingKey, kekBlob);
      zeroBytes(currentKos);

      const kosNew = randomBytes(MASTER_KEY_LEN);
      const credentialId = this.credentialId();
      try {
        await (await this.getKeychain()).set(credentialId, kosNew);
      } catch {
        zeroBytes(kosNew);
        throw vaultErr(VaultError.KeychainUnavailable);
      }
      await this.#storage.write(`${this.#config.vaultRoot}/${MASTER_KEY_FILE}`, encryptMasterKey(kosNew, masterKey));
      await this.#storage.write(`${this.#config.vaultRoot}/${KEK_FILE}`, encryptMasterKey(wrappingKey, kosNew));
      await this.writeMeta({ ...meta, rotatedAt: new Date().toISOString() });
      zeroBytes(kosNew);
    } finally {
      zeroBytes(wrappingKey);
    }
  }

  /**
   * RV6-REQ-9: remove the OS-keychain credential (the revoke path). The
   * keychain copy is OS-managed at rest and cannot be zeroed by the app;
   * removal is via this path. Deleting the entry without re-keying locks the
   * vault (fail-closed); the degraded path with opt-in + passphrase still
   * works.
   */
  async revokeKeychainEntry(): Promise<void> {
    this.requireUnlocked();
    await (await this.getKeychain()).delete(this.credentialId());
  }

  // -------------------------------------------------------------------------
  // Identity
  // -------------------------------------------------------------------------

  async storeNsec(npub: string, nsec: Uint8Array): Promise<void> {
    const key = this.requireUnlocked();
    this.resetIdleTimer();
    await this.writeEncrypted(key, this.path("identities", `${npub}.nsec`), nsec);
  }

  async getNsec(npub: string): Promise<Uint8Array> {
    const key = this.requireUnlocked();
    this.resetIdleTimer();
    return this.readDecrypted(key, this.path("identities", `${npub}.nsec`));
  }

  async deleteNsec(npub: string): Promise<void> {
    this.requireUnlocked();
    this.resetIdleTimer();
    await this.#storage.delete(this.path("identities", `${npub}.nsec`));
  }

  async listIdentities(): Promise<string[]> {
    this.requireUnlocked();
    this.resetIdleTimer();
    const files = await this.#storage.list(`${this.#config.vaultRoot}/identities`);
    return files
      .filter((f) => f.endsWith(".nsec"))
      .map((f) => f.slice(0, -".nsec".length));
  }

  // -------------------------------------------------------------------------
  // Wallet (Wavelength aezeed + wallet DB password — Q1: vaulted, not derived)
  // -------------------------------------------------------------------------

  async storeWalletEntry(entry: WalletSecretEntry): Promise<void> {
    const key = this.requireUnlocked();
    this.resetIdleTimer();
    await this.writeEncrypted(key, this.path("wallet", `${entry.walletId}.entry`), utf8ToBytes(JSON.stringify(entry)));
  }

  async getWalletEntry(walletId: string): Promise<WalletSecretEntry> {
    const key = this.requireUnlocked();
    this.resetIdleTimer();
    const plaintext = await this.readDecrypted(key, this.path("wallet", `${walletId}.entry`));
    return JSON.parse(bytesToUtf8(plaintext)) as WalletSecretEntry;
  }

  async listWalletIds(): Promise<string[]> {
    this.requireUnlocked();
    this.resetIdleTimer();
    const files = await this.#storage.list(`${this.#config.vaultRoot}/wallet`);
    return files
      .filter((f) => f.endsWith(".entry"))
      .map((f) => f.slice(0, -".entry".length));
  }

  // -------------------------------------------------------------------------
  // L-402 gateway HMAC key (WP-6; SEC-2026-044 custody)
  // -------------------------------------------------------------------------
  //
  // The L-402 credential-signing key is generated once per data root and
  // stored as an ordinary vault entry (`vault/l402/l402-hmac.key`,
  // XChaCha20-Poly1305 under the vault master key) — never in the gateway
  // SQLite, never in logs/frames. The gateway loads it into memory when the
  // vault is first unlocked and retains it for the process lifetime so
  // redemption of already-paid challenges stays honored while the wallet is
  // locked (SEC-2026-054). These methods are the ONLY persistence surface for
  // the key; the backup envelope includes the `l402` directory so one
  // operator-held recovery chain restores the whole sovereign surface.

  async storeL402Key(keyBytes: Uint8Array): Promise<void> {
    const key = this.requireUnlocked();
    this.resetIdleTimer();
    await this.writeEncrypted(key, this.path("l402", "l402-hmac.key"), keyBytes);
  }

  async getL402Key(): Promise<Uint8Array> {
    const key = this.requireUnlocked();
    this.resetIdleTimer();
    return this.readDecrypted(key, this.path("l402", "l402-hmac.key"));
  }

  // -------------------------------------------------------------------------
  // Generic encryption helpers
  // -------------------------------------------------------------------------

  async encryptBytes(plaintext: Uint8Array): Promise<Uint8Array> {
    const key = this.requireUnlocked();
    this.resetIdleTimer();
    return encryptEntry(key, plaintext);
  }

  async decryptBytes(data: Uint8Array): Promise<Uint8Array> {
    const key = this.requireUnlocked();
    this.resetIdleTimer();
    return decryptEntry(key, data);
  }

  // -------------------------------------------------------------------------
  // Backup (v3 encrypted envelope; OMEGA-DELTA-0301 / RV6-REQ-7)
  // -------------------------------------------------------------------------

  /**
   * Export a v3 encrypted backup. Envelope:
   * `[4-byte LE saltLen][salt][4-byte LE kekLen][wrapping.kek][4-byte LE mkLen][master.key][xchacha20poly1305(masterKey, JSON(entries))]`
   *
   * The passphrase-recoverable element is now the argon2id-wrapped K_os blob
   * (`wrapping.kek`) — replacing the v2 K_os-wrapped master-key blob — plus
   * the K_os-wrapped `master.key` blob and the payload under the master key.
   * Fresh-device restore: argon2id(passphrase, salt) → unwrap K_os → decrypt
   * `master.key` → decrypt payload → re-enroll K_os into the new device's OS
   * keychain (RV6-REQ-7/9).
   */
  async exportEncryptedBackup(): Promise<Uint8Array> {
    const masterKey = this.requireUnlocked();
    this.resetIdleTimer();

    const salt = await this.#storage.read(`${this.#config.vaultRoot}/${SALT_FILE}`);
    if (!salt) throw vaultErr(VaultError.DecryptionFailed);
    const kekBlob = await this.#storage.read(`${this.#config.vaultRoot}/${KEK_FILE}`);
    if (!kekBlob) throw vaultErr(VaultError.DecryptionFailed);
    const encryptedMasterKeyBlob = await this.#storage.read(`${this.#config.vaultRoot}/${MASTER_KEY_FILE}`);
    if (!encryptedMasterKeyBlob) throw vaultErr(VaultError.DecryptionFailed);

    const entries: Record<string, string> = {};
    for (const dir of ["identities", "wallet", "agents", "nip46", "l402"]) {
      const files = await this.#storage.list(`${this.#config.vaultRoot}/${dir}`);
      for (const file of files) {
        if (file === ".keep") continue;
        const fullPath = this.path(dir, file);
        const data = await this.#storage.read(fullPath);
        if (data) {
          // Re-encrypt under the master key so the backup always uses a fresh nonce.
          const plain = decryptEntry(masterKey, data);
          entries[`${dir}/${file}`] = bytesToHex(encryptEntry(masterKey, plain));
        }
      }
    }

    const backupPayload = {
      version: 3,
      createdAt: new Date().toISOString(),
      entries,
    };

    const payloadCiphertext = encryptEntry(masterKey, utf8ToBytes(JSON.stringify(backupPayload)));

    const saltHeader = new Uint8Array(4);
    new DataView(saltHeader.buffer).setUint32(0, salt.length, true);
    const kekHeader = new Uint8Array(4);
    new DataView(kekHeader.buffer).setUint32(0, kekBlob.length, true);
    const mkHeader = new Uint8Array(4);
    new DataView(mkHeader.buffer).setUint32(0, encryptedMasterKeyBlob.length, true);

    const backup = new Uint8Array(
      saltHeader.length + salt.length + kekHeader.length + kekBlob.length + mkHeader.length + encryptedMasterKeyBlob.length + payloadCiphertext.length,
    );
    let offset = 0;
    backup.set(saltHeader, offset);
    offset += saltHeader.length;
    backup.set(salt, offset);
    offset += salt.length;
    backup.set(kekHeader, offset);
    offset += kekHeader.length;
    backup.set(kekBlob, offset);
    offset += kekBlob.length;
    backup.set(mkHeader, offset);
    offset += mkHeader.length;
    backup.set(encryptedMasterKeyBlob, offset);
    offset += encryptedMasterKeyBlob.length;
    backup.set(payloadCiphertext, offset);
    return backup;
  }

  /**
   * Detect a pre-0301 v2 backup envelope:
   * `[saltLen(4)][salt][mkLen(4)][argon2id-wrapped master.key][payload]`.
   * Returns true only when the passphrase decrypts the master-key blob AND
   * the payload carries `version: 2` — so a random blob can never be
   * misidentified. Pure detection: nothing is written, and all intermediates
   * are zeroized.
   */
  private async detectV2Backup(data: Uint8Array, credential: string): Promise<boolean> {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (data.length < 8) return false;
    const saltLen = view.getUint32(0, true);
    if (data.length < 4 + saltLen + 4) return false;
    const salt = saltLen > 0 ? data.slice(4, 4 + saltLen) : new Uint8Array(0);
    const mkHeaderOff = 4 + saltLen;
    const mkLen = view.getUint32(mkHeaderOff, true);
    if (data.length < mkHeaderOff + 4 + mkLen) return false;
    const mkOff = mkHeaderOff + 4;
    const mkBlob = data.slice(mkOff, mkOff + mkLen);
    try {
      const wrappingKey = derivePassphraseWrappingKey(credential, salt);
      try {
        const masterKey = decryptMasterKey(wrappingKey, mkBlob);
        try {
          const payload = decryptEntry(masterKey, data.slice(mkOff + mkLen));
          const parsed = JSON.parse(bytesToUtf8(payload)) as { version?: number };
          return parsed.version === 2;
        } finally {
          zeroBytes(masterKey);
        }
      } finally {
        zeroBytes(wrappingKey);
      }
    } catch {
      return false;
    }
  }

  /**
   * Import a v3 backup (fresh-device restore, RV6-REQ-7). With the
   * passphrase: argon2id(passphrase, salt) → unwrap K_os from the kek blob →
   * decrypt the restored `master.key` → decrypt the payload → write all vault
   * files → re-enroll K_os into this device's OS keychain (so subsequent
   * unlocks are keychain-first). Restore without a keychain still works via
   * the degraded path per RV6-REQ-5 (the files are complete either way).
   * v2 backups are superseded by OMEGA-DELTA-0301 and refused with an
   * explicit message naming the migration step.
   */
  async importEncryptedBackup(data: Uint8Array, credential?: string): Promise<{ keychainEnrolled: boolean }> {
    if (!credential || credential.length < MIN_PASSPHRASE_LEN) {
      throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`);
    }
    // A pre-0301 v2 envelope ([saltLen][salt][mkLen][argon2id-wrapped
    // master.key][payload]) does not parse as v3 — detect it so the operator
    // gets the remediation instead of a bare DecryptionFailed.
    if (await this.detectV2Backup(data, credential)) {
      throw new Error(
        "backup version 2 is superseded by OMEGA-DELTA-0301; open the vault once on the original device (it migrates in place) and export a fresh v3 backup",
      );
    }
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (data.length < 12) throw vaultErr(VaultError.DecryptionFailed);
    const saltLen = view.getUint32(0, true);
    if (data.length < 4 + saltLen + 4) throw vaultErr(VaultError.DecryptionFailed);
    const salt = saltLen > 0 ? data.slice(4, 4 + saltLen) : new Uint8Array(0);
    const kekHeaderOff = 4 + saltLen;
    const kekLen = view.getUint32(kekHeaderOff, true);
    if (data.length < kekHeaderOff + 4 + kekLen + 4) throw vaultErr(VaultError.DecryptionFailed);
    const kekOff = kekHeaderOff + 4;
    const kekBlob = data.slice(kekOff, kekOff + kekLen);
    const mkHeaderOff = kekOff + kekLen;
    const mkLen = view.getUint32(mkHeaderOff, true);
    if (data.length < mkHeaderOff + 4 + mkLen) throw vaultErr(VaultError.DecryptionFailed);
    const mkOff = mkHeaderOff + 4;
    const encryptedMasterKeyBlob = data.slice(mkOff, mkOff + mkLen);

    const wrappingKey = derivePassphraseWrappingKey(credential, salt);
    let kos: Uint8Array | null = null;
    try {
      kos = decryptMasterKey(wrappingKey, kekBlob);
      const masterKey = decryptMasterKey(kos, encryptedMasterKeyBlob);
      zeroBytes(wrappingKey);

      const payloadCiphertext = data.slice(mkOff + mkLen);
      let backupJson: string;
      try {
        backupJson = bytesToUtf8(decryptEntry(masterKey, payloadCiphertext));
      } catch {
        throw vaultErr(VaultError.DecryptionFailed);
      }
      const backup = JSON.parse(backupJson) as {
        version: number;
        entries: Record<string, string>;
      };
      if (backup.version === 2) {
        throw new Error(
          "backup version 2 is superseded by OMEGA-DELTA-0301; open the vault once on the original device (it migrates in place) and export a fresh v3 backup",
        );
      }
      if (backup.version !== 3) {
        throw new Error("Unsupported backup version");
      }

      if (salt.length > 0) {
        await this.#storage.write(`${this.#config.vaultRoot}/${SALT_FILE}`, salt);
      }
      await this.#storage.write(`${this.#config.vaultRoot}/${KEK_FILE}`, kekBlob);
      await this.#storage.write(`${this.#config.vaultRoot}/${MASTER_KEY_FILE}`, encryptedMasterKeyBlob);
      const meta: WrappingKeyMeta = {
        method: "os-keychain",
        credentialId: this.credentialId(),
        argon2Params: { m: ARGON2_PARAMS.m, t: ARGON2_PARAMS.t, p: ARGON2_PARAMS.p, keyLen: MASTER_KEY_LEN },
        createdAt: new Date().toISOString(),
      };
      await this.writeMeta(meta);
      for (const [relativePath, hexData] of Object.entries(backup.entries)) {
        await this.#storage.write(`${this.#config.vaultRoot}/${relativePath}`, hexToBytes(hexData));
      }

      // Fresh-device re-enrollment (RV6-REQ-7/9): store K_os into THIS
      // device's keychain so subsequent unlocks are keychain-first. Failure
      // does not fail the restore — the degraded path (opt-in + passphrase)
      // still works because all vault files are complete.
      let keychainEnrolled = false;
      try {
        await (await this.getKeychain()).set(this.credentialId(), kos);
        keychainEnrolled = true;
      } catch {
        keychainEnrolled = false;
      }
      return { keychainEnrolled };
    } finally {
      zeroBytes(wrappingKey);
      if (kos) zeroBytes(kos);
    }
  }
}