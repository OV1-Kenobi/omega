//! Sovereign wallet vault (WP-4) — desktop file-store adaptation of satnam's
//! OPFS vault. The sole permitted storage location for secret key material in
//! the sidecar.
//!
//! ## Architecture (envelope identical to satnam; backend adapted to files)
//!
//! ```text
//! <data_root>/sovereign-wallet/vault/
//!   master.key          — AES-256-GCM ciphertext of the 256-bit master key
//!   passphrase.salt     — 32-byte random salt (not secret)
//!   wrapping.meta       — JSON WrappingKeyMeta (not secret)
//!   identities/
//!     {npub}.nsec       — XChaCha20-Poly1305(masterKey, nsecBytes)
//!   wallet/
//!     {walletId}.entry  — XChaCha20-Poly1305(masterKey, wallet secret entry)
//! ```
//!
//! ## Key derivation
//!
//! Passphrase path: argon2id(passphrase, salt, { m: 65536, t: 3, p: 4 }) →
//! 32-byte wrapping key. Master key at rest is AES-256-GCM
//! `[nonce(12) | ciphertext+tag]`. Every entry is XChaCha20-Poly1305 with a
//! fresh random 24-byte nonce prepended.
//!
//! ## OS-keychain decision (SEC-2026-052 / RV-6)
//!
//! Node 24.19.0 has NO built-in OS-keychain/DPAPI API (`node:safeStorage` is
//! Electron-only and is not present in a plain Node process — verified
//! `ERR_UNKNOWN_BUILTIN_MODULE`). The only routes to an OS-keychain wrapping
//! layer are native npm packages (keytar-class or Node bindings to Windows
//! Credential Manager / DPAPI), which require a native dependency, a capability
//! manifest (SEC-2026-040/041 precedent), and push the S8 dependency budget.
//! Per WP-2 SEC-2026-052 the accepted minimum for this signet phase is
//! **argon2id-only** (m:65536,t:3,p:4) master-key wrap; the OS-keychain layer
//! is a flagged hardening item mandatory before any mainnet-adjacent phase.

import { gcm } from "@noble/ciphers/aes.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { bytesToHex, hexToBytes, utf8ToBytes, randomBytes } from "@noble/hashes/utils.js";

import { FileBackend, type StorageBackend } from "./store.js";

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
/** argon2id parameters per satnam SPECIFICATION §2.2. */
const ARGON2_PARAMS = { m: 65536, t: 3, p: 4 } as const;
/** Master key size (bytes). */
const MASTER_KEY_LEN = 32;
/** Minimum passphrase length enforced client-side (satnam spec §2.2 floor). */
export const MIN_PASSPHRASE_LEN = 12;

/** Idle-lock bounds (ms): clamped to [5 min, 60 min], default 15 min. */
const IDLE_MIN_MS = 300_000;
const IDLE_MAX_MS = 3_600_000;
const IDLE_DEFAULT_MS = 900_000;

// ---------------------------------------------------------------------------
// Typed Vault Errors
// ---------------------------------------------------------------------------

export enum VaultError {
  VaultLocked = "VaultLocked",
  IdentityNotFound = "IdentityNotFound",
  DecryptionFailed = "DecryptionFailed",
}

function vaultErr(variant: VaultError): Error {
  return Object.assign(new Error(variant), { vaultError: variant });
}

export interface VaultConfig {
  /** Idle timeout before auto-lock (zeroes the master key). Clamped. */
  idleTimeoutMs: number;
  /** Vault directory root. */
  vaultRoot: string;
}

export const DEFAULT_VAULT_CONFIG: VaultConfig = {
  idleTimeoutMs: IDLE_DEFAULT_MS,
  vaultRoot: "sovereign-wallet/vault",
};

export interface WrappingKeyMeta {
  method: "passphrase";
  credentialId: string;
  argon2Params?: { m: number; t: number; p: number; keyLen: number };
  createdAt: string;
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

/** Encrypt the master key under a wrapping key (AES-256-GCM). */
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
  /** Master key held in memory while unlocked; zeroed on lock(). */
  #masterKey: Uint8Array | null = null;
  #idleTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(config?: Partial<VaultConfig>, root?: string) {
    this.#config = {
      ...DEFAULT_VAULT_CONFIG,
      ...config,
      idleTimeoutMs: Math.min(IDLE_MAX_MS, Math.max(IDLE_MIN_MS, config?.idleTimeoutMs ?? IDLE_DEFAULT_MS)),
    };
    const rootDir = root ?? this.#config.vaultRoot;
    this.#storage = new FileBackend(rootDir);
  }

  private path(dir: string, filename: string): string {
    return `${this.#config.vaultRoot}/${dir}/${filename}`;
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
    const saltPath = `${this.#config.vaultRoot}/passphrase.salt`;
    let salt = await this.#storage.read(saltPath);
    if (!salt) {
      salt = randomBytes(32);
      await this.#storage.write(saltPath, salt);
    }
    const wrappingKey = derivePassphraseWrappingKey(credential, salt);
    return { wrappingKey, salt };
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /** Initialize a fresh vault under a passphrase (argon2id-wrapped master key). */
  async initialize(credential: string): Promise<void> {
    for (const dir of ["identities", "wallet", "agents", "nip46", "l402"]) {
      const sentinel = `${this.#config.vaultRoot}/${dir}/.keep`;
      if (!(await this.#storage.exists(sentinel))) {
        await this.#storage.write(sentinel, new Uint8Array(0));
      }
    }

    const { wrappingKey } = await this.deriveWrappingKey(credential);
    try {
      const masterKey = randomBytes(MASTER_KEY_LEN);
      const encryptedMasterKey = encryptMasterKey(wrappingKey, masterKey);
      await this.#storage.write(`${this.#config.vaultRoot}/master.key`, encryptedMasterKey);

      const meta: WrappingKeyMeta = {
        method: "passphrase",
        credentialId: "",
        argon2Params: { m: ARGON2_PARAMS.m, t: ARGON2_PARAMS.t, p: ARGON2_PARAMS.p, keyLen: MASTER_KEY_LEN },
        createdAt: new Date().toISOString(),
      };
      await this.#storage.write(`${this.#config.vaultRoot}/wrapping.meta`, utf8ToBytes(JSON.stringify(meta)));

      this.#masterKey = masterKey;
      this.resetIdleTimer();
    } finally {
      zeroBytes(wrappingKey);
    }
  }

  /** Unlock an existing vault with the passphrase (argon2id → AES-GCM master key). */
  async unlock(credential: string): Promise<void> {
    const { wrappingKey } = await this.deriveWrappingKey(credential);
    try {
      const encryptedMasterKey = await this.#storage.read(`${this.#config.vaultRoot}/master.key`);
      if (!encryptedMasterKey) throw vaultErr(VaultError.DecryptionFailed);
      const masterKey = decryptMasterKey(wrappingKey, encryptedMasterKey);
      if (this.#masterKey) zeroBytes(this.#masterKey);
      this.#masterKey = masterKey;
      this.resetIdleTimer();
    } finally {
      zeroBytes(wrappingKey);
    }
  }

  /** Lock the vault: zero the master key and clear the idle timer. */
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
    return this.#storage.exists(`${this.#config.vaultRoot}/master.key`);
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
  // Backup (v2 encrypted envelope; passphrase-only threat model, SEC-2026-052)
  // -------------------------------------------------------------------------

  /**
   * Export a v2 encrypted backup. Envelope:
   * `[4-byte LE saltLen][salt][4-byte LE encMKLen][encryptedMasterKeyBlob][xchacha20poly1305(masterKey, JSON(entries))]`
   *
   * The argon2id salt (not secret) is included UNENCRYPTED in the prefix so a
   * fresh device can re-derive the wrapping key from the passphrase alone to
   * decrypt the master key — satisfying the design's "restore re-derives the
   * wrapping key from the passphrase on a fresh device". This is a small
   * labeled adaptation of satnam's envelope (which stored the salt only inside
   * the encrypted payload, leaving fresh-device restore circular); the salt is
   * not secret, so exposing it does not weaken the passphrase KDF.
   */
  async exportEncryptedBackup(): Promise<Uint8Array> {
    const masterKey = this.requireUnlocked();
    this.resetIdleTimer();

    const encryptedMasterKeyBlob = await this.#storage.read(`${this.#config.vaultRoot}/master.key`);
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

    const salt = await this.#storage.read(`${this.#config.vaultRoot}/passphrase.salt`);
    const backupPayload = {
      version: 2,
      createdAt: new Date().toISOString(),
      entries,
    };

    const payloadCiphertext = encryptEntry(masterKey, utf8ToBytes(JSON.stringify(backupPayload)));

    const saltBytes = salt ?? new Uint8Array(0);
    const saltHeader = new Uint8Array(4);
    new DataView(saltHeader.buffer).setUint32(0, saltBytes.length, true);
    const encMKLen = encryptedMasterKeyBlob.length;
    const mkHeader = new Uint8Array(4);
    new DataView(mkHeader.buffer).setUint32(0, encMKLen, true);

    const backup = new Uint8Array(
      saltHeader.length + saltBytes.length + mkHeader.length + encMKLen + payloadCiphertext.length,
    );
    let offset = 0;
    backup.set(saltHeader, offset);
    offset += saltHeader.length;
    if (saltBytes.length > 0) {
      backup.set(saltBytes, offset);
      offset += saltBytes.length;
    }
    backup.set(mkHeader, offset);
    offset += mkHeader.length;
    backup.set(encryptedMasterKeyBlob, offset);
    offset += encMKLen;
    backup.set(payloadCiphertext, offset);
    return backup;
  }

  /**
   * Import a v2 backup. With a credential (passphrase) on a fresh device, the
   * salt in the prefix re-derives the wrapping key to decrypt the master key,
   * then the payload restores every entry.
   */
  async importEncryptedBackup(data: Uint8Array, credential?: string): Promise<void> {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (data.length < 8) throw vaultErr(VaultError.DecryptionFailed);
    const saltLen = view.getUint32(0, true);
    if (data.length < 4 + saltLen + 4) throw vaultErr(VaultError.DecryptionFailed);
    const salt = saltLen > 0 ? data.slice(4, 4 + saltLen) : new Uint8Array(0);
    const mkHeaderOff = 4 + saltLen;
    const encMKLen = view.getUint32(mkHeaderOff, true);
    if (data.length < mkHeaderOff + 4 + encMKLen) throw vaultErr(VaultError.DecryptionFailed);
    const mkOff = mkHeaderOff + 4;
    const encryptedMasterKeyBlob = data.slice(mkOff, mkOff + encMKLen);

    let masterKey: Uint8Array | null = null;
    if (this.#masterKey) {
      masterKey = this.#masterKey;
    } else if (credential) {
      if (credential.length < MIN_PASSPHRASE_LEN) {
        throw new Error(`Passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`);
      }
      const wrappingKey = derivePassphraseWrappingKey(credential, salt);
      try {
        masterKey = decryptMasterKey(wrappingKey, encryptedMasterKeyBlob);
      } finally {
        zeroBytes(wrappingKey);
      }
    }
    if (!masterKey) throw vaultErr(VaultError.DecryptionFailed);

    const payloadCiphertext = data.slice(mkOff + encMKLen);
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
    if (backup.version !== 2) throw new Error("Unsupported backup version");

    // Restore the passphrase salt (from the envelope prefix, not secret) and
    // the encrypted master key blob so unlock() derives the same wrapping key.
    if (salt.length > 0) {
      await this.#storage.write(`${this.#config.vaultRoot}/passphrase.salt`, salt);
    }
    await this.#storage.write(`${this.#config.vaultRoot}/master.key`, encryptedMasterKeyBlob);
    for (const [relativePath, hexData] of Object.entries(backup.entries)) {
      await this.#storage.write(`${this.#config.vaultRoot}/${relativePath}`, hexToBytes(hexData));
    }
    // The vault is now populated; caller calls unlock(passphrase) to activate.
  }
}
