//! Typed OS-keychain seam for the sovereign-wallet vault (WP-3a /
//! OMEGA-DELTA-0301, RV6-REQ-1/2/4).
//!
//! The vault (serving plane) consumes ONLY this interface — it never imports
//! the native binding package. The production backend lives in
//! `./os-keychain.ts` (the only module that statically imports
//! `@napi-rs/keyring`), and tests inject `InMemoryKeychainBackend` from this
//! module. Structural tests pin that no serving-plane module statically
//! imports the provider package and that the real-SDK factory is unreachable
//! from the test suites (LRN-2026-051 pattern).
//!
//! Credential identity (RV6-REQ-4): the OS-keychain entry name is derived
//! from the data root — `omega-sovereign-wallet:<sha256(dataRoot)[:16]>` — so
//! distinct data roots never collide and the entry is unambiguous per vault.
//! No secret value ever appears in the credential name.

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";

/** Keychain credential-name prefix (RV6-REQ-4). */
export const KEYCHAIN_CREDENTIAL_PREFIX = "omega-sovereign-wallet:";

/** Derive the OS-keychain credential id for a data root (RV6-REQ-4). */
export function keychainCredentialId(dataRoot: string): string {
  const digest = sha256(utf8ToBytes(dataRoot));
  return `${KEYCHAIN_CREDENTIAL_PREFIX}${bytesToHex(digest).slice(0, 16)}`;
}

/**
 * The typed seam between the vault and the OS keychain.
 *
 * `get` returns `null` when no entry exists; a REJECTION means the keychain
 * store is unavailable (service down, binding error, headless session). The
 * vault treats both as `VaultError.KeychainUnavailable` — fail-closed per
 * RV6-REQ-5, never a silent fallback to the passphrase path.
 */
export interface KeychainBackend {
  get(credentialId: string): Promise<Uint8Array | null>;
  set(credentialId: string, value: Uint8Array): Promise<void>;
  delete(credentialId: string): Promise<void>;
}

/**
 * In-memory keychain for the unit suites and the sidecar's `memory` test seam
 * (`OMEGA_SOVEREIGN_WALLET_VAULT_KEYCHAIN=memory`). Never used in production;
 * the production default is `createOsKeychainBackend` from `./os-keychain.ts`.
 */
export class InMemoryKeychainBackend implements KeychainBackend {
  readonly #values = new Map<string, Uint8Array>();
  #unavailable = false;
  /** The most recent array handed out by `get` — lets tests observe zeroization (RV6-REQ-6). */
  lastReturned: Uint8Array | null = null;

  /** Test seam: make every operation throw (simulates a dead/locked store). */
  setUnavailable(unavailable: boolean): void {
    this.#unavailable = unavailable;
  }

  async get(credentialId: string): Promise<Uint8Array | null> {
    if (this.#unavailable) throw new Error("keychain store unavailable (test seam)");
    const value = this.#values.get(credentialId);
    this.lastReturned = value ? new Uint8Array(value) : null;
    return this.lastReturned;
  }

  async set(credentialId: string, value: Uint8Array): Promise<void> {
    if (this.#unavailable) throw new Error("keychain store unavailable (test seam)");
    this.#values.set(credentialId, new Uint8Array(value));
  }

  async delete(credentialId: string): Promise<void> {
    if (this.#unavailable) throw new Error("keychain store unavailable (test seam)");
    this.#values.delete(credentialId);
  }

  /** Test-only: whether an entry currently exists. */
  has(credentialId: string): boolean {
    return this.#values.has(credentialId);
  }

  /** Test-only: the stored value for an entry (a copy, never the live buffer). */
  peek(credentialId: string): Uint8Array | null {
    const value = this.#values.get(credentialId);
    return value ? new Uint8Array(value) : null;
  }
}