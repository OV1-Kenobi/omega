//! Production OS-keychain backend (WP-3a / OMEGA-DELTA-0301, RV6-REQ-1).
//!
//! THE ONLY module that statically imports the native binding package
//! (`@napi-rs/keyring` 2.0.0 — exact pin, committed lockfile; install-gate
//! integrity evidence in
//! planning/2026-08-31-omega-mainnet-transition/evidence/05-wp3a-evidence.md).
//! It wraps Windows Credential Manager generic credentials (CRED_TYPE_GENERIC
//! — the OS protects the value at rest with DPAPI under the user account) and
//! macOS Keychain Services (kSecClassGenericPassword) through the keyring-rs
//! native binding. The exact OS-level field mapping (service/account →
//! TargetName/UserName) is keyring-rs's documented behavior — recorded as
//! [REQUIRES VERIFICATION] for the WP-9/staging runtime probe, never assumed.
//!
//! API surface verified from the INSTALLED module at the exact pinned version
//! (LRN-2026-051 — never web docs alone):
//! `node_modules/@napi-rs/keyring/index.d.ts` — `AsyncEntry` with
//! `setSecret(secret: Uint8Array)`, `getSecret(): Promise<Uint8Array |
//! undefined>`, `deleteCredential(): Promise<boolean>`; `index.js` exports
//! `AsyncEntry`/`Entry`/`findCredentials`/`findCredentialsAsync`. `getSecret`
//! REJECTS when the store is locked/inaccessible and returns `undefined` when
//! no entry exists — exactly the fail-closed semantics the vault needs
//! (RV6-REQ-5). Line references are recorded in the WP-3a evidence artifact.

import { AsyncEntry } from "@napi-rs/keyring";

import { KEYCHAIN_CREDENTIAL_PREFIX, type KeychainBackend } from "./keychain.js";

/** The keyring-rs service name (the stable prefix of the credential id). */
const SERVICE = KEYCHAIN_CREDENTIAL_PREFIX.slice(0, -1); // "omega-sovereign-wallet"

/** Split a composite credential id into the keyring service/account pair. */
function splitCredentialId(credentialId: string): { service: string; account: string } {
  const colon = credentialId.indexOf(":");
  if (colon === -1) return { service: SERVICE, account: credentialId };
  return { service: credentialId.slice(0, colon), account: credentialId.slice(colon + 1) };
}

/**
 * Create the production OS-keychain backend (Windows Credential Manager /
 * macOS Keychain Services). K_os is stored as a raw 32-byte secret via
 * `setSecret`/`getSecret` (no string encoding of key bytes). The returned
 * arrays are fresh allocations owned by the caller, so the vault's
 * zeroization discipline (RV6-REQ-6) never disturbs the OS store.
 */
export function createOsKeychainBackend(): KeychainBackend {
  return {
    async get(credentialId: string): Promise<Uint8Array | null> {
      const { service, account } = splitCredentialId(credentialId);
      const entry = new AsyncEntry(service, account);
      const secret = await entry.getSecret();
      return secret ?? null;
    },
    async set(credentialId: string, value: Uint8Array): Promise<void> {
      const { service, account } = splitCredentialId(credentialId);
      const entry = new AsyncEntry(service, account);
      await entry.setSecret(value);
    },
    async delete(credentialId: string): Promise<void> {
      const { service, account } = splitCredentialId(credentialId);
      const entry = new AsyncEntry(service, account);
      await entry.deleteCredential();
    },
  };
}