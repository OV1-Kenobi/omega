//! Identity module barrel (WP-4): keygen, NIP-98, NIP-49, ceremony, and the
//! small vault-facing helpers the sidecar core consumes.

export * from "./keygen.js";
export * from "./ceremony.js";
export * from "./nip98.js";
export * from "./nip49.js";

import type { Vault } from "../vault/vault.js";

/**
 * Return the public npub of the primary (first stored) identity in the vault,
 * or null when the vault holds no identity. Public projection only — never key
 * material. Returns null when the vault is locked.
 */
export async function listPrimaryNpub(vault: Vault): Promise<string | null> {
  if (!vault.isUnlocked()) return null;
  const identities = await vault.listIdentities();
  return identities[0] ?? null;
}
