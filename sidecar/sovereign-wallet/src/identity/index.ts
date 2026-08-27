//! Identity module barrel (WP-4): keygen, NIP-98, NIP-49, ceremony, and the
//! small vault-facing helpers the sidecar core consumes.

export * from "./keygen.js";
export * from "./ceremony.js";
export * from "./nip98.js";
export * from "./nip49.js";

import type { Vault } from "../vault/vault.js";
import { publicProjectionFromSecretBytes } from "./keygen.js";

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

/**
 * Public identity projection of the primary identity: npub + 64-hex pubkey
 * (WP-5 — the hex is the `principal_pubkey` for pubkey-keyed spending
 * authorizations). The raw secret is read, its public projection computed,
 * and the secret buffer zeroized before returning. Public output only.
 */
export async function listPrimaryIdentity(
  vault: Vault,
): Promise<{ npub: string; pubkeyHex: string } | null> {
  if (!vault.isUnlocked()) return null;
  const identities = await vault.listIdentities();
  const npub = identities[0] ?? null;
  if (!npub) return null;
  const secret = await vault.getNsec(npub);
  try {
    const projection = publicProjectionFromSecretBytes(secret);
    return { npub: projection.npub, pubkeyHex: projection.pubkeyHex };
  } finally {
    secret.fill(0);
  }
}
