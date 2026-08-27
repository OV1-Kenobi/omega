//! Sovereign identity key generation and import (WP-4 of OA-P2-WALLET-2026-08-26).
//!
//! Faithful port of satnam-v0.2 `src/lib/identity/keygen.ts` to the desktop
//! Node sidecar. The derivation profile matches the frozen OpenAgents
//! sovereign-identity profile (`m/44'/1237'/0'/0/0`, empty BIP-39 passphrase):
//!
//!   CSPRNG → BIP-39 mnemonic (12 words, English) → PBKDF2 stretch (EMPTY
//!   passphrase) → BIP-32 master seed → NIP-06 path m/44'/1237'/0'/0/0 →
//!   secp256k1 → bech32 npub/nsec.
//!
//! ## OMEGA-DELTA-0284 — the sovereign identity derives from a BIP-39/NIP-06
//! shared root
//!
//! Omega-before-this generated one random Nostr keypair per account and derived
//! nothing (documented at `crates/agent_ui/src/effective_principal.rs`). Per
//! founder decision D2 (2026-08-26) and the satnam/sovereign-identity lineage,
//! fresh activation now derives the sovereign identity from a BIP-39 shared
//! root (12-word English mnemonic, empty passphrase, BIP-32 master seed) at the
//! NIP-06 path `m/44'/1237'/0'/0/0`. This is the sidecar's secret-handling home
//! for that divergence; the Rust `omega_identity` activation path keeps the
//! same shape and bridges the derived key through its existing import path.
//!
//! The random-keypair path remains as the import/legacy entry
//! (`importFromNsec`), exactly as satnam keeps it — the divergence is
//! **superseded by delta, not deleted**.
//!
//! SECRET BOUNDARY: nothing in this module persists key material. Mnemonic
//! display is a one-time ceremony responsibility (word-confirmation challenge
//! lives in `ceremony.ts`); storage is the vault (`storeNsec`) only.
//!
//! Cross-ecosystem test vector (canonical public BIP-39/NIP-06 vector): the
//! mnemonic `abandon … about` MUST derive npub
//! `npub1az708q3kd9zy6z6f44zav5ygvdwelkzspf6mtusttx47lft2z38sghk0w7`.

import { generateMnemonic, validateMnemonic, mnemonicToSeedSync } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { HDKey } from "@scure/bip32";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { bech32 } from "@scure/base";

/** Frozen derivation constants (do not change silently). */
export const NOSTR_DERIVATION_PATH = "m/44'/1237'/0'/0/0" as const;
export const DERIVATION_PROFILE_ID = "satnam.v2.nip06.v1" as const;
export const EMPTY_BIP39_PASSPHRASE = "" as const;

/** The canonical public frozen test vector (BIP-39 12-word → NIP-06 npub). */
export const FROZEN_TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
export const FROZEN_TEST_NPUB = "npub1az708q3kd9zy6z6f44zav5ygvdwelkzspf6mtusttx47lft2z38sghk0w7";

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** Normalize BIP-39 whitespace without changing words (matches OpenAgents). */
export function normalizeMnemonic(value: string): string {
  return value.trim().split(/\s+/).join(" ");
}

/** Validate an English BIP-39 checksum + word count. */
export function isValidEnglishMnemonic(mnemonic: string): boolean {
  try {
    return validateMnemonic(normalizeMnemonic(mnemonic), wordlist);
  } catch {
    return false;
  }
}

/** Generate a fresh 12-word English mnemonic from platform CSPRNG. */
export function generateMnemonic12(): string {
  return generateMnemonic(wordlist, 128);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Encode 32-byte x-only pubkey as bech32 npub. */
export function encodeNpub(pubkeyXonly: Uint8Array): string {
  return bech32.encode("npub", bech32.toWords(pubkeyXonly));
}

/** Encode 32-byte secret key as bech32 nsec. */
export function encodeNsec(secret: Uint8Array): string {
  return bech32.encode("nsec", bech32.toWords(secret));
}

/**
 * Decode nsec material: accepts bech32 `nsec1…` (prefix + length validated)
 * or raw 64-hex. Pattern matches satnam/OpenAgents `parseSecretMaterial`.
 */
export function decodeNsec(raw: string): Uint8Array {
  const trimmed = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Uint8Array.from(Buffer.from(trimmed.toLowerCase(), "hex"));
  }
  if (trimmed.startsWith("nsec1")) {
    const decoded = bech32.decode(trimmed as `${string}1${string}`, false);
    if (decoded.prefix !== "nsec") {
      throw new Error("identity/keygen: expected nsec prefix");
    }
    const bytes = new Uint8Array(bech32.fromWords(decoded.words));
    if (bytes.length !== 32) {
      throw new Error("identity/keygen: nsec payload must be 32 bytes");
    }
    return bytes;
  }
  throw new Error("identity/keygen: secret must be 64-hex or nsec1…");
}

/** Decode a bech32 npub to 32-byte x-only pubkey. */
export function decodeNpub(npub: string): Uint8Array {
  const decoded = bech32.decode(npub.trim() as `${string}1${string}`, false);
  if (decoded.prefix !== "npub") {
    throw new Error("identity/keygen: expected npub prefix");
  }
  const bytes = new Uint8Array(bech32.fromWords(decoded.words));
  if (bytes.length !== 32) {
    throw new Error("identity/keygen: npub payload must be 32 bytes");
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/** Public identity projection — safe to persist/display. No secrets. */
export interface DerivedIdentityPublic {
  readonly pubkeyHex: string;
  readonly npub: string;
  readonly derivationPath: typeof NOSTR_DERIVATION_PATH;
  readonly profileId: typeof DERIVATION_PROFILE_ID;
}

interface DerivedKeyMaterial {
  readonly publicPart: DerivedIdentityPublic;
  /** Raw 32-byte secret — caller MUST hand to vault.storeNsec() and drop. */
  readonly secret: Uint8Array;
}

function deriveFromSeed(seed: Uint8Array): DerivedKeyMaterial {
  const master = HDKey.fromMasterSeed(seed);
  const node = master.derive(NOSTR_DERIVATION_PATH);
  if (!node.privateKey) throw new Error("identity/keygen: failed to derive Nostr private key");
  // x-only pubkey exactly as the frozen OpenAgents reference (compressed, strip 02/03).
  const pubkeyXonly = secp256k1.getPublicKey(node.privateKey, true).slice(1);
  const publicPart: DerivedIdentityPublic = {
    pubkeyHex: bytesToHex(pubkeyXonly),
    npub: encodeNpub(Uint8Array.from(pubkeyXonly)),
    derivationPath: NOSTR_DERIVATION_PATH,
    profileId: DERIVATION_PROFILE_ID,
  };
  return { publicPart, secret: Uint8Array.from(node.privateKey) };
}

/**
 * Derive full key material from a mnemonic under the frozen empty-passphrase
 * profile. A non-empty passphrase produces DIFFERENT keys by design (BIP-39);
 * production recovery always uses the empty passphrase.
 */
export function deriveFromMnemonic(
  mnemonic: string,
  passphrase: string = EMPTY_BIP39_PASSPHRASE,
): DerivedKeyMaterial {
  const normalized = normalizeMnemonic(mnemonic);
  if (!isValidEnglishMnemonic(normalized)) {
    throw new Error("identity/keygen: not a valid BIP-39 English mnemonic");
  }
  const seed = mnemonicToSeedSync(normalized, passphrase);
  return deriveFromSeed(seed);
}

/** Derive only the PUBLIC projection (no secret retained in return path). */
export function derivePublicFromMnemonic(mnemonic: string): DerivedIdentityPublic {
  return deriveFromMnemonic(mnemonic).publicPart;
}

/**
 * Public projection from raw 32-byte secret bytes (public output only).
 * WP-5: used by the identity-status projection to report the pubkey hex of
 * the vault identity without persisting or logging the secret; the caller
 * zeroizes the secret buffer after use.
 */
export function publicProjectionFromSecretBytes(secret: Uint8Array): DerivedIdentityPublic {
  const pubkeyXonly = schnorr.getPublicKey(secret);
  return {
    pubkeyHex: bytesToHex(pubkeyXonly),
    npub: encodeNpub(Uint8Array.from(pubkeyXonly)),
    derivationPath: NOSTR_DERIVATION_PATH,
    profileId: DERIVATION_PROFILE_ID,
  };
}

/**
 * Import an existing identity from nsec material (bech32 or 64-hex).
 * Verifies the derived npub against the provided secret so a typo'd input
 * cannot silently create a mismatched identity record.
 */
export function importFromNsec(nsecRaw: string): DerivedKeyMaterial {
  const secret = decodeNsec(nsecRaw);
  const pubkeyXonly = schnorr.getPublicKey(secret);
  const publicPart: DerivedIdentityPublic = {
    pubkeyHex: bytesToHex(pubkeyXonly),
    npub: encodeNpub(pubkeyXonly),
    derivationPath: NOSTR_DERIVATION_PATH,
    profileId: DERIVATION_PROFILE_ID,
  };
  return { publicPart, secret };
}

/**
 * Verify that a mnemonic imports to an expected npub (mnemonic import flow:
 * user enters words + we check the derived npub they expect).
 */
export function verifyMnemonicMatches(mnemonic: string, expectedNpub: string): boolean {
  try {
    return derivePublicFromMnemonic(mnemonic).npub === normalizeBech32(expectedNpub);
  } catch {
    return false;
  }
}

function normalizeBech32(value: string): string {
  return value.trim().toLowerCase();
}
