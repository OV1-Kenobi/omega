//! NIP-49 / ncryptsec private-key encryption artifact (WP-4).
//!
//! The identity-only recovery artifact: the derived Nostr key is exported as a
//! NIP-49 `ncryptsec1…` token under an operator-chosen recovery password, so a
//! lost vault passphrase still restores the identity through the existing Rust
//! `omega_identity` recovery flow (discover → decrypt → adopt).
//!
//! The format is verified against the canonical NIP-49 test vector (password
//! `nostr`, log_n=16) which decrypts to the expected private key. The default
//! `log_n` is 16, matching `omega_identity`'s `NIP49_LOG_N = 16`.
//!
//! NIP-49 derivation uses **scrypt** (via Node's built-in `node:crypto` — no
//! new dependency), NOT argon2id or PBKDF2; the noble family ships no scrypt.
//! Per NIP-49, the symmetric key is zeroed and discarded after use.
//!
//! - key = scrypt(password, salt=16B, N=2^log_n, r=8, p=1) → 32 bytes
//! - nonce = 24 bytes
//! - ciphertext = XChaCha20-Poly1305(key, nonce, aad=KEY_SECURITY_BYTE)
//! - payload = version(0x02) || log_n || salt(16) || nonce(24) || aad(1) || ct(48)
//! - token = bech32("ncryptsec", payload)

import { scryptSync, randomBytes } from "node:crypto";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { bech32 } from "@scure/base";

/** NIP-49 version byte (0x02). */
const VERSION_NUMBER = 0x02;
/** 16-byte random salt. */
const SALT_LEN = 16;
/** 24-byte random nonce. */
const NONCE_LEN = 24;
/** KEY_SECURITY_BYTE: 0x02 = the client does not track key-handling history. */
const KEY_SECURITY_BYTE = 0x02;
/** scrypt params per NIP-49. */
const SCRYPT_R = 8;
const SCRYPT_P = 1;
/** Default log_n, matching omega_identity's NIP49_LOG_N = 16. */
export const DEFAULT_LOG_N = 16;
/** Minimum accepted log_n when decrypting (omega_identity refuses < 16). */
export const MIN_ACCEPTED_LOG_N = 16;

export interface EncryptedSecretKey {
  token: string;
  logN: number;
}

/**
 * Encrypt a 32-byte secret key as a NIP-49 `ncryptsec1…` token under a
 * recovery password. The password is NFKC-normalized per NIP-49.
 */
export function encryptSecretKey(
  secretKey: Uint8Array,
  password: string,
  logN: number = DEFAULT_LOG_N,
): EncryptedSecretKey {
  if (secretKey.length !== 32) throw new Error("nip49: secret key must be 32 bytes");
  const normalized = password.normalize("NFKC");
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const key = scryptSync(normalized, salt, 32, {
    N: 2 ** logN,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 1024 * 1024 * 1024,
  });
  try {
    const aad = new Uint8Array([KEY_SECURITY_BYTE]);
    const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(secretKey);
    const payload = new Uint8Array(1 + 1 + SALT_LEN + NONCE_LEN + 1 + ciphertext.length);
    payload[0] = VERSION_NUMBER;
    payload[1] = logN;
    payload.set(salt, 2);
    payload.set(nonce, 2 + SALT_LEN);
    payload.set(aad, 2 + SALT_LEN + NONCE_LEN);
    payload.set(ciphertext, 2 + SALT_LEN + NONCE_LEN + 1);
    const token = bech32.encode("ncryptsec", bech32.toWords(payload), false);
    return { token, logN };
  } finally {
    key.fill(0);
  }
}

/**
 * Decrypt a NIP-49 `ncryptsec1…` token back to the 32-byte secret key.
 * Rejects log_n below MIN_ACCEPTED_LOG_N (weak-KDF guard, mirroring
 * omega_identity's 16..=18 log_n boundary).
 */
export function decryptSecretKey(token: string, password: string): Uint8Array {
  const decoded = bech32.decode(token.trim() as `${string}1${string}`, false);
  if (decoded.prefix !== "ncryptsec") throw new Error("nip49: expected ncryptsec prefix");
  const payload = new Uint8Array(bech32.fromWords(decoded.words));
  if (payload.length !== 91) throw new Error("nip49: malformed payload length");
  if (payload[0] !== VERSION_NUMBER) throw new Error("nip49: unsupported version");
  const logN = payload[1]!; // payload length is validated to be exactly 91
  if (logN < MIN_ACCEPTED_LOG_N) {
    throw new Error(`nip49: log_n ${logN} is below the accepted minimum ${MIN_ACCEPTED_LOG_N}`);
  }
  const salt = payload.slice(2, 2 + SALT_LEN);
  const nonce = payload.slice(2 + SALT_LEN, 2 + SALT_LEN + NONCE_LEN);
  const aad = payload.slice(2 + SALT_LEN + NONCE_LEN, 2 + SALT_LEN + NONCE_LEN + 1);
  const ciphertext = payload.slice(2 + SALT_LEN + NONCE_LEN + 1);

  const normalized = password.normalize("NFKC");
  const key = scryptSync(normalized, salt, 32, {
    N: 2 ** logN,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 1024 * 1024 * 1024,
  });
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    throw new Error("nip49: decryption failed (wrong password or corrupt artifact)");
  } finally {
    key.fill(0);
  }
}

/** True when a string looks like a NIP-49 recovery artifact. */
export function looksLikeNcryptsec(value: string): boolean {
  return value.trim().startsWith("ncryptsec1");
}
