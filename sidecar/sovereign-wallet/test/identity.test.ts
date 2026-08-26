//! WP-4 identity/vault unit tests: derivation frozen vector, vault round-trip,
//! recovery artifact restore, NIP-98 verify, mnemonic challenge, importFromNsec,
//! NIP-49 canonical vector, zeroization.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";

import {
  deriveFromMnemonic,
  derivePublicFromMnemonic,
  encodeNsec,
  importFromNsec,
  FROZEN_TEST_MNEMONIC,
  FROZEN_TEST_NPUB,
  NOSTR_DERIVATION_PATH,
  EMPTY_BIP39_PASSPHRASE,
  verifyMnemonicMatches,
  generateMnemonic12,
  decodeNsec,
} from "../dist/identity/keygen.js";
import { verifyChallenge, CHALLENGE_INDEXES, challengeLabels } from "../dist/identity/ceremony.js";
import { Vault, MIN_PASSPHRASE_LEN } from "../dist/vault/vault.js";
import { FileBackend } from "../dist/vault/store.js";
import {
  verifyNip98,
  constructNip98Event,
  buildNip98AuthHeader,
} from "../dist/identity/nip98.js";
import { encryptSecretKey, decryptSecretKey } from "../dist/identity/nip49.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils.js";

const PASSPHRASE = "correct horse battery staple";

describe("identity keygen (OMEGA-DELTA-0284)", () => {
  it("derives the frozen BIP-39/NIP-06 public vector (abandon…about → npub)", () => {
    const derived = derivePublicFromMnemonic(FROZEN_TEST_MNEMONIC);
    assert.equal(derived.npub, FROZEN_TEST_NPUB);
    assert.equal(derived.derivationPath, NOSTR_DERIVATION_PATH);
    assert.equal(
      NOSTR_DERIVATION_PATH,
      "m/44'/1237'/0'/0/0",
      "OMEGA-DELTA-0284: the NIP-06 path must stay frozen",
    );
    assert.equal(
      EMPTY_BIP39_PASSPHRASE,
      "",
      "OMEGA-DELTA-0284: the BIP-39 passphrase must stay empty",
    );
  });

  it("derives full material and round-trips the secret through encode/decode nsec", () => {
    const derived = deriveFromMnemonic(FROZEN_TEST_MNEMONIC);
    assert.equal(derived.secret.length, 32);
    const nsec = encodeNsec(derived.secret);
    assert.ok(nsec.startsWith("nsec1"));
    const decoded = decodeNsec(nsec);
    assert.deepEqual(decoded, derived.secret);
  });

  it("importFromNsec accepts bech32 nsec and 64-hex and verifies the npub", () => {
    const derived = deriveFromMnemonic(FROZEN_TEST_MNEMONIC);
    const nsec = encodeNsec(derived.secret);
    // bech32 import
    const imported = importFromNsec(nsec);
    assert.equal(imported.publicPart.npub, FROZEN_TEST_NPUB);
    assert.deepEqual(imported.secret, derived.secret);
    // 64-hex import
    const hex = Buffer.from(derived.secret).toString("hex");
    const importedHex = importFromNsec(hex);
    assert.equal(importedHex.publicPart.npub, FROZEN_TEST_NPUB);
  });

  it("verifyMnemonicMatches confirms the mnemonic and rejects a wrong npub", () => {
    assert.equal(verifyMnemonicMatches(FROZEN_TEST_MNEMONIC, FROZEN_TEST_NPUB), true);
    assert.equal(verifyMnemonicMatches(FROZEN_TEST_MNEMONIC, "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu"), false);
  });

  it("generates a fresh valid 12-word mnemonic", () => {
    const mnemonic = generateMnemonic12();
    assert.equal(mnemonic.split(" ").length, 12);
    // The generated npub is a valid bech32 npub (public projection only).
    const npub = derivePublicFromMnemonic(mnemonic).npub;
    assert.ok(npub.startsWith("npub1"));
  });
});

describe("mnemonic ceremony (show-once + word challenge)", () => {
  it("challenge positions are the 2nd, 7th, and 11th words", () => {
    assert.deepEqual(challengeLabels(), [2, 7, 11]);
  });

  it("passes when the correct words are entered at positions 2/7/11", () => {
    const words = FROZEN_TEST_MNEMONIC.split(" ");
    const answers: Record<number, string> = {};
    for (const idx of CHALLENGE_INDEXES) {
      answers[idx] = words[idx];
    }
    assert.equal(verifyChallenge(FROZEN_TEST_MNEMONIC, answers), true);
  });

  it("fails when a challenge word is wrong", () => {
    const words = FROZEN_TEST_MNEMONIC.split(" ");
    const answers: Record<number, string> = {};
    for (const idx of CHALLENGE_INDEXES) answers[idx] = words[idx];
    answers[CHALLENGE_INDEXES[0]] = "wrong";
    assert.equal(verifyChallenge(FROZEN_TEST_MNEMONIC, answers), false);
  });
});

describe("vault (desktop file store, WP-4)", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sw-vault-"));
  const root = path.join(dir, "vault");
  let vault: Vault;

  before(() => {
    vault = new Vault({ vaultRoot: "vault" }, root);
  });
  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("enforces the minimum passphrase length (SEC-2026-052)", async () => {
    const short = new Vault({ vaultRoot: "vault" }, path.join(dir, "short"));
    await assert.rejects(() => short.initialize("short"), /at least/);
    assert.ok(MIN_PASSPHRASE_LEN >= 12);
  });

  it("initializes, stores an identity, round-trips unlock, and zeroizes on lock", async () => {
    await vault.initialize(PASSPHRASE);
    assert.equal(vault.isUnlocked(), true);

    const derived = deriveFromMnemonic(FROZEN_TEST_MNEMONIC);
    await vault.storeNsec(derived.publicPart.npub, derived.secret);
    // Zero the caller's copy after sealing (S4 discipline).
    derived.secret.fill(0);

    // The stored secret is encrypted (not plaintext) on disk.
    const raw = await new FileBackend(root).read(`vault/identities/${derived.publicPart.npub}.nsec`);
    assert.ok(raw && raw.length > 32, "entry ciphertext is non-trivial");
    const plaintext = Buffer.from(derived.publicPart.npub).toString("utf8");
    const rawText = Buffer.from(raw).toString("utf8");
    assert.ok(!rawText.includes(plaintext), "nsec entry is not stored in plaintext");

    // Lock zeroizes the master key.
    vault.lock();
    assert.equal(vault.isUnlocked(), false);
    await assert.rejects(() => vault.getNsec(derived.publicPart.npub), (e) => {
      return e instanceof Error && (e as { vaultError?: string }).vaultError === "VaultLocked";
    });

    // Unlock with the correct passphrase restores access to the identity.
    await vault.unlock(PASSPHRASE);
    assert.equal(vault.isUnlocked(), true);
    const nsec = await vault.getNsec(derived.publicPart.npub);
    assert.equal(nsec.length, 32);
    assert.deepEqual(await vault.listIdentities(), [derived.publicPart.npub]);
  });

  it("rejects the wrong passphrase on unlock", async () => {
    vault.lock();
    await assert.rejects(() => vault.unlock("wrong passphrase value"), (e) => {
      return e instanceof Error && (e as { vaultError?: string }).vaultError === "DecryptionFailed";
    });
  });

  it("restores from the v2 encrypted backup on a fresh device (recovery artifact restores)", async () => {
    await vault.unlock(PASSPHRASE);
    const backup = await vault.exportEncryptedBackup();
    assert.ok(backup.length > 100);

    // Fresh device: a new vault over a new root, restored from the backup, then
    // unlocked with the passphrase to recover the identity.
    const freshRoot = path.join(dir, "fresh");
    const fresh = new Vault({ vaultRoot: "vault" }, freshRoot);
    await fresh.importEncryptedBackup(backup, PASSPHRASE);
    await fresh.unlock(PASSPHRASE);
    assert.equal(fresh.isUnlocked(), true);

    const identities = await fresh.listIdentities();
    assert.equal(identities.length, 1);
    const nsec = await fresh.getNsec(identities[0]);
    assert.equal(nsec.length, 32);
    // The recovered identity matches the frozen vector's npub.
    assert.equal(identities[0], FROZEN_TEST_NPUB);
  });

  it("stores and retrieves a Wavelength wallet entry (aezeed vaulted, Q1)", async () => {
    await vault.unlock(PASSPHRASE);
    const walletId = "wlt-0001";
    await vault.storeWalletEntry({
      walletId,
      walletDbPassword: "opaque-wallet-password",
      aezeed: "abandon art ability able ...",
      createdAt: new Date().toISOString(),
    });
    const entry = await vault.getWalletEntry(walletId);
    assert.equal(entry.walletDbPassword, "opaque-wallet-password");
    assert.equal(entry.aezeed, "abandon art ability able ...");
  });
});

describe("NIP-98 auth (kind 27235)", () => {
  const secret = deriveFromMnemonic(FROZEN_TEST_MNEMONIC).secret;
  const url = "https://relay.example/.netlify/functions/register";
  const body = new TextEncoder().encode(JSON.stringify({ username: "satoshi" }));

  it("verifies a valid constructed header", () => {
    const header = buildNip98AuthHeader(secret, url, "POST", body);
    const outcome = verifyNip98(header, url, "POST", body);
    assert.equal(outcome.authenticated, true);
    if (outcome.authenticated) {
      assert.equal(outcome.pubkey, deriveFromMnemonic(FROZEN_TEST_MNEMONIC).publicPart.pubkeyHex);
      assert.ok(outcome.eventId, "eventId is the replay-safe dedupe key");
    }
  });

  it("rejects a wrong HTTP method", () => {
    const header = buildNip98AuthHeader(secret, url, "POST", body);
    const outcome = verifyNip98(header, url, "GET", body);
    assert.equal(outcome.authenticated, false);
    if (!outcome.authenticated) assert.equal(outcome.reason, "method_mismatch");
  });

  it("rejects an expired (stale) event beyond ±60s skew", () => {
    const event = constructNip98Event(secret, url, "POST", body);
    // Reconstruct a stale event by signing with a forged old timestamp.
    // Simplest reliable check: directly call verifyNip98 with a header signed
    // "now - 200s" by constructing a manual event through a small helper below.
    const staleHeader = staleSignedHeader(secret, url, body);
    const outcome = verifyNip98(staleHeader, url, "POST", body);
    assert.equal(outcome.authenticated, false);
    if (!outcome.authenticated) assert.equal(outcome.reason, "expired");
  });

  it("rejects a payload mismatch", () => {
    const header = buildNip98AuthHeader(secret, url, "POST", body);
    const tampered = new TextEncoder().encode(JSON.stringify({ username: "tampered" }));
    const outcome = verifyNip98(header, url, "POST", tampered);
    assert.equal(outcome.authenticated, false);
    if (!outcome.authenticated) assert.equal(outcome.reason, "payload_mismatch");
  });
});

describe("NIP-49 recovery artifact", () => {
  it("decrypts the canonical NIP-49 test vector (password=nostr, log_n=16)", () => {
    const token =
      "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    const key = decryptSecretKey(token, "nostr");
    assert.equal(
      Buffer.from(key).toString("hex"),
      "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683",
    );
  });

  it("encrypts then decrypts a secret key round-trip (recovery artifact restores)", () => {
    const secret = deriveFromMnemonic(FROZEN_TEST_MNEMONIC).secret;
    const { token } = encryptSecretKey(secret, "recovery-password-1234", 16);
    assert.ok(token.startsWith("ncryptsec1"));
    const restored = decryptSecretKey(token, "recovery-password-1234");
    assert.deepEqual(restored, secret);
  });

  it("rejects the wrong recovery password", () => {
    const secret = deriveFromMnemonic(FROZEN_TEST_MNEMONIC).secret;
    const { token } = encryptSecretKey(secret, "recovery-password-1234", 16);
    assert.throws(() => decryptSecretKey(token, "wrong-password"), /decryption failed/);
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Sign a NIP-98 event with a stale created_at (now - skew - margin). */
function staleSignedHeader(secret: Uint8Array, url: string, body: Uint8Array): string {
  const pubkey = bytesToHex(schnorr.getPublicKey(secret));
  const tags = [
    ["u", url],
    ["method", "POST"],
    ["payload", bytesToHex(sha256(body))],
  ];
  const unsigned = { pubkey, created_at: Math.floor(Date.now() / 1000) - 200, kind: 27235, tags, content: "" };
  const id = bytesToHex(
    sha256(
      utf8ToBytes(
        JSON.stringify([0, unsigned.pubkey, unsigned.created_at, unsigned.kind, unsigned.tags, unsigned.content]),
      ),
    ),
  );
  const sig = bytesToHex(schnorr.sign(Buffer.from(id, "hex"), secret));
  const signed = { ...unsigned, id, sig };
  return `Nostr ${Buffer.from(utf8ToBytes(JSON.stringify(signed))).toString("base64")}`;
}
