//! RV6-REQ-10 test set (OMEGA-DELTA-0301) — OS-keychain master-key wrapping
//! for the sovereign-wallet vault.
//!
//! Positive 1-7 and negative 1-8 exactly as listed in the WP-2 security
//! review (evidence/03-wp2-security-review.md section 3, RV6-REQ-10). The
//! real OS-keychain binding is NEVER touched: every vault injects
//! `InMemoryKeychainBackend` from the typed seam, and the structural tests at
//! the bottom pin that the serving plane has no static import of the provider
//! package and that the real-SDK factory (`os-keychain.ts`) is unreachable
//! from the test suites (LRN-2026-051 pattern).

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, describe, it } from "node:test";

import { gcm } from "@noble/ciphers/aes.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { Vault, VAULT_FALLBACK_OPT_IN_ENV, VaultError, type VaultSecurityEvent } from "../dist/vault/vault.js";
import { FileBackend } from "../dist/vault/store.js";
import {
  InMemoryKeychainBackend,
  KEYCHAIN_CREDENTIAL_PREFIX,
  keychainCredentialId,
} from "../dist/vault/keychain.js";
import { deriveFromMnemonic, FROZEN_TEST_MNEMONIC, FROZEN_TEST_NPUB } from "../dist/identity/keygen.js";

const PASSPHRASE = "correct horse battery staple";
const ARGON2 = { m: 65536, t: 3, p: 4 } as const;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, "..", "src");

function zeroBytes(buf: Uint8Array): void {
  buf.fill(0);
}

/** Seal an entry the way the vault does: XChaCha20-Poly1305 [nonce(24)|ct+tag]. */
function sealEntry(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(plaintext);
  const out = new Uint8Array(24 + ct.length);
  out.set(nonce, 0);
  out.set(ct, 24);
  return out;
}

/**
 * Build a pre-0301 argon2id-only vault fixture (the scheme OMEGA-DELTA-0301
 * migrates): salt + argon2id-wrapped master.key + meta method "passphrase",
 * with the directory sentinels and (optionally) one entry of each type sealed
 * under the master key.
 */
async function buildArgon2OnlyFixture(
  root: string,
  passphrase: string,
  withEntries = false,
): Promise<{ masterKey: Uint8Array; oldMasterKeyBlob: Uint8Array }> {
  const backend = new FileBackend(root);
  const salt = randomBytes(32);
  await backend.write("vault/passphrase.salt", salt);
  const masterKey = randomBytes(32);
  const wrappingKey = argon2id(utf8ToBytes(passphrase), salt, { ...ARGON2, dkLen: 32 });
  try {
    const nonce = randomBytes(12);
    const blob = new Uint8Array(12 + 48); // nonce + ciphertext(32) + tag(16)
    blob.set(nonce, 0);
    blob.set(gcm(wrappingKey, nonce).encrypt(masterKey), 12);
    await backend.write("vault/master.key", blob);
    const meta = {
      method: "passphrase",
      credentialId: "",
      argon2Params: { m: ARGON2.m, t: ARGON2.t, p: ARGON2.p, keyLen: 32 },
      createdAt: new Date().toISOString(),
    };
    await backend.write("vault/wrapping.meta", utf8ToBytes(JSON.stringify(meta)));
    for (const dir of ["identities", "wallet", "agents", "nip46", "l402"]) {
      await backend.write(`vault/${dir}/.keep`, new Uint8Array(0));
    }
    if (withEntries) {
      const derived = deriveFromMnemonic(FROZEN_TEST_MNEMONIC);
      await backend.write(
        `vault/identities/${derived.publicPart.npub}.nsec`,
        sealEntry(masterKey, derived.secret),
      );
      await backend.write(
        "vault/wallet/wlt-0001.entry",
        sealEntry(
          masterKey,
          utf8ToBytes(
            JSON.stringify({
              walletId: "wlt-0001",
              walletDbPassword: "opaque-wallet-password",
              aezeed: "abandon art ability able ...",
              createdAt: new Date().toISOString(),
            }),
          ),
        ),
      );
      const l402Key = randomBytes(32);
      await backend.write("vault/l402/l402-hmac.key", sealEntry(masterKey, l402Key));
      return { masterKey, oldMasterKeyBlob: blob };
    }
    return { masterKey, oldMasterKeyBlob: blob };
  } finally {
    zeroBytes(wrappingKey);
  }
}

describe("RV6-REQ-10 — OS-keychain master-key wrapping (OMEGA-DELTA-0301)", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sw-rv6-"));
  let counter = 0;

  function newRoot(): string {
    counter += 1;
    return path.join(dir, `root-${counter}`);
  }

  function makeVault(
    root: string,
    keychain: InMemoryKeychainBackend = new InMemoryKeychainBackend(),
    config: { onSecurityEvent?: (event: VaultSecurityEvent) => void } = {},
  ): Vault {
    return new Vault({ vaultRoot: "vault", ...config }, root, keychain);
  }

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  // -------------------------------------------------------------------------
  // Positive cases 1-7
  // -------------------------------------------------------------------------

  it("RV6-REQ-10 positive 1: initialize → unlock via keychain WITHOUT passphrase succeeds, wrapMethod os-keychain", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    assert.equal(vault.isUnlocked(), true);
    // The keychain holds exactly one 32-byte K_os under the derived id.
    const credentialId = keychainCredentialId(root);
    assert.equal(keychain.has(credentialId), true);
    const kos = keychain.peek(credentialId);
    assert.equal(kos?.length, 32);
    vault.lock();

    const result = await vault.unlock(); // NO passphrase — keychain path
    assert.equal(result.wrapMethod, "os-keychain");
    assert.equal(vault.isUnlocked(), true);
  });

  it("RV6-REQ-10 positive 2: all entry types round-trip under the migrated vault (nsec, wallet entry, L-402 key)", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    await buildArgon2OnlyFixture(root, PASSPHRASE, true);
    const vault = makeVault(root, keychain);

    const result = await vault.unlock(PASSPHRASE); // migrates in place
    assert.equal(result.wrapMethod, "passphrase-fallback");
    assert.equal(result.migrated, true);

    // nsec
    const nsec = await vault.getNsec(FROZEN_TEST_NPUB);
    const expectedSecret = deriveFromMnemonic(FROZEN_TEST_MNEMONIC).secret;
    assert.deepEqual(nsec, expectedSecret);
    // wallet entry
    const entry = await vault.getWalletEntry("wlt-0001");
    assert.equal(entry.walletDbPassword, "opaque-wallet-password");
    assert.equal(entry.aezeed, "abandon art ability able ...");
    // L-402 key
    const l402Key = await vault.getL402Key();
    assert.equal(l402Key.length, 32);
  });

  it("RV6-REQ-10 positive 3: migration from an argon2id-only fixture preserves every entry and the old passphrase path still works post-migration", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    await buildArgon2OnlyFixture(root, PASSPHRASE, true);
    const vault = makeVault(root, keychain);

    const migrated = await vault.unlock(PASSPHRASE);
    assert.equal(migrated.migrated, true);
    assert.equal(migrated.wrapMethod, "passphrase-fallback");
    assert.equal(keychain.has(keychainCredentialId(root)), true);
    vault.lock();

    // The old passphrase path still works post-migration — as the DEGRADED
    // path via wrapping.kek (opt-in required, per RV6-REQ-5).
    keychain.delete(keychainCredentialId(root)); // keychain now unavailable
    const degraded = await vault.unlock(PASSPHRASE, { allowPassphraseFallback: true });
    assert.equal(degraded.wrapMethod, "passphrase-fallback");
    assert.equal(vault.isUnlocked(), true);
    // Entries still intact after the degraded unlock.
    assert.equal((await vault.listIdentities()).length, 1);
    assert.deepEqual(await vault.listWalletIds(), ["wlt-0001"]);
  });

  it("RV6-REQ-10 positive 4: backup v3 export → fresh-device import → passphrase restore → entries intact → K_os re-enrolled", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    const derived = deriveFromMnemonic(FROZEN_TEST_MNEMONIC);
    await vault.storeNsec(derived.publicPart.npub, derived.secret);
    await vault.storeWalletEntry({
      walletId: "wlt-0001",
      walletDbPassword: "opaque-wallet-password",
      aezeed: "abandon art ability able ...",
      createdAt: new Date().toISOString(),
    });
    await vault.storeL402Key(randomBytes(32));
    const backup = await vault.exportEncryptedBackup();

    // Fresh device: new root, new keychain.
    const freshRoot = newRoot();
    const freshKeychain = new InMemoryKeychainBackend();
    const fresh = makeVault(freshRoot, freshKeychain);
    const imported = await fresh.importEncryptedBackup(backup, PASSPHRASE);
    assert.equal(imported.keychainEnrolled, true);
    // K_os re-enrolled into the new device's keychain.
    assert.equal(freshKeychain.has(keychainCredentialId(freshRoot)), true);

    // Subsequent unlock is keychain-first — no passphrase.
    const unlocked = await fresh.unlock();
    assert.equal(unlocked.wrapMethod, "os-keychain");
    const identities = await fresh.listIdentities();
    assert.equal(identities.length, 1);
    assert.equal(identities[0], FROZEN_TEST_NPUB);
    const entry = await fresh.getWalletEntry("wlt-0001");
    assert.equal(entry.walletDbPassword, "opaque-wallet-password");
    assert.equal((await fresh.getL402Key()).length, 32);
  });

  it("RV6-REQ-10 positive 5: lock/idle-lock unchanged", async () => {
    const root = newRoot();
    const vault = makeVault(root);
    await vault.initialize(PASSPHRASE);
    await vault.storeNsec(deriveFromMnemonic(FROZEN_TEST_MNEMONIC).publicPart.npub, randomBytes(32));
    vault.lock();
    assert.equal(vault.isUnlocked(), false);
    await assert.rejects(
      () => vault.getNsec(FROZEN_TEST_NPUB),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === "VaultLocked",
    );
    // Lock clears the idle timer and the master key; unlock resets the timer
    // (the clamp behavior is unchanged: [5 min, 60 min], default 15 min).
    const result = await vault.unlock();
    assert.equal(result.wrapMethod, "os-keychain");
    assert.equal(vault.isUnlocked(), true);
  });

  it("RV6-REQ-10 positive 6: re-key rotation — old credential removed, master.key decrypts under the new key", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    await vault.storeWalletEntry({
      walletId: "wlt-0001",
      walletDbPassword: "opaque-wallet-password",
      aezeed: "abandon art ability able ...",
      createdAt: new Date().toISOString(),
    });
    const credentialId = keychainCredentialId(root);
    const oldKos = keychain.peek(credentialId);

    await vault.rekey(PASSPHRASE);
    const newKos = keychain.peek(credentialId);
    assert.notDeepEqual(newKos, oldKos, "the old credential value must be replaced");
    assert.equal(newKos?.length, 32);
    vault.lock();

    // master.key decrypts under the new key (keychain-first unlock succeeds).
    const result = await vault.unlock();
    assert.equal(result.wrapMethod, "os-keychain");
    assert.equal((await vault.getWalletEntry("wlt-0001")).walletDbPassword, "opaque-wallet-password");
    vault.lock();

    // The degraded path also works after rotation (wrapping.kek rewritten).
    keychain.delete(credentialId);
    const degraded = await vault.unlock(PASSPHRASE, { allowPassphraseFallback: true });
    assert.equal(degraded.wrapMethod, "passphrase-fallback");
  });

  it("RV6-REQ-10 positive 7: degraded-path unlock with opt-in + correct passphrase succeeds and reports wrapMethod passphrase-fallback", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    vault.lock();
    keychain.delete(keychainCredentialId(root)); // keychain unavailable

    const result = await vault.unlock(PASSPHRASE, { allowPassphraseFallback: true });
    assert.equal(result.wrapMethod, "passphrase-fallback");
    assert.equal(vault.isUnlocked(), true);
  });

  // -------------------------------------------------------------------------
  // Negative cases 1-8
  // -------------------------------------------------------------------------

  it("RV6-REQ-10 negative 1: keychain unavailable → unlock REFUSED (fail-closed, typed KeychainUnavailable) with NO fallback", async () => {
    // (a) entry missing
    const rootA = newRoot();
    const keychainA = new InMemoryKeychainBackend();
    const vaultA = makeVault(rootA, keychainA);
    await vaultA.initialize(PASSPHRASE);
    vaultA.lock();
    keychainA.delete(keychainCredentialId(rootA));
    await assert.rejects(
      () => vaultA.unlock(PASSPHRASE),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.KeychainUnavailable,
    );
    assert.equal(vaultA.isUnlocked(), false);

    // (b) binding error / store locked (backend throws)
    const rootB = newRoot();
    const keychainB = new InMemoryKeychainBackend();
    const vaultB = makeVault(rootB, keychainB);
    await vaultB.initialize(PASSPHRASE);
    vaultB.lock();
    keychainB.setUnavailable(true);
    await assert.rejects(
      () => vaultB.unlock(),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.KeychainUnavailable,
    );
    assert.equal(vaultB.isUnlocked(), false);
  });

  it("RV6-REQ-10 negative 2: passphrase fallback WITHOUT the opt-in → refused", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    vault.lock();
    keychain.delete(keychainCredentialId(root)); // wrapping.kek exists, but...
    await assert.rejects(
      () => vault.unlock(PASSPHRASE), // ...no allowPassphraseFallback opt-in
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.KeychainUnavailable,
    );
    assert.equal(vault.isUnlocked(), false);
  });

  it("RV6-REQ-10 negative 3: mainnet-configured wallet + degraded unlock without the operator confirmation → refused", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    vault.lock();
    keychain.delete(keychainCredentialId(root));

    await assert.rejects(
      () => vault.unlock(PASSPHRASE, { allowPassphraseFallback: true, mainnetConfigured: true, operatorConfirmed: false }),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.OperatorConfirmationRequired,
    );
    assert.equal(vault.isUnlocked(), false);

    // With the operator confirmation the degraded unlock succeeds.
    const ok = await vault.unlock(PASSPHRASE, {
      allowPassphraseFallback: true,
      mainnetConfigured: true,
      operatorConfirmed: true,
    });
    assert.equal(ok.wrapMethod, "passphrase-fallback");
  });

  it("RV6-REQ-10 negative 4: wrong keychain entry → DecryptionFailed with no argon2id attempt", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    vault.lock();
    // Overwrite the entry with a WRONG K_os (keychain is available).
    keychain.set(keychainCredentialId(root), randomBytes(32));

    await assert.rejects(
      // Even with the fallback opt-in and a correct passphrase, the wrong
      // keychain entry refuses with DecryptionFailed — the argon2id path is
      // NOT attempted (fallback is only for keychain UNAVAILABILITY).
      () => vault.unlock(PASSPHRASE, { allowPassphraseFallback: true }),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.DecryptionFailed,
    );
    assert.equal(vault.isUnlocked(), false);
  });

  it("RV6-REQ-10 negative 5: corrupted master.key under K_os → DecryptionFailed, no plaintext leak", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    vault.lock();

    // Corrupt one byte of master.key (valid K_os still in the keychain).
    const backend = new FileBackend(root);
    const blob = (await backend.read("vault/master.key"))!;
    const corrupted = new Uint8Array(blob);
    corrupted[corrupted.length - 1] ^= 0xff;
    await backend.write("vault/master.key", corrupted);

    await assert.rejects(
      () => vault.unlock(),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.DecryptionFailed,
    );
    assert.equal(vault.isUnlocked(), false);
  });

  it("RV6-REQ-10 negative 6: wrapping.meta method mismatch → refused", async () => {
    const root = newRoot();
    const vault = makeVault(root);
    await vault.initialize(PASSPHRASE);
    vault.lock();

    const backend = new FileBackend(root);
    await backend.write(
      "vault/wrapping.meta",
      utf8ToBytes(JSON.stringify({ method: "hsm", credentialId: "", createdAt: new Date().toISOString() })),
    );

    await assert.rejects(
      () => vault.unlock(),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.DecryptionFailed,
    );
    assert.equal(vault.isUnlocked(), false);
  });

  it("RV6-REQ-10 negative 7: migration failure mid-way → old vault still unlocks via passphrase (no lockout)", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const fixture = await buildArgon2OnlyFixture(root, PASSPHRASE, true);
    const vault = makeVault(root, keychain);

    // The keychain store is unavailable → migration's keychain.set fails.
    keychain.setUnavailable(true);
    const result = await vault.unlock(PASSPHRASE);
    assert.equal(result.wrapMethod, "passphrase-fallback");
    assert.equal(result.migrated, false);
    assert.equal(vault.isUnlocked(), true, "a failed migration must not lock the vault out");

    // Old path intact: master.key unchanged, meta still "passphrase".
    const backend = new FileBackend(root);
    assert.deepEqual(await backend.read("vault/master.key"), fixture.oldMasterKeyBlob);
    const metaRaw = await backend.read("vault/wrapping.meta");
    assert.match(JSON.parse(Buffer.from(metaRaw!).toString("utf8")).method, /passphrase/);

    // The vault is fully usable on the old path.
    const nsec = await vault.getNsec(FROZEN_TEST_NPUB);
    assert.equal(nsec.length, 32);

    // Next unlock with a healthy keychain migrates successfully.
    vault.lock();
    keychain.setUnavailable(false);
    const second = await vault.unlock(PASSPHRASE);
    assert.equal(second.migrated, true);
    assert.equal(keychain.has(keychainCredentialId(root)), true);
  });

  it("RV6-REQ-10 negative 8: zeroization hook — K_os buffer zeroed after unlock", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    vault.lock();

    await vault.unlock(); // keychain path — the backend hands out the buffer
    assert.ok(keychain.lastReturned !== null, "the keychain handed out a K_os buffer");
    assert.equal(
      keychain.lastReturned!.every((byte) => byte === 0),
      true,
      "RV6-REQ-6: K_os must be zeroized immediately after master-key decryption",
    );
  });

  // -------------------------------------------------------------------------
  // Requirement pins (RV6-REQ-4/5/7/8/9) and structural tests
  // -------------------------------------------------------------------------

  it("RV6-REQ-4: the credential id derives from the data root and carries no secret", () => {
    const id = keychainCredentialId("C:\\some\\data\\root");
    assert.equal(id, `${KEYCHAIN_CREDENTIAL_PREFIX}${id.slice(KEYCHAIN_CREDENTIAL_PREFIX.length)}`);
    assert.match(id, /^omega-sovereign-wallet:[0-9a-f]{16}$/);
    assert.notEqual(keychainCredentialId("root-a"), keychainCredentialId("root-b"));
  });

  it("RV6-REQ-5: the degraded-path opt-in env name is the recorded constant", () => {
    assert.equal(VAULT_FALLBACK_OPT_IN_ENV, "OMEGA_VAULT_ALLOW_PASSPHRASE_FALLBACK");
  });

  it("RV6-REQ-5: every passphrase-fallback unlock emits a redacted security event", async () => {
    const events: VaultSecurityEvent[] = [];
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain, { onSecurityEvent: (event) => events.push(event) });
    await vault.initialize(PASSPHRASE);
    vault.lock();
    keychain.delete(keychainCredentialId(root));

    await vault.unlock(PASSPHRASE, { allowPassphraseFallback: true, mainnetConfigured: true, operatorConfirmed: true });
    assert.equal(events.length, 1);
    assert.equal(events[0].type, "passphrase-fallback-unlock");
    assert.equal(events[0].wrapMethod, "passphrase-fallback");
    assert.equal(events[0].mainnetConfigured, true);
    // No secret material in the event.
    assert.equal(JSON.stringify(events[0]).includes(PASSPHRASE), false);
  });

  it("RV6-REQ-8: migration is idempotent — the second unlock is keychain-first", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    await buildArgon2OnlyFixture(root, PASSPHRASE, false);
    const vault = makeVault(root, keychain);
    const first = await vault.unlock(PASSPHRASE);
    assert.equal(first.migrated, true);
    vault.lock();
    const second = await vault.unlock(); // keychain-first, no passphrase
    assert.equal(second.wrapMethod, "os-keychain");
    assert.equal(second.migrated, undefined);
  });

  it("RV6-REQ-7: v2 backups are refused with the supersession message (envelope v3 only)", async () => {
    const salt = randomBytes(32);
    const masterKey = randomBytes(32);
    const wrappingKey = argon2id(utf8ToBytes(PASSPHRASE), salt, { ...ARGON2, dkLen: 32 });
    let v2Backup: Uint8Array;
    try {
      const nonce = randomBytes(12);
      const mkBlob = new Uint8Array(12 + 48);
      mkBlob.set(nonce, 0);
      mkBlob.set(gcm(wrappingKey, nonce).encrypt(masterKey), 12);
      const payload = encryptUnderMasterKey(masterKey, utf8ToBytes(JSON.stringify({ version: 2, createdAt: new Date().toISOString(), entries: {} })));
      const saltHeader = new Uint8Array(4);
      new DataView(saltHeader.buffer).setUint32(0, salt.length, true);
      const mkHeader = new Uint8Array(4);
      new DataView(mkHeader.buffer).setUint32(0, mkBlob.length, true);
      v2Backup = new Uint8Array(4 + salt.length + 4 + mkBlob.length + payload.length);
      let offset = 0;
      v2Backup.set(saltHeader, offset);
      offset += 4;
      v2Backup.set(salt, offset);
      offset += salt.length;
      v2Backup.set(mkHeader, offset);
      offset += 4;
      v2Backup.set(mkBlob, offset);
      offset += mkBlob.length;
      v2Backup.set(payload, offset);
    } finally {
      zeroBytes(wrappingKey);
    }

    const freshRoot = newRoot();
    const fresh = makeVault(freshRoot);
    await assert.rejects(
      () => fresh.importEncryptedBackup(v2Backup, PASSPHRASE),
      /superseded by OMEGA-DELTA-0301/,
    );
    // Nothing was written by the refused import.
    assert.equal(await new FileBackend(freshRoot).exists("vault/master.key"), false);
  });

  it("RV6-REQ-9: rekey with a wrong passphrase refuses and rotates nothing", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    const credentialId = keychainCredentialId(root);
    const before = keychain.peek(credentialId);
    await assert.rejects(
      () => vault.rekey("wrong passphrase value"),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.DecryptionFailed,
    );
    assert.deepEqual(keychain.peek(credentialId), before, "nothing rotated");
  });

  it("RV6-REQ-9: revoking the keychain entry locks the vault (fail-closed); degraded path still works with opt-in", async () => {
    const root = newRoot();
    const keychain = new InMemoryKeychainBackend();
    const vault = makeVault(root, keychain);
    await vault.initialize(PASSPHRASE);
    await vault.revokeKeychainEntry();
    assert.equal(keychain.has(keychainCredentialId(root)), false);
    vault.lock();

    await assert.rejects(
      () => vault.unlock(),
      (e) => e instanceof Error && (e as { vaultError?: string }).vaultError === VaultError.KeychainUnavailable,
    );
    const degraded = await vault.unlock(PASSPHRASE, { allowPassphraseFallback: true });
    assert.equal(degraded.wrapMethod, "passphrase-fallback");
  });

  it("structural: the serving plane has no static provider import; the real-SDK factory is unreachable from tests", () => {
    const vaultSource = readFileSync(path.join(SRC, "vault", "vault.ts"), "utf8");
    const mainSource = readFileSync(path.join(SRC, "main.ts"), "utf8");
    const osKeychainSource = readFileSync(path.join(SRC, "vault", "os-keychain.ts"), "utf8");
    const keychainSource = readFileSync(path.join(SRC, "vault", "keychain.ts"), "utf8");

    // Serving plane: no STATIC IMPORT of the provider package (LRN-2026-051).
    // (Doc comments may name the package; the import shape is what is pinned.)
    for (const source of [vaultSource, mainSource]) {
      assert.equal(source.includes('from "@napi-rs/keyring"'), false, "serving plane must not statically import the provider");
      assert.equal(source.includes('require("@napi-rs/keyring")'), false, "serving plane must not require the provider");
    }
    // The seam module is the single static import site.
    assert.ok(osKeychainSource.includes('from "@napi-rs/keyring"'), "os-keychain.ts is the provider seam");
    assert.ok(osKeychainSource.includes("createOsKeychainBackend"));
    assert.ok(keychainSource.includes("KeychainBackend"));
    assert.ok(keychainSource.includes(KEYCHAIN_CREDENTIAL_PREFIX));

    // Tests: the real-SDK factory is unreachable from the test suites. The check
    // inspects IMPORT STATEMENTS only (a regex over import lines), so the
    // assertion literals and doc comments in this very file cannot trip it.
    for (const testFile of ["vault-keychain.test.ts", "identity.test.ts", "l402.test.ts", "protocol.test.ts"]) {
      const text = readFileSync(path.join(HERE, testFile), "utf8");
      const providerImports = text
        .split("\n")
        .filter((line) => /^\s*import\s/.test(line) && /@napi-rs\/keyring|vault\/os-keychain/.test(line));
      assert.deepEqual(
        providerImports,
        [],
        `${testFile} must not import the provider or the real-SDK factory (got: ${providerImports.join("; ")})`,
      );
    }
  });
});

/** Encrypt under the vault master key (v2-payload shape for the refusal test). */
function encryptUnderMasterKey(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(plaintext);
  const out = new Uint8Array(24 + ct.length);
  out.set(nonce, 0);
  out.set(ct, 24);
  return out;
}