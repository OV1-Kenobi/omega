// Offline tests for the P12 client-side encryption and ciphertext ledger
// boundary (source-summarization-p12.mjs). All key material and content in
// these tests is synthetic. The AEAD/KDF choices are PROVISIONAL (module
// header); these tests pin the boundary properties, not final crypto approval.

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { test } from "node:test";

import {
  P12_KEY_DOMAIN,
  P12_OPERATOR_FIELDS,
  P12_STATUS_VOCABULARY,
  createP12LedgerStore,
  createUserSalt,
  decryptHistoryEntry,
  derivePurposeKey,
  encryptHistoryEntry,
} from "./source-summarization-p12.mjs";
import {
  createCredentialStoreSigner,
  createInMemoryStorage,
  deriveNpub,
  npubToPublicKeyHex,
  provisionSignerIdentity,
  publicKeyOf,
  schnorrSign,
  schnorrVerify,
} from "./source-summarization-signer.mjs";
import { createSyntheticPaymentAuthority, verifyChallengeToken } from "./source-summarization-l402.mjs";

const SYNTHETIC_HISTORY = JSON.stringify({
  source_url: "https://private.example.test/research-note",
  source_title: "SYNTHETIC_PRIVATE_TITLE",
  question: "SYNTHETIC_PRIVATE_QUESTION",
  answer_excerpt: "SYNTHETIC_PRIVATE_ANSWER",
});

function userKey() {
  return randomBytes(32);
}

test("an entry is exactly the five operator-readable fields; plaintext never appears", () => {
  const salt = createUserSalt();
  const entry = encryptHistoryEntry({
    plaintext: SYNTHETIC_HISTORY,
    keyMaterial: userKey(),
    saltHex: salt,
    userToken: "SYNTHETIC_USER_TOKEN_A",
  });
  assert.deepEqual(Object.keys(entry).sort(), [...P12_OPERATOR_FIELDS].sort());
  const serialized = JSON.stringify(entry);
  assert.equal(serialized.includes("private.example.test"), false);
  assert.equal(serialized.includes("SYNTHETIC_PRIVATE"), false);
  assert.ok(P12_STATUS_VOCABULARY.includes(entry.status));
});

test("round trip decrypts with the user key; wrong key, wrong salt, and tampering fail closed", () => {
  const salt = createUserSalt();
  const key = userKey();
  const entry = encryptHistoryEntry({ plaintext: SYNTHETIC_HISTORY, keyMaterial: key, saltHex: salt, userToken: "SYNTHETIC_USER_TOKEN_A" });
  assert.equal(decryptHistoryEntry({ entry, keyMaterial: key, saltHex: salt }), SYNTHETIC_HISTORY);

  assert.throws(() => decryptHistoryEntry({ entry, keyMaterial: userKey(), saltHex: salt }), /decryption failed/);
  assert.throws(() => decryptHistoryEntry({ entry, keyMaterial: key, saltHex: createUserSalt() }), /decryption failed/);

  const flippedBlob = Buffer.from(entry.ciphertext_blob, "base64");
  flippedBlob[flippedBlob.length - 1] ^= 0x01;
  assert.throws(
    () => decryptHistoryEntry({ entry: { ...entry, ciphertext_blob: flippedBlob.toString("base64") }, keyMaterial: key, saltHex: salt }),
    /decryption failed/,
  );

  // AAD binding (AEAD binding): tampering ANY operator-readable metadata field
  // breaks authentication at decryption time.
  for (const tampered of [
    { ...entry, entry_id: "0197f000-0000-7000-8000-00000000dead" },
    { ...entry, user_token: "SYNTHETIC_USER_TOKEN_B" },
    { ...entry, timestamp: "2027-01-01T00:00:00.000Z" },
    { ...entry, status: "superseded" },
  ]) {
    assert.throws(() => decryptHistoryEntry({ entry: tampered, keyMaterial: key, saltHex: salt }), /decryption failed/);
  }
});

test("every encryption uses a fresh nonce: identical input yields distinct blobs", () => {
  const salt = createUserSalt();
  const key = userKey();
  const first = encryptHistoryEntry({ plaintext: SYNTHETIC_HISTORY, keyMaterial: key, saltHex: salt, userToken: "SYNTHETIC_USER_TOKEN_A", entryId: "fixed-entry", timestamp: "2026-08-17T12:00:00.000Z" });
  const second = encryptHistoryEntry({ plaintext: SYNTHETIC_HISTORY, keyMaterial: key, saltHex: salt, userToken: "SYNTHETIC_USER_TOKEN_A", entryId: "fixed-entry", timestamp: "2026-08-17T12:00:00.000Z" });
  assert.notEqual(first.ciphertext_blob, second.ciphertext_blob);
});

test("the provisional scrypt path round-trips (final Argon2id remains Security-gated)", () => {
  const salt = createUserSalt();
  const entry = encryptHistoryEntry({
    plaintext: SYNTHETIC_HISTORY,
    keyMaterial: "SYNTHETIC_PASSPHRASE_NOT_REAL",
    kdfMode: "scrypt-provisional",
    saltHex: salt,
    userToken: "SYNTHETIC_USER_TOKEN_A",
  });
  assert.equal(
    decryptHistoryEntry({ entry, keyMaterial: "SYNTHETIC_PASSPHRASE_NOT_REAL", kdfMode: "scrypt-provisional", saltHex: salt }),
    SYNTHETIC_HISTORY,
  );
  assert.throws(
    () => decryptHistoryEntry({ entry, keyMaterial: "SYNTHETIC_WRONG_PASSPHRASE", kdfMode: "scrypt-provisional", saltHex: salt }),
    /decryption failed/,
  );
});

test("the store is opt-in default-off and rejects content-bearing or key-bearing entries", () => {
  const store = createP12LedgerStore();
  assert.equal(store.isOptedIn(), false);
  const salt = createUserSalt();
  const entry = encryptHistoryEntry({ plaintext: SYNTHETIC_HISTORY, keyMaterial: userKey(), saltHex: salt, userToken: "SYNTHETIC_USER_TOKEN_A" });
  assert.throws(() => store.append(entry), /opt-in required/);

  store.optIn();
  store.setSalt("SYNTHETIC_USER_TOKEN_A", salt);
  store.append(entry);
  assert.equal(store.listEntries("SYNTHETIC_USER_TOKEN_A").length, 1);

  assert.throws(() => store.append({ ...entry, entry_id: "another-entry", url: "https://private.example.test" }), /non-allowlisted field/);
  assert.throws(() => store.append({ ...entry, entry_id: "another-entry", user_key: "deadbeef" }), /non-allowlisted field/);
  assert.throws(() => store.append({ ...entry, entry_id: "another-entry", passphrase: "SYNTHETIC_PASSPHRASE_NOT_REAL" }), /non-allowlisted field/);
  assert.throws(() => store.append(entry), /entry_id must be unique/);
  assert.throws(() => store.append({ ...entry, entry_id: "another-entry", status: "paid" }), /enumerated vocabulary/);
});

test("per-user salts are unique per user, public by design, and stable for the ledger lifetime", () => {
  const saltA = createUserSalt();
  const saltB = createUserSalt();
  assert.notEqual(saltA, saltB);
  assert.match(saltA, /^[0-9a-f]{32}$/);

  const store = createP12LedgerStore({ optIn: true });
  store.setSalt("SYNTHETIC_USER_TOKEN_A", saltA);
  store.setSalt("SYNTHETIC_USER_TOKEN_B", saltB);
  assert.equal(store.getSalt("SYNTHETIC_USER_TOKEN_A"), saltA);
  assert.equal(store.getSalt("SYNTHETIC_USER_TOKEN_B"), saltB);
  assert.throws(() => store.setSalt("SYNTHETIC_USER_TOKEN_A", createUserSalt()), /re-encryption/);
});

test("opt-out deletes ciphertext and salt together; retention is metadata-only", () => {
  const store = createP12LedgerStore({ optIn: true, maxEntriesPerUser: 2 });
  const salt = createUserSalt();
  const key = userKey();
  store.setSalt("SYNTHETIC_USER_TOKEN_A", salt);
  for (let index = 0; index < 3; index += 1) {
    store.append(
      encryptHistoryEntry({
        plaintext: `${SYNTHETIC_HISTORY}:${index}`,
        keyMaterial: key,
        saltHex: salt,
        userToken: "SYNTHETIC_USER_TOKEN_A",
        entryId: `entry-${index}`,
        timestamp: new Date(Date.parse("2026-08-17T12:00:00.000Z") + index * 1000).toISOString(),
      }),
    );
  }
  // Count-based retention kept the newest 2, decided on timestamps only.
  assert.equal(store.listEntries("SYNTHETIC_USER_TOKEN_A").length, 2);
  assert.deepEqual(
    store.listEntries("SYNTHETIC_USER_TOKEN_A").map((entry) => entry.entry_id),
    ["entry-1", "entry-2"],
  );
  store.optOut("SYNTHETIC_USER_TOKEN_A");
  assert.equal(store.listEntries("SYNTHETIC_USER_TOKEN_A").length, 0);
  assert.equal(store.getSalt("SYNTHETIC_USER_TOKEN_A"), null);
});

test("simulated store exfiltration yields no plaintext and no key material", () => {
  const store = createP12LedgerStore({ optIn: true });
  const salt = createUserSalt();
  const key = userKey();
  store.setSalt("SYNTHETIC_USER_TOKEN_A", salt);
  store.append(encryptHistoryEntry({ plaintext: SYNTHETIC_HISTORY, keyMaterial: key, saltHex: salt, userToken: "SYNTHETIC_USER_TOKEN_A" }));
  const exfiltrated = JSON.stringify({
    entries: store.listEntries("SYNTHETIC_USER_TOKEN_A"),
    salt: store.getSalt("SYNTHETIC_USER_TOKEN_A"),
  });
  assert.equal(exfiltrated.includes("private.example.test"), false);
  assert.equal(exfiltrated.includes("SYNTHETIC_PRIVATE"), false);
  assert.equal(exfiltrated.includes(key.toString("hex")), false);
  assert.equal(exfiltrated.includes(key.toString("base64")), false);
});

test("the store surface exposes no key-accepting API (no server-side key path)", () => {
  const store = createP12LedgerStore({ optIn: true });
  const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(store)).concat(Object.keys(store));
  for (const name of methods) {
    assert.doesNotMatch(name, /key|passphrase|crypt|wrap|escrow|recover|derive/i, `store method ${name} must not suggest a key path`);
  }
});

test("p12 keys and signing keys occupy separate domains", async () => {
  const salt = createUserSalt();
  // Synthetic shared root entropy for the derivation-separation half.
  const sharedRoot = randomBytes(32);

  // 1) Derivation separation at the p12 HKDF seam (the property the module
  // header promises): identical root entropy derives distinct keys per
  // purpose string, and the ledger key is never the raw root bytes — the
  // byte format a BIP-340 signer key takes.
  const ledgerKey = derivePurposeKey(sharedRoot, salt, P12_KEY_DOMAIN);
  const receiptDomainKey = derivePurposeKey(sharedRoot, salt, "receipt-signer-bip340-v1");
  const authorityDomainKey = derivePurposeKey(sharedRoot, salt, "l402-authority-ed25519-v1");
  assert.equal(ledgerKey.equals(sharedRoot), false);
  assert.equal(ledgerKey.equals(receiptDomainKey), false);
  assert.equal(ledgerKey.equals(authorityDomainKey), false);
  assert.equal(receiptDomainKey.equals(authorityDomainKey), false);

  // 2) Receipt-signer direction, both ways, against a real provisioned
  // service identity (in-memory test storage seam; no DPAPI round trip).
  const storage = createInMemoryStorage();
  const serviceNpub = await provisionSignerIdentity({ storage });
  const signer = createCredentialStoreSigner({ storage });
  const digest = createHash("sha256").update("SYNTHETIC_KEY_SEPARATION_DIGEST").digest("hex");
  const signed = await signer.sign({ artifact_digest: digest });

  const ledgerKeyHex = publicKeyOf(ledgerKey);
  const ledgerKeyNpub = deriveNpub(Buffer.from(ledgerKeyHex, "hex"));
  assert.notEqual(ledgerKeyNpub, serviceNpub);
  assert.equal(npubToPublicKeyHex(ledgerKeyNpub), ledgerKeyHex);
  // The service signature does not verify as p12-derived key material: the
  // receipt-signer verify API rejects the foreign identity, and the pure
  // BIP-340 check under the p12 key's public key fails.
  assert.equal(
    await signer.verify({ artifact_digest: digest, publisher_signature: signed.publisher_signature, publisher_npub: ledgerKeyNpub }),
    false,
  );
  assert.equal(
    schnorrVerify(Buffer.from(digest, "hex"), Buffer.from(ledgerKeyHex, "hex"), Buffer.from(signed.publisher_signature, "hex")),
    false,
  );
  // And a signature MADE WITH the p12 ledger key does not verify as the
  // service identity.
  const forgedWithLedgerKey = schnorrSign(Buffer.from(digest, "hex"), ledgerKey).toString("hex");
  assert.equal(
    await signer.verify({ artifact_digest: digest, publisher_signature: forgedWithLedgerKey, publisher_npub: serviceNpub }),
    false,
  );

  // 3) P12 direction: receipt-signing key material (a valid BIP-340 scalar)
  // does not open the ledger.
  const signerDomainScalar = randomBytes(32);
  publicKeyOf(signerDomainScalar); // throws unless this is valid signer-format key material
  const entry = encryptHistoryEntry({
    plaintext: SYNTHETIC_HISTORY,
    keyMaterial: randomBytes(32),
    saltHex: salt,
    userToken: "SYNTHETIC_USER_TOKEN_A",
  });
  assert.throws(() => decryptHistoryEntry({ entry, keyMaterial: signerDomainScalar, saltHex: salt }), /decryption failed/);

  // 4) Authority direction: authority key material in its only exportable
  // byte form (PKCS#8 DER, never 32 bytes) is rejected by the p12 key
  // derivation, and an authority token verifies only under its own key. The
  // authority surface accepts KeyObject pairs only — there is no raw-byte
  // path through which p12 material could enter it (structural; no
  // byte-to-KeyObject conversion exists anywhere in these modules).
  const authorityKeyPair = generateKeyPairSync("ed25519");
  const authority = createSyntheticPaymentAuthority({ ed25519KeyPair: authorityKeyPair });
  const { macaroon } = authority.issueChallenge({
    capability: "source-summarization",
    version: "0.1.0",
    amountSats: 21,
    serviceIdentity: serviceNpub,
  });
  assert.equal(verifyChallengeToken(macaroon, authority.publicKeyPem).ok, true);
  const foreignAuthority = createSyntheticPaymentAuthority();
  assert.equal(verifyChallengeToken(macaroon, foreignAuthority.publicKeyPem).ok, false);
  const exportedAuthorityKey = authorityKeyPair.privateKey.export({ type: "pkcs8", format: "der" });
  assert.ok(Buffer.isBuffer(exportedAuthorityKey));
  assert.notEqual(exportedAuthorityKey.length, 32);
  assert.throws(() => derivePurposeKey(exportedAuthorityKey, salt, P12_KEY_DOMAIN), /32 bytes/);
});
