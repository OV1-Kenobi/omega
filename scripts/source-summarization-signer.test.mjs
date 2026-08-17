// Offline test-runner coverage for the local publisher signer adapter
// (`scripts/source-summarization-signer.mjs`), WP2 Chunk D.
//
// Storage: tests use the TEST-ONLY in-memory storage seam so no real DPAPI
// round trip is required; one optional real-DPAPI smoke test runs only when
// PowerShell with ProtectedData is verifiably available and marks itself
// skipped otherwise. No keys or credentials appear in any test output or
// artifact.

import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  WIRE_PREFIX,
  createCredentialStoreSigner,
  createDpapiFileStorage,
  createInMemoryStorage,
  defaultStorageDir,
  deriveNpub,
  npubToPublicKeyHex,
  probePowerShellAvailability,
  provisionSignerIdentity,
  publicKeyOf,
  schnorrSign,
  schnorrVerify,
} from "./source-summarization-signer.mjs";

const SCRIPT_PATH = new URL("./source-summarization-signer.mjs", import.meta.url);
const SYNTHETIC_DIGEST = "ab".repeat(32);

// Independent vectors from `crates/omega_identity/src/contract.rs` (read-only;
// produced by the nostr/secp256k1 Rust crates, which are NOT this module):
const CONTRACT_PUBLIC_KEY_HEX = "f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785";
const CONTRACT_NPUB = "npub1lpkyfgk7jhv3fx63c63f4l4thgnycx8zlf7ynh5ngf9qc455w7zs7s8hua";
const CONTRACT_EVENT_ID_HEX = "2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45";
const CONTRACT_SIGNATURE_HEX =
  "a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd";

// Deterministic signing KAT recorded 2026-08-17 from this module's own
// implementation (fixed key, fixed digest, zero auxiliary randomness): locks
// the signing path against accidental change. The independent verification
// anchor for the verify path is the Rust-vector test below.
const KAT_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const KAT_DIGEST_HEX = "6ba1047984405bd6694d6293e5a5a09c81cdcd92c035dff325268a6eed5f6f2e";
const KAT_PUBKEY_HEX = "84bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0";
const KAT_SIGNATURE_HEX =
  "20b71f890c13dbffc118800293b3143667bb964d9ed7d7b475da22b2d5baba243b210caa334c835479e9d3a2fbc3e872bf8b7e11ff9a8e6ada43918b9f7608fc";

function provisionedMemorySigner() {
  const storage = createInMemoryStorage();
  const provision = provisionSignerIdentity({ storage });
  const signer = createCredentialStoreSigner({ storage });
  return { storage, provision, signer };
}

test("provisioning creates exactly one identity and the npub is stable across reloads", async () => {
  const storage = createInMemoryStorage();
  const npub = await provisionSignerIdentity({ storage });
  assert.equal(typeof npub, "string");
  assert.match(npub, /^npub1[0-9a-z]+$/);

  const firstSigner = createCredentialStoreSigner({ storage });
  const first = await firstSigner.sign({ artifact_digest: SYNTHETIC_DIGEST });
  assert.equal(first.publisher_npub, npub);
  assert.equal(firstSigner.publisher_npub, npub);

  // A second signer instance over the same store is a fresh load ("reload")
  // and must derive the identical identity.
  const secondSigner = createCredentialStoreSigner({ storage });
  const second = await secondSigner.sign({ artifact_digest: SYNTHETIC_DIGEST });
  assert.equal(second.publisher_npub, npub);
  assert.equal(secondSigner.publisher_npub, npub);

  // One-time provisioning: a second provision must refuse, never regenerate.
  await assert.rejects(
    provisionSignerIdentity({ storage }),
    (error) => error.code === "identity_already_provisioned",
  );
});

test("sign returns a 128-hex BIP-340 signature and the service npub; verify round-trips", async () => {
  const { provision, signer } = provisionedMemorySigner();
  const npub = await provision;
  const signed = await signer.sign({ artifact_digest: SYNTHETIC_DIGEST });
  assert.match(signed.publisher_signature, /^[0-9a-f]{128}$/);
  assert.equal(signed.publisher_npub, npub);
  const verified = await signer.verify({
    artifact_digest: SYNTHETIC_DIGEST,
    publisher_signature: signed.publisher_signature,
    publisher_npub: signed.publisher_npub,
  });
  assert.equal(verified, true);
});

test("a tampered signature, wrong npub, or malformed inputs fail verification with false", async () => {
  const { provision, signer } = provisionedMemorySigner();
  const npub = await provision;
  const { publisher_signature, publisher_npub } = await signer.sign({ artifact_digest: SYNTHETIC_DIGEST });

  const flipped = publisher_signature.slice(0, -1) + (publisher_signature.endsWith("0") ? "1" : "0");
  assert.equal(
    await signer.verify({ artifact_digest: SYNTHETIC_DIGEST, publisher_signature: flipped, publisher_npub }),
    false,
  );
  assert.equal(
    await signer.verify({ artifact_digest: SYNTHETIC_DIGEST, publisher_signature, publisher_npub: "npub1wrongidentity" }),
    false,
  );
  assert.equal(
    await signer.verify({ artifact_digest: SYNTHETIC_DIGEST, publisher_signature: "not-a-signature", publisher_npub }),
    false,
  );
  // A malformed digest is an input-shape violation and fails closed like sign().
  await assert.rejects(
    signer.verify({ artifact_digest: "not-a-digest", publisher_signature, publisher_npub }),
    (error) => error.code === "invalid_digest",
  );
  // Even a mathematically valid signature produced by a DIFFERENT identity must
  // fail the same-identity rule.
  const other = createInMemoryStorage();
  await provisionSignerIdentity({ storage: other });
  const otherSigner = createCredentialStoreSigner({ storage: other });
  const foreign = await otherSigner.sign({ artifact_digest: SYNTHETIC_DIGEST });
  assert.notEqual(npub, foreign.publisher_npub);
  assert.equal(
    await signer.verify({
      artifact_digest: SYNTHETIC_DIGEST,
      publisher_signature: foreign.publisher_signature,
      publisher_npub: foreign.publisher_npub,
    }),
    false,
  );
});

test("an unprovisioned signer fails closed and never generates an identity on sign", async () => {
  const storage = createInMemoryStorage();
  const signer = createCredentialStoreSigner({ storage });
  await assert.rejects(
    signer.sign({ artifact_digest: SYNTHETIC_DIGEST }),
    (error) => error.code === "publisher_signer_unavailable",
  );
  await assert.rejects(
    signer.verify({
      artifact_digest: SYNTHETIC_DIGEST,
      publisher_signature: "0".repeat(128),
      publisher_npub: "npub1x",
    }),
    (error) => error.code === "publisher_signer_unavailable",
  );
  // No silent generation: the store must still be empty.
  assert.equal(await storage.exists(), false);
  assert.equal(storage.inspectWire(), null);
});

test("npub derivation matches the omega_identity contract vector and round-trips", () => {
  const encoded = deriveNpub(Buffer.from(CONTRACT_PUBLIC_KEY_HEX, "hex"));
  assert.equal(encoded, CONTRACT_NPUB);
  assert.equal(npubToPublicKeyHex(CONTRACT_NPUB), CONTRACT_PUBLIC_KEY_HEX);

  // Random-key round trip: encode -> decode must recover the x-only key.
  const probeKey = Buffer.alloc(32, 0x42);
  assert.equal(npubToPublicKeyHex(deriveNpub(probeKey)), probeKey.toString("hex"));

  assert.throws(() => npubToPublicKeyHex("npub1invalid"), (error) => error.code === "invalid_npub");
  assert.throws(() => npubToPublicKeyHex("NPUB1INVALIDUPPERCASEIDENTITYSTRING"), (error) => error.code === "invalid_npub");
});

test("BIP-340 verification accepts the independent Rust-crate vector and rejects tampering", () => {
  const message = Buffer.from(CONTRACT_EVENT_ID_HEX, "hex");
  const publicKey = Buffer.from(CONTRACT_PUBLIC_KEY_HEX, "hex");
  const signature = Buffer.from(CONTRACT_SIGNATURE_HEX, "hex");
  assert.equal(schnorrVerify(message, publicKey, signature), true);
  const tampered = Buffer.from(signature);
  tampered[0] ^= 0x01;
  assert.equal(schnorrVerify(message, publicKey, tampered), false);
  assert.equal(schnorrVerify(message, Buffer.alloc(32, 0), signature), false);
});

test("deterministic signing known-answer test locks the sign path", () => {
  const key = Buffer.from(KAT_KEY_HEX, "hex");
  const message = Buffer.from(KAT_DIGEST_HEX, "hex");
  const aux = Buffer.alloc(32, 0);
  const signature = schnorrSign(message, key, aux);
  assert.equal(signature.toString("hex"), KAT_SIGNATURE_HEX);
  assert.equal(publicKeyOf(key), KAT_PUBKEY_HEX);
  assert.equal(schnorrVerify(message, Buffer.from(KAT_PUBKEY_HEX, "hex"), signature), true);
  // Different auxiliary randomness must change the signature (nonce variability).
  const different = schnorrSign(message, key, Buffer.alloc(32, 1));
  assert.notEqual(different.toString("hex"), KAT_SIGNATURE_HEX);
});

test("corrupt or foreign stored data fails closed and never regenerates silently", async () => {
  const storage = createInMemoryStorage();
  await provisionSignerIdentity({ storage });
  const signer = createCredentialStoreSigner({ storage });
  const before = await signer.sign({ artifact_digest: SYNTHETIC_DIGEST });

  storage.replaceWire("OMEGA-SS:v1:%%%not-base64%%%");
  const corruptSigner = createCredentialStoreSigner({ storage });
  await assert.rejects(
    corruptSigner.sign({ artifact_digest: SYNTHETIC_DIGEST }),
    (error) => error.code === "credential_store_corrupt",
  );
  await assert.rejects(
    corruptSigner.verify({
      artifact_digest: SYNTHETIC_DIGEST,
      publisher_signature: before.publisher_signature,
      publisher_npub: before.publisher_npub,
    }),
    (error) => error.code === "credential_store_corrupt",
  );

  storage.replaceWire("garbage-without-prefix");
  const prefixlessSigner = createCredentialStoreSigner({ storage });
  await assert.rejects(
    prefixlessSigner.sign({ artifact_digest: SYNTHETIC_DIGEST }),
    (error) => error.code === "credential_store_corrupt",
  );

  // A foreign (wrong-size) blob also fails closed.
  storage.replaceWire(`${WIRE_PREFIX}${Buffer.from([1, 2, 3]).toString("base64")}\n`);
  const wrongSizeSigner = createCredentialStoreSigner({ storage });
  await assert.rejects(
    wrongSizeSigner.sign({ artifact_digest: SYNTHETIC_DIGEST }),
    (error) => error.code === "credential_store_corrupt",
  );
});

test("the secret never appears in storage, signing output, or provisioning output", async () => {
  const knownKey = Buffer.from(Array.from({ length: 32 }, (_, index) => 0x41 + index));
  const knownKeyHex = knownKey.toString("hex");
  const knownKeyBase64 = knownKey.toString("base64");

  const storage = createInMemoryStorage();
  await storage.write(knownKey);
  const wire = storage.inspectWire();
  assert.match(wire, /^OMEGA-SS:v1:/);
  assert.equal(wire.includes(knownKeyHex), false);
  assert.equal(wire.includes(knownKeyBase64), false);
  const unwrapped = Buffer.from(wire.slice(WIRE_PREFIX.length).trim(), "base64");
  assert.notDeepEqual(unwrapped, knownKey);

  const signer = createCredentialStoreSigner({ storage });
  const signed = await signer.sign({ artifact_digest: SYNTHETIC_DIGEST });
  for (const text of [signed.publisher_signature, signed.publisher_npub, JSON.stringify(signed)]) {
    assert.equal(text.includes(knownKeyHex), false);
    assert.equal(text.includes(knownKeyBase64), false);
  }

  const provisioned = createInMemoryStorage();
  const npub = await provisionSignerIdentity({ storage: provisioned });
  assert.equal(typeof npub, "string");
  assert.match(npub, /^npub1/);
  // Provisioning output is the public npub ONLY: decoding it yields a valid
  // public key, and the wire stores 32 protected bytes, not a readable key.
  assert.match(npubToPublicKeyHex(npub), /^[0-9a-f]{64}$/);
  assert.equal(Buffer.from(provisioned.inspectWire().slice(WIRE_PREFIX.length).trim(), "base64").length, 32);
});

test("real DPAPI file storage round trip", { skip: false }, async (context) => {
  const powershell = await probePowerShellAvailability();
  if (!powershell) {
    context.skip("PowerShell with ProtectedData is unavailable; the real DPAPI round trip is skipped.");
    return;
  }
  const storageDir = mkdtempSync(join(tmpdir(), "omega-ss-dpapi-"));
  try {
    const knownKey = Buffer.from(Array.from({ length: 32 }, (_, index) => 0x02 * (index + 1)));
    const storage = createDpapiFileStorage({ storageDir });
    assert.equal(await storage.exists(), false);
    await storage.write(knownKey);
    assert.equal(await storage.exists(), true);
    const wire = readFileSync(join(storageDir, "signer.key"), "utf8");
    assert.match(wire, /^OMEGA-SS:v1:/);
    assert.equal(wire.includes(knownKey.toString("hex")), false);
    const restored = await storage.read();
    assert.deepEqual(restored, knownKey);
    // A second storage over the same dir (a fresh session) reads back the same.
    const reloaded = createDpapiFileStorage({ storageDir });
    assert.deepEqual(await reloaded.read(), knownKey);
  } finally {
    rmSync(storageDir, { recursive: true, force: true });
  }
});

test("the signer module has no network client or egress call", () => {
  const source = readFileSync(SCRIPT_PATH, "utf8");
  assert.doesNotMatch(source, /from ["']node:(?:http|https|net|dns)(?:["'])/);
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.doesNotMatch(source, /new\s+WebSocket\s*\(/);
});

test("default storage dir resolves under the user profile or env override", () => {
  const dir = defaultStorageDir();
  assert.equal(typeof dir, "string");
  assert.ok(dir.length > 0);
  assert.ok(dir.includes("source-summarization"));
  assert.equal(process.env.OMEGA_SOURCE_SUMMARIZATION_SIGNER_DIR !== undefined, dir === process.env.OMEGA_SOURCE_SUMMARIZATION_SIGNER_DIR);
});