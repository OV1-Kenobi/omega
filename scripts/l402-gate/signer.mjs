#!/usr/bin/env node

// Local publisher signer adapter for the Omega Source Summarization MCP server.
//
// WP2 Chunk D (implementation-plan Chunk D): a dependency-free Node module that
// implements the signer contract injected into `createServer` in
// `source-summarization-mcp.mjs`. It produces BIP-340 Schnorr signatures over
// the canonical artifact digest under a dedicated SERVICE identity, whose secret
// key is generated from the OS CSPRNG on first provisioning and stored ONLY in a
// Windows user-scope DPAPI-protected file OUTSIDE the repository.
//
// Identity and security boundary (PRD P2, WP1 section 3.4, #314 rules 7/9/10):
//   - This identity is the service-scoped Nostr identity of THIS MCP ("this
//     MCP's Nostr ID"). It is NOT the founder's personal Omega account key.
//     One npub binds artifacts, receipts, and the M9 capability record.
//   - The secret key never enters the repo, never appears in code, stdout,
//     logs, or artifacts, and is never logged or rendered anywhere. Only the
//     public npub leaves this module (provisioning result, signer output).
//   - Provisioning is one-time: `provisionSignerIdentity` refuses to regenerate
//     over an existing identity (no silent rotation). Missing or corrupt
//     ciphertext fails closed with a structured error stating that provisioning
//     is required. DPAPI unavailability fails closed; there is NO plaintext
//     fallback (agent-and-skill-security-policy: no bypass modes).
//   - The signer loads its identity lazily at first cryptographic use;
//     construction performs no I/O and never throws, so an unprovisioned server
//     still starts and tools fail closed with `publisher_signer_unavailable`
//     (preserving pre-Chunk-D behavior).
//
// Key storage:
//   - Default file: %APPDATA%\Omega Dev\source-summarization\signer.key
//     (overridable via OMEGA_SOURCE_SUMMARIZATION_SIGNER_DIR for tests/dev).
//   - Wire format: "OMEGA-SS:v1:<base64(DPAPI ciphertext)>" - a versioned,
//     corruption-detectable envelope.
//   - DPAPI is invoked through a bounded `execFile` of pwsh/powershell with a
//     fixed minimal script (below). The secret crosses the process boundary
//     only over private pipes owned by this process (stdin in, captured stdout
//     out); it is never echoed to the console, written to a file in the clear,
//     or placed on the command line (command lines are visible to other local
//     processes; pipes are not).
//   - Best-effort: after writing the key file, ICACLS removes inherited ACEs
//     and grants the current user full control without elevation. If the ACL
//     step fails the NTFS default applies (user-profile files are normally
//     user-only); hardening failure never blocks provisioning and never lowers
//     the cryptographic bar.
//
// Testability: `createInMemoryStorage()` is a clearly labeled TEST-ONLY storage
// seam that lets the offline suite cover identity lifecycle, signing, and
// fail-closed behavior without a real DPAPI round trip. The real DPAPI + file
// path is covered by an optional smoke test that skips cleanly when PowerShell
// is unavailable, plus the provisioning round used for the service identity.

import { createHash, randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Structured fail-closed errors
// ---------------------------------------------------------------------------

class StoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "StoreError";
    this.code = code;
  }
}

function corruptStore(message) {
  return new StoreError("credential_store_corrupt", message);
}

function unprovisioned() {
  return new StoreError(
    "publisher_signer_unavailable",
    "No local publisher signer identity is provisioned; provisioning is required before signing or verification.",
  );
}

// ---------------------------------------------------------------------------
// Minimal secp256k1 + BIP-340 Schnorr (BigInt affine math).
// Copied from the in-repo precedent `scripts/market-demo-mcp.mjs` (the repo's
// own code, lines 38-148), kept self-contained. The sign path is unchanged
// except that the auxiliary randomness is an optional explicit parameter so a
// deterministic known-answer test can be recorded; the production signer always
// passes fresh OS randomness, as the precedent does.
// ---------------------------------------------------------------------------

const FIELD_P = 2n ** 256n - 2n ** 32n - 977n;
const CURVE_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GENERATOR = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
];

const fieldMod = (a, m = FIELD_P) => ((a % m) + m) % m;

function modPow(base, exponent, modulus) {
  let result = 1n;
  base = fieldMod(base, modulus);
  while (exponent > 0n) {
    if (exponent & 1n) {
      result = (result * base) % modulus;
    }
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

const modInverse = (a, m = FIELD_P) => modPow(fieldMod(a, m), m - 2n, m);

function pointAdd(a, b) {
  if (!a) return b;
  if (!b) return a;
  const [ax, ay] = a;
  const [bx, by] = b;
  if (ax === bx) {
    if (fieldMod(ay + by) === 0n) {
      return null;
    }
    const lambda = fieldMod(3n * ax * ax * modInverse(2n * ay));
    const x = fieldMod(lambda * lambda - 2n * ax);
    return [x, fieldMod(lambda * (ax - x) - ay)];
  }
  const lambda = fieldMod((by - ay) * modInverse(bx - ax));
  const x = fieldMod(lambda * lambda - ax - bx);
  return [x, fieldMod(lambda * (ax - x) - ay)];
}

function pointMul(point, scalar) {
  let result = null;
  let addend = point;
  while (scalar > 0n) {
    if (scalar & 1n) {
      result = pointAdd(result, addend);
    }
    addend = pointAdd(addend, addend);
    scalar >>= 1n;
  }
  return result;
}

const bigToBytes = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex");
const bytesToBig = (buffer) => BigInt("0x" + buffer.toString("hex"));
const sha256 = (...buffers) =>
  createHash("sha256").update(Buffer.concat(buffers)).digest();

function taggedHash(tag, ...buffers) {
  const tagDigest = sha256(Buffer.from(tag));
  return sha256(tagDigest, tagDigest, ...buffers);
}

export function schnorrSign(message, secretKey, aux = randomBytes(32)) {
  if (message.length !== 32 || secretKey.length !== 32 || aux.length !== 32) {
    throw new StoreError("invalid_input", "Schnorr signing needs 32-byte message, key, and aux.");
  }
  let d = bytesToBig(secretKey);
  if (d === 0n || d >= CURVE_N) {
    throw new StoreError("invalid_key", "secret key out of range");
  }
  const publicPoint = pointMul(GENERATOR, d);
  if (publicPoint[1] % 2n !== 0n) {
    d = CURVE_N - d;
  }
  const publicX = bigToBytes(publicPoint[0]);
  const masked = bigToBytes(
    d ^ bytesToBig(taggedHash("BIP0340/aux", aux)),
  );
  let k = fieldMod(
    bytesToBig(taggedHash("BIP0340/nonce", masked, publicX, message)),
    CURVE_N,
  );
  if (k === 0n) {
    throw new StoreError("invalid_nonce", "zero nonce");
  }
  const noncePoint = pointMul(GENERATOR, k);
  if (noncePoint[1] % 2n !== 0n) {
    k = CURVE_N - k;
  }
  const challenge = fieldMod(
    bytesToBig(
      taggedHash("BIP0340/challenge", bigToBytes(noncePoint[0]), publicX, message),
    ),
    CURVE_N,
  );
  return Buffer.concat([
    bigToBytes(noncePoint[0]),
    bigToBytes(fieldMod(k + challenge * d, CURVE_N)),
  ]);
}

export function publicKeyOf(secretKey) {
  if (secretKey.length !== 32) {
    throw new StoreError("invalid_key", "a BIP-340 secret key must be 32 bytes");
  }
  const point = pointMul(GENERATOR, bytesToBig(secretKey));
  return bigToBytes(point[0]).toString("hex");
}

// Lift an x-coordinate to the curve point with even y (BIP-340 lift_x).
function liftX(x) {
  if (x >= FIELD_P) return null;
  const ySquared = fieldMod(x * x * x + 7n);
  let y = modPow(ySquared, (FIELD_P + 1n) / 4n, FIELD_P);
  if (fieldMod(y * y) !== ySquared) return null;
  if (y % 2n !== 0n) y = FIELD_P - y;
  return [x, y];
}

// BIP-340 verification over a 32-byte message with the x-only public key.
// Follows the specification: lift_x(r), lift_x(pubkey) with even y,
// e = tagged_hash("BIP0340/challenge", r || pubkey || m) mod n,
// R = s*G - e*P; accepted iff R has even y and its x equals r.
export function schnorrVerify(message, publicKeyX, signature) {
  if (
    message.length !== 32 ||
    publicKeyX.length !== 32 ||
    signature.length !== 64
  ) {
    return false;
  }
  const r = bytesToBig(signature.subarray(0, 32));
  const s = bytesToBig(signature.subarray(32));
  if (r >= FIELD_P || s >= CURVE_N) return false;
  if (!liftX(r)) return false;
  const publicPoint = liftX(bytesToBig(publicKeyX));
  if (!publicPoint) return false;
  const challenge = fieldMod(
    bytesToBig(
      taggedHash("BIP0340/challenge", signature.subarray(0, 32), publicKeyX, message),
    ),
    CURVE_N,
  );
  const negativeChallenge = challenge === 0n ? 0n : CURVE_N - challenge;
  const sPoint = pointMul(GENERATOR, s);
  const ePoint = pointMul(publicPoint, negativeChallenge);
  const sum = pointAdd(sPoint, ePoint);
  if (!sum) return false;
  if (sum[1] % 2n !== 0n) return false;
  return sum[0] === r;
}

// ---------------------------------------------------------------------------
// Minimal bech32 (NIP-19 npub encoding), with checksum verification.
// ---------------------------------------------------------------------------

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) {
      if (((top >>> index) & 1) === 1) chk ^= BECH32_GENERATORS[index];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const result = [];
  for (let index = 0; index < hrp.length; index += 1) {
    result.push(hrp.charCodeAt(index) >> 5);
  }
  result.push(0);
  for (let index = 0; index < hrp.length; index += 1) {
    result.push(hrp.charCodeAt(index) & 31);
  }
  return result;
}

function bech32CreateChecksum(hrp, data) {
  const polymodValue = bech32Polymod(bech32HrpExpand(hrp).concat(data, [0, 0, 0, 0, 0, 0])) ^ 1;
  const checksum = [];
  for (let index = 0; index < 6; index += 1) {
    checksum.push((polymodValue >>> (5 * (5 - index))) & 31);
  }
  return checksum;
}

function convertBits(value, fromBits, toBits, pad) {
  let accumulator = 0;
  let bits = 0;
  const result = [];
  const maxValue = (1 << toBits) - 1;
  for (const entry of value) {
    accumulator = (accumulator << fromBits) | entry;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((accumulator >> bits) & maxValue);
    }
  }
  if (pad) {
    if (bits > 0) result.push((accumulator << (toBits - bits)) & maxValue);
  } else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue) !== 0) {
    throw new StoreError("invalid_encoding", "bech32 data does not decode without padding.");
  }
  return result;
}

function bech32Encode(hrp, data) {
  const combined = data.concat(bech32CreateChecksum(hrp, data));
  return `${hrp}1${combined.map((word) => BECH32_CHARSET[word]).join("")}`;
}

function bech32Decode(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 90) {
    throw new StoreError("invalid_npub", "The npub has an invalid length.");
  }
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  if (hasLower && hasUpper) {
    throw new StoreError("invalid_npub", "The npub mixes character cases.");
  }
  const text = value.toLowerCase();
  const separator = text.lastIndexOf("1");
  if (separator < 1 || separator + 7 > text.length) {
    throw new StoreError("invalid_npub", "The npub has no valid separator.");
  }
  const hrp = text.slice(0, separator);
  const dataPart = text.slice(separator + 1);
  const data = [];
  for (const character of dataPart) {
    const word = BECH32_CHARSET.indexOf(character);
    if (word === -1) throw new StoreError("invalid_npub", "The npub uses an invalid character.");
    data.push(word);
  }
  if (bech32Polymod(bech32HrpExpand(hrp).concat(data)) !== 1) {
    throw new StoreError("invalid_npub", "The npub checksum does not verify.");
  }
  const words = data.slice(0, -6);
  const bytes = convertBits(words, 5, 8, false);
  return { hrp, words, bytes };
}

export function deriveNpub(publicKeyBytes) {
  if (!Buffer.isBuffer(publicKeyBytes) || publicKeyBytes.length !== 32) {
    throw new StoreError("invalid_public_key", "An npub derivation needs a 32-byte x-only public key.");
  }
  return bech32Encode("npub", convertBits([...publicKeyBytes], 8, 5, true));
}

export function npubToPublicKeyHex(npub) {
  const decoded = bech32Decode(npub);
  if (decoded.hrp !== "npub") {
    throw new StoreError("invalid_npub", "The publisher identity is not an npub.");
  }
  if (decoded.bytes.length !== 32) {
    throw new StoreError("invalid_npub", "The npub does not carry a 32-byte public key.");
  }
  return Buffer.from(decoded.bytes).toString("hex");
}

// ---------------------------------------------------------------------------
// Credential storage (DPAPI via a bounded PowerShell shim)
// ---------------------------------------------------------------------------

export const WIRE_PREFIX = "OMEGA-SS:v1:";
const KEY_FILE_NAME = "signer.key";
const WIRE_MAX_CHARS = 8192;

// Fixed, minimal PowerShell shims (two static scripts; the operation is baked
// in because pwsh -EncodedCommand does not forward positional arguments). Each
// is sent via -EncodedCommand (UTF-16LE base64), which is immune to Windows
// command-line quoting. The operating secret crosses the process boundary over
// private pipes only: encrypt reads raw key bytes from stdin and emits the DPAPI
// ciphertext as base64 on stdout; decrypt reads the base64 ciphertext on stdin
// and emits the key as lowercase hex on stdout. Neither direction ever prints
// the raw key to the console, and Node captures both stdout streams privately
// (never logged, never rendered).
const DPAPI_SHIM_HEADER = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
`;

const DPAPI_ENCRYPT_SHIM = `${DPAPI_SHIM_HEADER}
$stream = [Console]::OpenStandardInput()
$buffer = New-Object byte[] 65536
$memory = New-Object System.IO.MemoryStream
while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) { $memory.Write($buffer, 0, $read) }
$cipher = [System.Security.Cryptography.ProtectedData]::Protect($memory.ToArray(), $null, $scope)
[Console]::Out.Write([Convert]::ToBase64String($cipher))
`;

const DPAPI_DECRYPT_SHIM = `${DPAPI_SHIM_HEADER}
$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput())
$line = $reader.ReadLine()
if ($null -eq $line -or $line.Length -eq 0) { throw 'empty ciphertext input' }
$cipher = [Convert]::FromBase64String($line.Trim())
$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($cipher, $null, $scope)
$hex = ''
foreach ($byte in $plain) { $hex = $hex + $byte.ToString('x2') }
[Console]::Out.Write($hex)
`;

const DPAPI_SCRIPTS = {
  encrypt: DPAPI_ENCRYPT_SHIM,
  decrypt: DPAPI_DECRYPT_SHIM,
};

function encodePowerShellScript(script) {
  return Buffer.from(script, "utf16le").toString("base64");
}

const PS_PROBE_SCRIPT =
  "Add-Type -AssemblyName System.Security.Cryptography.ProtectedData; [void][System.Security.Cryptography.ProtectedData]; 'PROBE_OK'";

let cachedPowerShell = undefined;

function runBoundedShell(executable, args, stdinInput, failureCode = "credential_store_unavailable") {
  return new Promise((resolvePromise, rejectPromise) => {
    let child;
    try {
      child = execFile(
        executable,
        args,
        { windowsHide: true, maxBuffer: 1024 * 1024, timeout: 30000 },
        (error, stdout) => {
          if (error) {
            rejectPromise(new StoreError(failureCode, "The OS credential store operation failed."));
            return;
          }
          resolvePromise(stdout);
        },
      );
    } catch {
      rejectPromise(new StoreError(failureCode, "The OS credential store operation failed."));
      return;
    }
    child.stdin.end(stdinInput);
  });
}

// Returns the path of a working PowerShell (pwsh preferred, then powershell) or
// null when neither provides the DPAPI ProtectedData type. Cached per process.
export async function probePowerShellAvailability() {
  if (cachedPowerShell !== undefined) return cachedPowerShell;
  for (const candidate of ["pwsh", "powershell"]) {
    try {
      const stdout = await runBoundedShell(
        candidate,
        ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellScript(PS_PROBE_SCRIPT)],
        "",
      );
      if (stdout.includes("PROBE_OK")) {
        cachedPowerShell = candidate;
        return candidate;
      }
    } catch {
      // Try the next candidate.
    }
  }
  cachedPowerShell = null;
  return null;
}

// Validates the wire envelope and returns the base64 payload STRING unchanged.
// The DPAPI shim consumes the base64 text directly; never reconstruct a binary
// buffer into a string (Buffer.toString() would mangle the ciphertext).
function parseWirePayload(text) {
  if (typeof text !== "string" || !text.startsWith(WIRE_PREFIX)) {
    throw corruptStore("The stored signer identity is missing or unreadable; provisioning is required.");
  }
  if (text.length > WIRE_MAX_CHARS) {
    throw corruptStore("The stored signer identity exceeds the bounded size; provisioning is required.");
  }
  const payload = text.slice(WIRE_PREFIX.length).trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(payload)) {
    throw corruptStore("The stored signer identity is corrupted; provisioning is required.");
  }
  if (Buffer.from(payload, "base64").length === 0) {
    throw corruptStore("The stored signer identity is corrupted; provisioning is required.");
  }
  return payload;
}

export function defaultStorageDir() {
  const override = process.env.OMEGA_SOURCE_SUMMARIZATION_SIGNER_DIR;
  if (typeof override === "string" && override.trim() !== "") return override.trim();
  const base = process.env.APPDATA ?? join(homedir(), ".omega-dev");
  return join(base, "Omega Dev", "source-summarization");
}

// Best-effort user-only ACL hardening for the key file: remove inherited ACEs
// and grant the current user full control. Runs without elevation; if it fails,
// the NTFS default applies (the file lives under the user profile) and the
// failure is ignored - it never blocks provisioning and never lowers the
// cryptographic bar.
function hardenKeyFileAcl(filePath) {
  if (process.platform !== "win32") return Promise.resolve();
  const username = process.env.USERNAME;
  if (!username) return Promise.resolve();
  return new Promise((resolvePromise) => {
    try {
      execFile(
        "icacls",
        [filePath, "/inheritance:r", "/grant:r", `${username}:(F)`],
        { windowsHide: true, timeout: 30000 },
        () => resolvePromise(),
      );
    } catch {
      resolvePromise();
    }
  });
}

export function createDpapiFileStorage({ storageDir } = {}) {
  const keyPath = join(storageDir ?? defaultStorageDir(), KEY_FILE_NAME);
  const shell = () => probePowerShellAvailability();

  async function protect(bytes) {
    const executable = await shell();
    if (!executable) {
      throw new StoreError(
        "credential_store_unavailable",
        "DPAPI protection is unavailable (PowerShell with ProtectedData was not found); the signer fails closed and never falls back to plaintext.",
      );
    }
    const stdout = await runBoundedShell(
      executable,
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellScript(DPAPI_SCRIPTS.encrypt)],
      bytes,
    );
    const payload = stdout.trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(payload)) {
      throw new StoreError("credential_store_unavailable", "The OS credential store returned no usable ciphertext.");
    }
    return payload;
  }

  async function unprotect(payload) {
    const executable = await shell();
    if (!executable) {
      throw new StoreError(
        "credential_store_unavailable",
        "DPAPI protection is unavailable (PowerShell with ProtectedData was not found); the signer fails closed and never falls back to plaintext.",
      );
    }
    // A failing decryption is treated as corruption: DPAPI rejected the stored
    // ciphertext (tampered or unreadable), so the store fails closed and
    // provisioning is required. This is never a plaintext fallback.
    const stdout = await runBoundedShell(
      executable,
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellScript(DPAPI_SCRIPTS.decrypt)],
      `${payload}\n`,
      "credential_store_corrupt",
    );
    const hex = stdout.trim();
    if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) {
      throw corruptStore("The stored signer identity could not be decrypted; provisioning is required.");
    }
    return Buffer.from(hex, "hex");
  }

  return {
    keyPath,
    async exists() {
      try {
        await stat(keyPath);
        return true;
      } catch (error) {
        if (error?.code === "ENOENT") return false;
        throw new StoreError("credential_store_unavailable", "The stored signer identity could not be inspected.");
      }
    },
    async read() {
      let text;
      try {
        text = await readFile(keyPath, "utf8");
      } catch (error) {
        if (error?.code === "ENOENT") return null;
        throw corruptStore("The stored signer identity could not be read; provisioning is required.");
      }
      const payload = parseWirePayload(text);
      return unprotect(payload);
    },
    async write(bytes) {
      const payload = await protect(bytes);
      await mkdir(dirnameParts(keyPath), { recursive: true });
      await writeFile(keyPath, `${WIRE_PREFIX}${payload}\n`, { encoding: "utf8", flag: "w" });
      await hardenKeyFileAcl(keyPath);
    },
  };
}

function dirnameParts(keyPath) {
  const separator = keyPath.lastIndexOf("\\");
  const separatorAlt = keyPath.lastIndexOf("/");
  const cut = Math.max(separator, separatorAlt);
  return cut === -1 ? "." : keyPath.slice(0, cut);
}

// TEST-ONLY in-memory storage seam. Reversible byte transform (XOR 0x5A) keeps
// the at-rest representation visibly distinct from the raw key so tests can
// assert that plaintext secrets never appear in storage or output, without
// pretending to be real cryptography. Real protection is DPAPI, covered by the
// optional real-DPAPI smoke test and the service provisioning round.
export function createInMemoryStorage() {
  let wire = null;
  const protect = (bytes) => Buffer.from(bytes.map((byte) => byte ^ 0x5a));
  return {
    async exists() {
      return wire !== null;
    },
    async read() {
      if (wire === null) return null;
      return protect(Buffer.from(parseWirePayload(wire), "base64"));
    },
    async write(bytes) {
      wire = `${WIRE_PREFIX}${protect(bytes).toString("base64")}\n`;
    },
    // TEST-ONLY inspection / corruption-injection handles.
    inspectWire() {
      return wire;
    },
    replaceWire(value) {
      wire = value;
    },
  };
}

// ---------------------------------------------------------------------------
// Identity handling and the signer
// ---------------------------------------------------------------------------

function bytesToValidSecretKey(secretKey) {
  if (!Buffer.isBuffer(secretKey) || secretKey.length !== 32) {
    throw new StoreError("identity_mismatch", "The stored signer key is not a 32-byte secret key.");
  }
  const scalar = bytesToBig(secretKey);
  if (scalar === 0n || scalar >= CURVE_N) {
    throw new StoreError("identity_mismatch", "The stored signer key is not a valid BIP-340 secret key.");
  }
  return scalar;
}

function digestToMessage(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new StoreError("invalid_digest", "The artifact digest must be a SHA-256 hex digest.");
  }
  return Buffer.from(value.toLowerCase(), "hex");
}

function identityFromSecretKey(secretKey) {
  bytesToValidSecretKey(secretKey);
  const publicKeyHex = publicKeyOf(secretKey);
  const publicKeyBytes = Buffer.from(publicKeyHex, "hex");
  const publisherNpub = deriveNpub(publicKeyBytes);
  // Fail closed unless the identity verifies as its own npub: the derived npub
  // must decode back to the same x-only public key (this also validates the
  // npub checksum). A key that fails this check is never used.
  if (npubToPublicKeyHex(publisherNpub) !== publicKeyHex) {
    throw new StoreError("identity_mismatch", "The stored signer identity does not verify as its own npub; provisioning is required.");
  }
  return { secretKey, publicKeyHex, publisherNpub };
}

async function loadStoreIdentity(store) {
  const secretKey = await store.read();
  if (secretKey === null) return null;
  // The store layer must yield a 32-byte secret key; anything else is a corrupt
  // or foreign store and fails closed with provisioning required.
  if (!Buffer.isBuffer(secretKey) || secretKey.length !== 32) {
    throw corruptStore("The stored signer identity is not a valid 32-byte key; provisioning is required.");
  }
  return identityFromSecretKey(secretKey);
}

export function createCredentialStoreSigner({ storageDir, clock, storage } = {}) {
  // `clock` is accepted for contract symmetry with the server's injected clock;
  // the signer is deterministic over the digest and does not stamp time - the
  // server stamps `signed_at` when it assembles the artifact's integrity block.
  const store = storage ?? createDpapiFileStorage({ storageDir: storageDir ?? defaultStorageDir() });
  let identityPromise = null;
  const identity = () => {
    identityPromise ??= loadStoreIdentity(store);
    return identityPromise;
  };
  const signer = {
    publisher_npub: null,
    async sign({ artifact_digest }) {
      const loaded = await identity();
      if (!loaded) throw unprovisioned();
      const signature = schnorrSign(digestToMessage(artifact_digest), loaded.secretKey).toString("hex");
      signer.publisher_npub ??= loaded.publisherNpub;
      return { publisher_signature: signature, publisher_npub: loaded.publisherNpub };
    },
    async verify({ artifact_digest, publisher_signature, publisher_npub }) {
      const loaded = await identity();
      if (!loaded) throw unprovisioned();
      // Same-identity rule: the claimed npub must be exactly the service npub.
      if (publisher_npub !== loaded.publisherNpub) return false;
      if (typeof publisher_signature !== "string" || !/^[0-9a-f]{128}$/i.test(publisher_signature)) return false;
      return schnorrVerify(
        digestToMessage(artifact_digest),
        Buffer.from(loaded.publicKeyHex, "hex"),
        Buffer.from(publisher_signature, "hex"),
      );
    },
  };
  return signer;
}

// One-time provisioning: generate a fresh service key from the OS CSPRNG,
// protect it at rest through the storage seam, and return ONLY the public npub.
// Refuses to regenerate over an existing identity - no silent rotation.
export async function provisionSignerIdentity({ storageDir, storage } = {}) {
  const store = storage ?? createDpapiFileStorage({ storageDir: storageDir ?? defaultStorageDir() });
  if (await store.exists()) {
    throw new StoreError(
      "identity_already_provisioned",
      "A signer identity already exists; provisioning is one-time and never regenerates an existing identity.",
    );
  }
  let secretKey = null;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const candidate = randomBytes(32);
    try {
      bytesToValidSecretKey(candidate);
      secretKey = candidate;
      break;
    } catch {
      // Bounded retry on the astronomically unlikely out-of-range draw.
    }
  }
  if (!secretKey) {
    throw new StoreError("internal_error", "The OS random source produced no valid signer key within the bounded retry budget.");
  }
  const identity = identityFromSecretKey(secretKey);
  await store.write(secretKey);
  return identity.publisherNpub;
}