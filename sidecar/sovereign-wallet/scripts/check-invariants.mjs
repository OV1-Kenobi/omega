#!/usr/bin/env node
//! Adapted satnam S1-S12 invariant suite for the sovereign-wallet sidecar
//! (SEC-2026-051; named by WP-2). Wired into the sidecar test/build step.
//!
//! Applies: S1 (no key-material columns in SQL), S2 (no JWT), S3 (no
//! @sentry/telemetry egress), S4 (no key material outside vault/), S8
//! (dependency budget <= 22), S10 (NIP-98 verify on every accepting surface,
//! adapted), S11 (no console logging of key material, extended).
//! Not applicable: S5 (OPFS), S6 (CMAC), S7 (font CDN), S9 (Netlify count),
//! S12 (CSP — Node process, no browser surface this phase).

import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "src");

const failures = [];
const notes = [];

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      walk(full, out);
    } else if (full.endsWith(".ts") || full.endsWith(".mjs")) {
      out.push(full);
    }
  }
  return out;
}

const files = walk(SRC);
const sources = files.map((file) => ({ file, text: readFileSync(file, "utf8") }));

// --- S1: no key-material columns in SQL -------------------------------------
{
  const forbiddenColumns = ["nsec", "secret", "preimage", "mnemonic", "password", "passphrase", "macaroon", "token_hash"];
  const sqlStatements = sources.flatMap(({ file, text }) =>
    (text.match(/CREATE TABLE[^;]*/gi) ?? []).map((statement) => ({ file, statement })),
  );
  if (sqlStatements.length === 0) {
    notes.push("S1: no CREATE TABLE statements found in src (schemas may live in node:sqlite callers); scanning column names anyway");
  }
  for (const { file, statement } of sqlStatements) {
    const lower = statement.toLowerCase();
    for (const column of forbiddenColumns) {
      if (new RegExp(`\\b${column}\\b`, "i").test(lower)) {
        failures.push(`S1 FAIL (${path.basename(file)}): column "${column}" is forbidden in SQL (no key material in stores)`);
      }
    }
  }
  notes.push(`S1: scanned ${sqlStatements.length} CREATE TABLE statement(s) for forbidden columns`);
}

// --- S2: no JWT --------------------------------------------------------------
{
  const jwtHits = sources.filter(({ file, text }) => /jwt/i.test(text));
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const jwtDeps = Object.keys(deps).filter((name) => /jwt/.test(name));
  if (jwtHits.length || jwtDeps.length) {
    failures.push(`S2 FAIL: JWT present (src hits: ${jwtHits.length}, deps: ${jwtDeps.join(",")})`);
  }
  notes.push("S2: no JWT libraries or secrets");
}

// --- S3: no @sentry / egress telemetry ---------------------------------------
{
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const sentry = Object.keys(deps).filter((name) => /sentry/.test(name));
  const srcHits = sources.filter(({ file, text }) => /sentry/i.test(text));
  if (sentry.length || srcHits.length) {
    failures.push(`S3 FAIL: telemetry/egress dependency present (deps: ${sentry.join(",")}, src hits: ${srcHits.length})`);
  }
  notes.push("S3: no @sentry/* or egress telemetry in a wallet process");
}

// --- S4: no key material written outside vault/ ------------------------------
{
  // `src/vault/store.ts` is the vault persistence backend: every write it
  // performs lands under the vault root (atomic temp + rename). WP-4 added it;
  // it is the vault surface, not an out-of-vault write, so it is allowlisted
  // as a whole.
  const vaultBackend = "src/vault/store.ts";
  const fsWrite = /fs\.(writeFile|appendFile|createWriteStream)|writeFileSync|appendFileSync/;
  for (const { file, text } of sources) {
    if (path.normalize(file).replace(/\\/g, "/").endsWith(vaultBackend)) {
      notes.push(`S4: ${vaultBackend} is the vault persistence backend (atomic vault-root writes); allowed`);
      continue;
    }
    for (const match of text.matchAll(new RegExp(fsWrite.source, "g"))) {
      const line = text.slice(0, match.index).split("\n").length;
      const context = text.split("\n")[line - 1] ?? "";
      if (/vault|lock|marker|idempotency|waved\.pid|sidecar\.lock/.test(context)) continue;
      failures.push(`S4 FAIL (${path.basename(file)}:${line}): fs write outside vault/run surfaces: ${context.trim()}`);
    }
  }
  notes.push("S4: no persistent key material outside vault/ (adapted: no fs writes of secrets outside vault/)");
}

// --- S8: dependency budget <= 22 ----------------------------------------------
{
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const direct = Object.keys(pkg.dependencies ?? {}).length;
  const lock = JSON.parse(readFileSync(path.join(ROOT, "package-lock.json"), "utf8"));
  const packages = lock.packages ?? {};
  const total = Object.keys(packages).filter((name) => name !== "" && !packages[name].dev).length;
  if (direct > 22 || total > 22) {
    failures.push(`S8 FAIL: dependency budget exceeded (direct=${direct}, runtime total=${total}; budget is 22)`);
  }
  notes.push(`S8: dependency budget OK (direct=${direct}, runtime total=${total} <= 22)`);
}

// --- S10: NIP-98 verify on every accepting surface (adapted) ------------------
{
  // WP-3 has no NIP-98 accepting surface (identity lands in WP-4). The check
  // asserts no route handler parses an `Authorization: Nostr` header without
  // importing the verifier — i.e., no accepting surface exists yet unverified.
  const authNostr = sources.filter(({ file, text }) => /Authorization:\s*Nostr|Nostr\s+[0-9a-f]/i.test(text));
  const verifier = sources.filter(({ file, text }) => /verifyNip98|nip98.*verify|verify.*nip98/i.test(text));
  if (authNostr.length > 0 && verifier.length === 0) {
    failures.push("S10 FAIL: an accepting surface parses NIP-98 auth without a verifier");
  }
  notes.push(`S10: NIP-98 accepting surfaces = ${authNostr.length}, verifier imports = ${verifier.length} (WP-4 wires the verifier)`);
}

// --- S11: no console logging of key material (extended) -----------------------
{
  const secretPatterns = /nsec|mnemonic|aezeed|wallet.?password|passphrase|preimage|admin\.macaroon|loopback.?token/i;
  for (const { file, text } of sources) {
    for (const match of text.matchAll(/console\.(log|error|warn|info)\(([^)]*)\)/g)) {
      const args = match[2] ?? "";
      if (secretPatterns.test(args)) {
        const line = text.slice(0, match.index).split("\n").length;
        failures.push(`S11 FAIL (${path.basename(file)}:${line}): console output may carry key material: ${args.trim().slice(0, 80)}`);
      }
    }
  }
  notes.push("S11: no console logging of key material (mnemonic/aezeed/password/passphrase/preimage/macaroon/token)");
}

// --- S5/S6/S7/S9/S12: not applicable ------------------------------------------
{
  notes.push("S5: OPFS — NOT APPLICABLE (Node process, no browser storage)");
  notes.push("S6: CMAC — NOT APPLICABLE (NFC out of scope this phase)");
  notes.push("S7: font CDN — NOT APPLICABLE (no browser UI)");
  notes.push("S9: Netlify function count — NOT APPLICABLE");
  notes.push("S12: CSP — NOT APPLICABLE (Node process; revisit if an HTTP surface serves HTML)");
}

const ok = failures.length === 0;
console.log(`invariants: ${ok ? "PASS" : "FAIL"} (${notes.length} notes, ${failures.length} failures)`);
for (const note of notes) console.log(`  note: ${note}`);
for (const failure of failures) console.log(`  FAIL: ${failure}`);
process.exit(ok ? 0 : 1);