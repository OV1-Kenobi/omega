//! Named secret redaction (SEC-2026-046).
//!
//! A process-wide registry of active secret VALUES (mnemonic words, wallet DB
//! password, passphrase, nsec, preimage, admin.macaroon hex, loopback token)
//! plus shape-based patterns for values the sidecar may not hold in memory.
//! Every log line, stderr-forwarded line, and frame-body debug capture passes
//! through `redact` before it can reach the supervisor, Omega's log, or the
//! sidecar's own log file.

const REGISTERED: string[] = [];

/** Register an active secret value so any occurrence is redacted from output. */
export function registerSecret(value: string): void {
  if (value.length >= 4) {
    REGISTERED.push(value);
  }
}

export function clearRegisteredSecrets(): void {
  REGISTERED.length = 0;
}

/** Shape patterns for values the sidecar may not currently hold. */
const SHAPE_PATTERNS: RegExp[] = [
  /nsec1[02-9ac-hj-np-z]{58,62}/g, // bech32 nsec (NIP-19)
  /\b[0-9a-f]{64}\b/g, // 64-hex (preimage, payment preimage, macaroon, keys)
  /lnbc[a-z0-9]+/gi, // mainnet BOLT11 (never minted here; redact if ever seen)
  /lntbs[a-z0-9]+/gi, // signet BOLT11 (contains no secret, but keep invoices out of logs)
  /lntb[a-z0-9]+/gi,
  /lnbcrt[a-z0-9]+/gi,
];

/** Redact every registered secret and secret-shaped string from a line. */
export function redact(line: string): string {
  let out = line;
  for (const secret of REGISTERED) {
    // Case-preserving replace of the exact value; secrets are long enough that
    // a plain split/join is safe and much faster than a regex with escaping.
    if (out.includes(secret)) {
      out = out.split(secret).join("[REDACTED]");
    }
  }
  for (const pattern of SHAPE_PATTERNS) {
    out = out.replace(pattern, "[REDACTED]");
  }
  return out;
}

/** True when a line contains a secret-shaped string (used by tests + S11). */
export function containsSecretShape(line: string): boolean {
  return SHAPE_PATTERNS.some((pattern) => pattern.test(line));
}

/** Redact a structured value (frame body) for debug capture without mutating it. */
export function redactJsonValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redact(value);
  }
  if (Array.isArray(value)) {
    return value.map(redactJsonValue);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = redactJsonValue(entry);
    }
    return out;
  }
  return value;
}