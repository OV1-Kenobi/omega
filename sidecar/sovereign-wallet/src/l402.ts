//! MDK-protocol L-402 gateway (design §5; founder decision D3/D5) — the ONLY
//! paid boundary in this phase (WP-6 acceptance). Signet/testnet only;
//! mainnet is refused everywhere (D4).
//!
//! The protocol shape is verified from the OpenAgents MDK/L-402 audit
//! (`apps/openagents.com/docs/2026-06-02-mdk-l402-agent-checkout-audit.md`):
//!
//! ```text
//! client -> POST protected route (no proof)
//!   <- HTTP 402 + WWW-Authenticate: L402 macaroon="<credential>", invoice="<lnbc…>"
//!      + JSON body { error:{code:"payment_required"}, challengeId, macaroon,
//!                    invoice, paymentHash, amountSats, expiresAt }
//! client pays the invoice (mandate-gated Rust path) -> preimage
//! client retries with X-OpenAgents-L402: <macaroon>:<preimage> -> protected handler
//! ```
//!
//! Security conditions implemented (WP-2 §5 WP-6 carry list):
//! - SEC-2026-044 HMAC-key custody: the credential signing key is generated
//!   once per data root from CSPRNG, stored encrypted in the vault
//!   (`vault/l402/l402-hmac.key`, XChaCha20-Poly1305 under the vault master
//!   key), never in the gateway SQLite, never in logs/frames; constant-time
//!   verification; key-version prefix + short challenge expiry = the rotation
//!   path (a token signed under a rotated key is rejected).
//! - SEC-2026-048 deferred-settlement crash window: a `checked` redemption
//!   row is inserted BEFORE the protected handler runs; on success the SAME
//!   row is settled (unique partial index = single winner); on failure the
//!   proof stays retryable until expiry; after a crash between handler success
//!   and settle, the retry finds the checked row and re-runs the (idempotent)
//!   handler, then settles — exactly one settled row ever (see
//!   `l402-store.ts`).
//! - SEC-2026-055 invoice binding: the challenge's paymentHash is parsed from
//!   the minted BOLT11 `p` field (never client-supplied) and cross-checked
//!   against the wallet entry's payment hash when present; the challenge row
//!   binds invoice <-> paymentHash <-> resource <-> amount.
//! - SEC-2026-054 locked wallet: challenge minting fails closed with a named
//!   `wallet_locked` error when the wallet is locked; redemption of
//!   already-issued challenges does NOT require the unlocked wallet and stays
//!   honored.
//! - One-shot redemption: unique partial index on settled redemptions; a
//!   second use of the same token/preimage is refused `credential_consumed`
//!   (concurrency single-winner at the SQLite layer).
//! - Entitlement scoping: the credential freezes `resource = METHOD:/path` and
//!   the amount; redemption re-checks the current endpoint price and the
//!   request's method/path against the frozen values.
//! - Signet/testnet-only: the gateway never mints or accepts mainnet invoices
//!   (prefix guard on the minted invoice; the wallet engine itself refuses
//!   mainnet — SEC-2026-050).

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { bech32 } from "@scure/base";

import type { L402ChallengeRow, L402Store } from "./l402-store.js";
import type { Vault } from "./vault/vault.js";

export const L402_KEY_VERSION = 1;
export const L402_CHALLENGE_TTL_MS = 30 * 60 * 1000; // 30 minutes (short expiry = rotation path)
/** Demo protected route: a paid echo (audit's first-endpoint shape), 1 sat, immediate. */
export const DEMO_ECHO_PROTECTED_REF = "paid:echo";
/** Demo paid-MCP-tool lane (design §5.4): deferred settlement, 1 sat per call. */
export const DEMO_MCP_TOOL_PROTECTED_REF = "paid:tool:demo";
export const DEMO_ECHO_PATH = "/v1/l402/paid/echo";
export const DEMO_MCP_PATH_PREFIX = "/v1/l402/mcp/";

export interface MintedInvoice {
  invoice: string;
  entryPaymentHash: string | null;
}

export interface L402GatewayDeps {
  network: "signet" | "regtest";
  store: L402Store;
  vault: Vault | null;
  /**
   * Wallet readiness gate for MINTING (SEC-2026-054). Throws the sidecar's
   * envelopeError (`WALLET_LOCKED` / `WALLET_NOT_CREATED` / `WALLET_SYNCING`)
   * when the wallet is not ready; redemption never calls this.
   */
  walletReady(): Promise<void>;
  /** Mint a BOLT11 invoice via the Wavelength engine (the sidecar's Recv path). */
  mintInvoice(amtSat: number, memo: string): Promise<MintedInvoice>;
  nowMs(): number;
}

export interface L402HttpResult {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface L402GatewayState {
  state: "ready" | "locked" | "unavailable" | "absent";
  note: string;
}

/** The signed opaque credential payload (audit: HMAC-signed opaque token, v0). */
interface CredentialPayload {
  v: number; // key version
  r: string; // resource = METHOD:/path
  c: "SAT";
  a: number; // frozen amount sats
  i: string; // challenge id
  e: number; // expires at (ms)
}

// ---------------------------------------------------------------------------
// BOLT11 payment-hash parsing (SEC-2026-055: server-derived, never client
// supplied)
// ---------------------------------------------------------------------------

/**
 * Extract the payment hash (the `p` tagged field) from a BOLT11 invoice.
 * Returns null when the invoice is not a well-formed bech32 BOLT11 with a
 * 32-byte `p` field. The payment hash is ALWAYS derived from the minted
 * invoice here — a client-supplied paymentHash is never accepted (SEC-2026-055).
 */
export function bolt11PaymentHash(invoice: string): string | null {
  // BOLT-11: `ln` + currency (bc | tbs | tb | bcrt) + optional amount
  // (digits + optional multiplier m/u/n/p) + `1` + bech32 data. The hrp may
  // contain digit '1's (e.g. "lntbs100u"), so the separator must be parsed
  // from the hrp grammar, never `indexOf("1")`. Uppercase invoices are
  // normalized (BIP-173 all-uppercase handling).
  const normalized = invoice.trim().toLowerCase();
  const match =
    /^ln(?:bcrt|tbs|tb|bc)[0-9]*[munp]?1([qpzry9x8gf2tvdw0s3jn54khce6mua7l]+)$/.exec(normalized);
  if (!match) return null;
  let words: number[];
  try {
    words = bech32.decode(normalized as `${string}1${string}`, false).words;
  } catch {
    return null;
  }
  // BOLT-11 data part: 35-bit timestamp (7 words), then tagged fields of the
  // form type (5 bits) | data_length (10 bits, big-endian) | data
  // (data_length x 5 bits), then a 520-bit signature (104 words). We stop at
  // the first `p` field (mandatory, appears before the signature).
  let offset = 7;
  while (offset + 3 <= words.length) {
    const tag = words[offset]!;
    const length = ((words[offset + 1]! << 5) | words[offset + 2]!) & 0x3ff;
    offset += 3;
    if (offset + length > words.length) return null;
    const data = words.slice(offset, offset + length);
    offset += length;
    if (tag === 1) {
      // `p`: 52 words = 32 bytes (256-bit payment hash).
      const bytes = new Uint8Array(bech32.fromWords(data));
      if (bytes.length !== 32) return null;
      return Buffer.from(bytes).toString("hex");
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Credential (opaque HMAC token; MDK-compatible v0 — no macaroon delegation
// claims, per the audit)
// ---------------------------------------------------------------------------

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

/** Constant-time HMAC comparison over SHA-256 digests. */
function hmacMatches(expected: Buffer, provided: Buffer): boolean {
  return timingSafeEqual(sha256Digest(expected), sha256Digest(provided));
}

function sha256Digest(value: Uint8Array): Buffer {
  return createHash("sha256").update(value).digest();
}

function signCredential(key: Uint8Array, payload: CredentialPayload): string {
  const encoded = `v${payload.v}.${b64url(Buffer.from(JSON.stringify(payload), "utf8"))}`;
  const signature = createHmac("sha256", key).update(encoded, "utf8").digest("base64url");
  return `${encoded}.${signature}`;
}

function parseCredential(
  key: Uint8Array,
  credential: string,
): CredentialPayload | null {
  // shape: v<version>.<b64url(payload)>.<b64url(sig)>
  const match = /^v(\d+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(credential);
  if (!match) return null;
  const version = Number.parseInt(match[1]!, 10);
  if (version !== L402_KEY_VERSION) return null; // rotated key: old tokens rejected
  const encoded = `v${match[1]}.${match[2]}`;
  const expected = createHmac("sha256", key).update(encoded, "utf8").digest();
  const provided = Buffer.from(match[3]!, "base64url");
  if (!hmacMatches(expected, provided)) return null;
  try {
    const payload = JSON.parse(Buffer.from(match[2]!, "base64url").toString("utf8")) as CredentialPayload;
    if (payload.v !== L402_KEY_VERSION || payload.c !== "SAT") return null;
    if (typeof payload.r !== "string" || typeof payload.a !== "number" || typeof payload.i !== "string" || typeof payload.e !== "number") {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------

export class L402Gateway {
  readonly #deps: L402GatewayDeps;
  /** In-memory HMAC key (SEC-2026-044 custody). See `#ensureKey`. */
  #key: Uint8Array | null = null;

  constructor(deps: L402GatewayDeps) {
    this.#deps = deps;
    // Seed the demo product catalog (audit Phase 1: "seed one local paid
    // endpoint policy in code").
    const now = deps.nowMs();
    deps.store.seedProduct({
      id: "product_paid_echo",
      stableKey: "paid:echo",
      method: "POST",
      pathPattern: DEMO_ECHO_PATH,
      protectedRef: DEMO_ECHO_PROTECTED_REF,
      title: "Paid echo (signet demo)",
      status: "active",
      rail: "mdk_lightning",
      currency: "SAT",
      amountSats: 1,
      settlementMode: "immediate",
      createdAtMs: now,
      updatedAtMs: now,
    });
    deps.store.seedProduct({
      id: "product_paid_tool_demo",
      stableKey: "paid:tool:demo",
      method: "POST",
      pathPattern: `${DEMO_MCP_PATH_PREFIX}*`,
      protectedRef: DEMO_MCP_TOOL_PROTECTED_REF,
      title: "Paid MCP tool (signet demo)",
      status: "active",
      rail: "mdk_lightning",
      currency: "SAT",
      amountSats: 1,
      settlementMode: "deferred",
      createdAtMs: now,
      updatedAtMs: now,
    });
  }

  /**
   * The gateway's observable state for `status.l402_gateway_state`.
   * - `absent`   — never constructed (flag off).
   * - `unavailable` — the state store is not open.
   * - `locked`   — the HMAC key is unavailable (vault locked and never
   *   unlocked since startup): minting refused; redemption verification
   *   unavailable until the vault is unlocked once.
   * - `ready`    — key available (vault unlocked; loaded on first use).
   */
  state(): L402GatewayState {
    return {
      state: this.#deps.vault && this.#deps.vault.isUnlocked() ? "ready" : "locked",
      note:
        this.#deps.vault && this.#deps.vault.isUnlocked()
          ? "L-402 gateway ready (signet/testnet only; mainnet refused)"
          : "L-402 gateway locked: unlock the identity vault to enable challenge minting",
    };
  }

  /**
   * SEC-2026-044 key lifecycle. The key is generated once per data root from
   * CSPRNG and stored encrypted in the vault (`vault/l402/l402-hmac.key`).
   * It is loaded into memory when the vault is first unlocked and RETAINED
   * for the sidecar process lifetime (zeroized on `shutdown`), so redemption
   * of already-paid challenges stays honored while the wallet is locked
   * (SEC-2026-054) — the at-rest custody is vault-encrypted; the in-memory
   * lifetime is the gateway's, not the idle-lock's. Labeled resolution of the
   * SEC-2026-044 "zeroized on lock" wording vs SEC-2026-054 "redemption stays
   * honored while locked": the vault master key IS zeroized on lock
   * (unchanged); this separate in-memory key is process-scoped.
   */
  async #ensureKey(): Promise<Uint8Array | null> {
    if (this.#key) return this.#key;
    if (!this.#deps.vault || !this.#deps.vault.isUnlocked()) return null;
    let stored = await this.#deps.vault.getL402Key().catch(() => null);
    if (!stored) {
      stored = randomBytes(32);
      await this.#deps.vault.storeL402Key(stored);
    }
    this.#key = stored;
    return stored;
  }

  /** Zeroize the in-memory key and drop the reference (shutdown/lock). */
  shutdown(): void {
    if (this.#key) {
      this.#key.fill(0);
      this.#key = null;
    }
  }

  // -------------------------------------------------------------------------
  // Route surface
  // -------------------------------------------------------------------------

  /**
   * Dispatch a gateway-route request. Returns null when the path is not a
   * gateway route (the HTTP surface then 404s). Routes:
   * - POST /v1/l402/paid/echo            (immediate settlement demo)
   * - POST /v1/l402/mcp/<server>/<tool>  (deferred settlement demo tool lane)
   */
  async handleRequest(
    method: string,
    pathname: string,
    headers: Record<string, string | string[] | undefined>,
    body: string,
  ): Promise<L402HttpResult | null> {
    let protectedRef: string | null = null;
    if (method === "POST" && pathname === DEMO_ECHO_PATH) {
      protectedRef = DEMO_ECHO_PROTECTED_REF;
    } else if (method === "POST" && pathname.startsWith(DEMO_MCP_PATH_PREFIX)) {
      const segments = pathname.slice(DEMO_MCP_PATH_PREFIX.length).split("/").filter(Boolean);
      if (segments.length === 2) {
        protectedRef = `paid:tool:${segments[0]}:${segments[1]}`;
      }
    }
    if (!protectedRef) return null;

    const proof = parseProofHeader(headers);
    if (!proof) {
      return this.#issueChallenge(protectedRef, method, pathname);
    }
    return this.#redeem(protectedRef, method, pathname, proof);
  }

  // -------------------------------------------------------------------------
  // Challenge issuance (design §5.2)
  // -------------------------------------------------------------------------

  async #issueChallenge(
    protectedRef: string,
    method: string,
    pathname: string,
  ): Promise<L402HttpResult> {
    const product = this.#resolveProduct(protectedRef);
    if (!product || product.amountSats === null) {
      return errorResult(500, "configuration_error", "no active pricing for this protected route");
    }

    // SEC-2026-054: minting requires the wallet (fail closed, named error).
    let walletReadyError: { code: string; message: string } | null = null;
    try {
      await this.#deps.walletReady();
    } catch (error) {
      walletReadyError = envelopeOf(error);
    }
    if (walletReadyError) {
      return {
        status: 503,
        headers: { "cache-control": "no-store" },
        body: {
          error: { code: "wallet_locked", message: walletReadyError.message },
          remediation: "run unlock (operator-only)",
        },
      };
    }

    // SEC-2026-044: the credential key must be available to mint.
    const key = await this.#ensureKey();
    if (!key) {
      return errorResult(503, "gateway_locked", "the L-402 gateway key is unavailable (vault locked); unlock the vault to enable challenge minting");
    }

    // Mint via the Wavelength engine; the gateway never accepts an invoice
    // from a request (SEC-2026-055: server-side mint only).
    let minted: MintedInvoice;
    try {
      minted = await this.#deps.mintInvoice(product.amountSats, `L402 ${protectedRef}`);
    } catch (error) {
      const envelope = envelopeOf(error);
      if (envelope?.code === "MAINNET_REFUSED") {
        return errorResult(500, "mainnet_refused", "mainnet invoices are never minted (D4)");
      }
      return errorResult(502, "invoice_mint_failed", `Wavelength receive failed: ${envelope?.message ?? String(error)}`);
    }

    // Invoice binding (SEC-2026-055): paymentHash parsed from the BOLT11 `p`
    // field — never from the request — and cross-checked against the wallet
    // entry's payment hash when present.
    // Mainnet hard-bail (D4): the gateway itself refuses a mainnet invoice
    // from the wallet engine, independent of the sidecar's prefix guard
    // (defense in depth).
    if (minted.invoice.startsWith("lnbc") && !minted.invoice.startsWith("lnbcrt")) {
      return errorResult(500, "mainnet_refused", "mainnet invoices are never minted (D4)");
    }
    const paymentHash = bolt11PaymentHash(minted.invoice);
    if (!paymentHash) {
      return errorResult(500, "configuration_error", "the minted invoice carries no parseable payment hash");
    }
    if (minted.entryPaymentHash && minted.entryPaymentHash.toLowerCase() !== paymentHash.toLowerCase()) {
      return errorResult(500, "configuration_error", "the wallet entry payment hash does not match the invoice payment hash (invoice binding)");
    }

    // Replay protection: sweep expired challenges, then persist a challenge
    // row keyed on payment_hash (unique) and token_hash (unique); the token
    // hash is stored, never the token (SEC-2026-044).
    this.#deps.store.sweepExpired(this.#deps.nowMs());
    const now = this.#deps.nowMs();
    const expiresAtMs = now + L402_CHALLENGE_TTL_MS;
    const challengeId = `l402_challenge_${now.toString(36)}_${randomBytes(6).toString("hex")}`;
    const resource = `${method}:${pathname}`;
    const payload: CredentialPayload = {
      v: L402_KEY_VERSION,
      r: resource,
      c: "SAT",
      a: product.amountSats,
      i: challengeId,
      e: expiresAtMs,
    };
    const credential = signCredential(key, payload);
    const tokenHash = sha256Hex(credential);
    const challenge: L402ChallengeRow = {
      id: challengeId,
      protectedRef,
      method,
      path: pathname,
      resource,
      status: "issued",
      amountSats: product.amountSats,
      invoice: minted.invoice,
      paymentHash,
      tokenHash,
      expiresAtMs,
      createdAtMs: now,
      updatedAtMs: now,
    };
    try {
      this.#deps.store.insertChallenge(challenge);
    } catch (error) {
      return errorResult(500, "configuration_error", `challenge persistence failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    this.#deps.store.insertReceipt("payment_challenge_issued", "issued", challengeId, `L-402 challenge issued for ${protectedRef}`, now);

    // The standard L-402 challenge (audit §"Response Contract").
    return {
      status: 402,
      headers: {
        "www-authenticate": `L402 macaroon="${credential}", invoice="${minted.invoice}"`,
        "cache-control": "no-store",
      },
      body: {
        error: { code: "payment_required", message: "Payment required" },
        challengeId,
        macaroon: credential,
        invoice: minted.invoice,
        paymentHash,
        amountSats: product.amountSats,
        expiresAt: Math.floor(expiresAtMs / 1000),
      },
    };
  }

  // -------------------------------------------------------------------------
  // Redemption (design §5.3)
  // -------------------------------------------------------------------------

  async #redeem(
    protectedRef: string,
    method: string,
    pathname: string,
    proof: { macaroon: string; preimage: string },
  ): Promise<L402HttpResult> {
    const key = this.#key ?? (await this.#ensureKey());
    if (!key) {
      return errorResult(503, "gateway_locked", "the L-402 gateway key is unavailable (vault locked); unlock the vault once to enable redemption");
    }

    // 1. Verify the credential (HMAC, constant-time; SEC-2026-044).
    const payload = parseCredential(key, proof.macaroon);
    if (!payload) {
      return errorResult(401, "invalid_credential", "malformed or unsigned L-402 credential");
    }

    // 2. Resource binding: the credential's frozen resource must equal the
    //    request's METHOD:/path (entitlement scoping, design §5.4).
    if (payload.r !== `${method}:${pathname}`) {
      return errorResult(403, "resource_mismatch", "the L-402 credential is bound to a different resource");
    }

    // 3. Re-check the current endpoint price (audit rule). The per-tool MCP
    //    lane falls back to the seeded demo tool product when no specific
    //    product row exists yet.
    const product = this.#resolveProduct(protectedRef);
    if (!product || product.amountSats === null) {
      return errorResult(500, "pricing_error", "no active pricing for this protected route");
    }
    if (payload.a !== product.amountSats) {
      return errorResult(403, "amount_mismatch", "the endpoint price changed since the challenge was issued");
    }

    // 4. Look up the challenge by token hash, then verify the core L-402
    //    proof sha256(preimage) == paymentHash BEFORE the status checks
    //    (audit order), so a wrong preimage is `invalid_payment_proof` even
    //    after the challenge was redeemed.
    const tokenHash = sha256Hex(proof.macaroon);
    const challenge = this.#deps.store.getChallengeByTokenHash(tokenHash);
    if (!challenge || challenge.id !== payload.i) {
      return errorResult(401, "invalid_credential", "unknown L-402 challenge");
    }
    if (!isHex64(proof.preimage)) {
      return errorResult(401, "invalid_payment_proof", "the preimage is not 64-hex");
    }
    const preimageBytes = Buffer.from(proof.preimage, "hex");
    const proofHash = sha256Hex(preimageBytes);
    if (proofHash.toLowerCase() !== challenge.paymentHash.toLowerCase()) {
      return errorResult(401, "invalid_payment_proof", "sha256(preimage) does not match the payment hash");
    }

    // 5. Challenge state: issued/paid only; redeemed is consumed; expired or
    //    revoked re-challenges.
    if (challenge.status === "redeemed") {
      return errorResult(401, "credential_consumed", "this L-402 credential was already redeemed");
    }
    if (challenge.status === "expired" || challenge.status === "revoked") {
      return errorResult(402, "payment_required", "the L-402 challenge expired or was revoked; re-challenge");
    }
    if (challenge.status !== "issued" && challenge.status !== "paid") {
      return errorResult(500, "configuration_error", `challenge in unexpected state ${challenge.status}`);
    }
    if (challenge.expiresAtMs < this.#deps.nowMs()) {
      this.#deps.store.sweepExpired(this.#deps.nowMs());
      return errorResult(402, "payment_required", "the L-402 challenge expired; re-challenge");
    }

    // 6. Settlement by mode. The request id is deterministic so a retry after
    //    a crash reuses the same redemption row (SEC-2026-048).
    const requestId = sha256Hex(`${tokenHash}:${proof.preimage}`).slice(0, 40);
    const now = this.#deps.nowMs();

    const settlementMode = product.settlementMode;
    if (settlementMode === "immediate") {
      return this.#settleImmediate(challenge, requestId, now);
    }
    return this.#settleDeferred(challenge, requestId, now, protectedRef);
  }

  /**
   * Immediate settlement (audit order): verify -> insert the settled
   * redemption (single-winner) -> mark the challenge redeemed -> grant the
   * one-shot entitlement + receipt -> run the protected handler. A crash
   * after the insert but before the response leaves a settled redemption (no
   * double-spend; the client's paid access attempt is recorded and a retry is
   * refused `credential_consumed`).
   */
  #settleImmediate(
    challenge: L402ChallengeRow,
    requestId: string,
    nowMs: number,
  ): L402HttpResult {
    const inserted = this.#deps.store.insertSettledRedemption(
      challenge.id,
      challenge.protectedRef,
      requestId,
      nowMs,
    );
    if (!inserted.settled) {
      // The unique partial index refused a second settled row: consumed.
      return errorResult(401, "credential_consumed", "this L-402 credential was already redeemed");
    }
    this.#deps.store.markRedeemed(challenge.id, nowMs);
    this.#deps.store.insertEntitlement(
      challenge.id,
      challenge.protectedRef,
      challenge.resource,
      challenge.amountSats,
      nowMs,
      challenge.expiresAtMs,
    );
    this.#deps.store.insertReceipt("payment_redemption_settled", "settled", challenge.id, `L-402 redemption settled for ${challenge.protectedRef}`, nowMs);
    const body = this.#protectedEcho(challenge);
    return { status: 200, headers: { "cache-control": "no-store" }, body };
  }

  /**
   * Deferred settlement (SEC-2026-048; audit §"Deferred settlement"): insert
   * a `checked` redemption BEFORE the handler; settle the SAME row only after
   * the handler succeeds. On handler failure the proof stays retryable until
   * expiry. After a crash between handler success and settle, a retry reuses
   * the checked row, re-runs the (idempotent) handler, and settles — exactly
   * one settled redemption per challenge (unique partial index).
   */
  #settleDeferred(
    challenge: L402ChallengeRow,
    requestId: string,
    nowMs: number,
    protectedRef: string,
  ): L402HttpResult {
    // Crash-window anchor: the checked row (inserted before the handler).
    this.#deps.store.insertCheckedRedemption(challenge.id, challenge.protectedRef, requestId, nowMs);

    // The protected handler (demo tool lane: idempotent by construction —
    // returns a canned result, no side effects).
    const body = this.#protectedToolResult(challenge, protectedRef);

    const settled = this.#deps.store.settleCheckedRedemption(challenge.id, nowMs);
    if (!settled.settled) {
      // Another redemption settled this challenge first (concurrency winner).
      return errorResult(401, "credential_consumed", "this L-402 credential was already redeemed");
    }
    this.#deps.store.markRedeemed(challenge.id, nowMs);
    this.#deps.store.insertEntitlement(
      challenge.id,
      challenge.protectedRef,
      challenge.resource,
      challenge.amountSats,
      nowMs,
      challenge.expiresAtMs,
    );
    this.#deps.store.insertReceipt("payment_redemption_settled", "settled", challenge.id, `L-402 redemption settled for ${challenge.protectedRef}`, nowMs);
    return { status: 200, headers: { "cache-control": "no-store" }, body };
  }

  // -------------------------------------------------------------------------
  // Protected handlers (the demo paid surface)
  // -------------------------------------------------------------------------

  /**
   * Product resolution: an exact product row first, then the seeded demo MCP
   * tool product for any `paid:tool:*` scope (per-tool product rows can be
   * seeded later without changing the demo price).
   */
  #resolveProduct(protectedRef: string): ReturnType<L402Store["getProduct"]> {
    const exact = this.#deps.store.getProduct(protectedRef);
    if (exact) return exact;
    if (protectedRef.startsWith("paid:tool:")) {
      return this.#deps.store.getProduct(DEMO_MCP_TOOL_PROTECTED_REF);
    }
    return null;
  }

  /** The paid echo: returns the challenge's paid scope (immediate settlement). */
  #protectedEcho(challenge: L402ChallengeRow): unknown {
    return {
      ok: true,
      echo: {
        protectedRef: challenge.protectedRef,
        amountSats: challenge.amountSats,
        settled: true,
      },
      message: "paid endpoint access granted (signet demo — never mainnet)",
    };
  }

  /** The paid MCP tool result (deferred settlement; idempotent). */
  #protectedToolResult(challenge: L402ChallengeRow, protectedRef: string): unknown {
    const tool = protectedRef.slice("paid:tool:".length);
    return {
      ok: true,
      tool,
      message: "paid MCP tool executed (signet demo — never mainnet)",
      result: { content: [{ type: "text", text: `paid tool ${tool} completed` }] },
    };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseProofHeader(
  headers: Record<string, string | string[] | undefined>,
): { macaroon: string; preimage: string } | null {
  // Preferred v0 (audit "Auth header collision"): X-OpenAgents-L402: <macaroon>:<preimage>
  const custom = headerValue(headers, "x-openagents-l402");
  if (custom) {
    const proof = splitProof(custom);
    if (proof) return proof;
  }
  // Strict L402 compatibility: Authorization: L402 <macaroon>:<preimage>
  const authorization = headerValue(headers, "authorization");
  if (authorization && authorization.startsWith("L402 ")) {
    const proof = splitProof(authorization.slice("L402 ".length).trim());
    if (proof) return proof;
  }
  return null;
}

function headerValue(
  headers: Record<string, string | string[] | undefined>,
  key: string,
): string | null {
  const value = headers[key];
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.length > 0) return value[0] ?? null;
  return null;
}

function splitProof(value: string): { macaroon: string; preimage: string } | null {
  const colon = value.indexOf(":");
  if (colon <= 0 || colon === value.length - 1) return null;
  return { macaroon: value.slice(0, colon), preimage: value.slice(colon + 1) };
}

function isHex64(value: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(value);
}

function errorResult(
  status: number,
  code: string,
  message: string,
): L402HttpResult {
  return {
    status,
    headers: { "cache-control": "no-store" },
    body: { error: { code, message } },
  };
}

/** Extract the sidecar error envelope (code/message) from a thrown envelopeError. */
function envelopeOf(error: unknown): { code: string; message: string } | null {
  if (error instanceof Error && "envelope" in error) {
    const envelope = (error as { envelope: { code: string; message: string } }).envelope;
    return { code: envelope.code, message: envelope.message };
  }
  return null;
}