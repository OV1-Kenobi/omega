//! phoenixd client (OMEGA-DELTA-0303): the sidecar's node rail.
//!
//! Replaces `wavelength.ts` (the waved daemon integration). The sidecar is a
//! CLIENT-ONLY process for the node rail: no daemon child is spawned,
//! supervised, or tree-killed (design §2; deletion disposition §8.1). The
//! phoenixd node runs on the founder's Lunanode, binds loopback, and is
//! reached over Tailscale (or an SSH tunnel) — the base URL is config
//! (`OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL`), never code; the API key
//! (`http-password`) is env-only and redaction-registered (design §2.2).
//!
//! Verified call shapes (authoritative source: github.com/ACINQ/phoenixd,
//! read 2026-09-04 — `src/commonMain/kotlin/fr/acinq/phoenixd/Api.kt` and
//! `json/ApiType.kt` at master; the docs site 403'd direct fetch, so the
//! source is the primary reference):
//! - Auth (RV-C1, resolved): HTTP Basic auth. The Ktor `basic` provider's
//!   `validate { credentials -> … }` compares ONLY the password against the
//!   full-access (`http-password`) and limited-access passwords; the username
//!   is NOT validated (Api.kt: install(Authentication) basic { validate });
//!   the StatusPages text confirms "use basic auth with the http password set
//!   in phoenix.conf". The client uses username "phoenix" (arbitrary) with
//!   the full-access password. `payinvoice`/`payoffer`/`lnurlpay`/
//!   `sendtoaddress`/`bumpfee`/`closechannel`/`lnurlauth` are full-access-only
//!   (Api.kt: authenticate("full-access", strategy = Required)); `createinvoice`
//!   and `getinfo` accept either password.
//! - Request bodies are FORM-ENCODED (`call.receiveParameters()`), never JSON.
//! - `createinvoice` (POST /createinvoice): form fields amountSat (optional),
//!   description (max 128 chars), descriptionHash, expirySeconds, externalId,
//!   webhookUrl; response GeneratedInvoice { amountSat?, paymentHash, serialized }
//!   (ApiType.kt).
//! - `payinvoice` (POST /payinvoice): form fields invoice (BOLT11), amountSat
//!   (optional override for pay-any); success = payment_sent
//!   { recipientAmountSat, routingFeeSat, paymentId, paymentHash,
//!   paymentPreimage } — the PREIMAGE IS PRESENT (RV-C2, resolved: the L-402
//!   redemption proof and the escrow fee proof require it; the websocket
//!   listener is NOT mandatory — the design's fail-closed trigger did not
//!   fire); failure = payment_failed { paymentHash?, offerId?, reason }.
//!   kotlinx.serialization sealed-class polymorphism emits a "type"
//!   discriminator carrying the @SerialName.
//! - `getinfo` (GET /getinfo): NodeInfo { nodeId, channels, chain, blockHeight,
//!   version }. NOTE (RV-C3 factual record, 2026-09-04): current master
//!   exposes `chain` AND `blockHeight` — the design note's "verified absence"
//!   was docs-based and is superseded by the source; the founder's public-tip-API
//!   decision (PRD decision 4) stands regardless, and this slice's wallet-height
//!   seam fails closed (the C3-2 slice wires the tip API under 0304).
//!
//! Non-negotiables enforced here:
//! - The network grammar union `"signet" | "regtest" | "mainnet"` (0286
//!   re-anchored to this module by 0303); mainnet requires the explicit
//!   allow-mainnet opt-in; unset never defaults to mainnet.
//! - SEC-2026-050 (revised by OMEGA-DELTA-0286, re-anchored to the rail by
//!   0303): the REPORTED network (the getinfo `chain` field when present)
//!   must equal the configured network; `mainnet` reported is refused UNLESS
//!   configured mainnet AND the allow-mainnet opt-in is present. When getinfo
//!   exposes no chain field, the assertion is carried by the env gate + the
//!   invoice HRP guard (design §2.6.3) — the honest state is "rail network =
//!   configured network, enforced at the grammar + guard".
//! - The BOLT11 HRP guard (0286, moved here with the rail): configured mainnet
//!   accepts `lnbc` (never `lnbcrt`); signet/regtest refuse `lnbc`.
//! - The API key never leaves the process pair: env -> client memory ->
//!   Authorization header; the caller registers it for redaction (SEC-2026-046).
//! - The pay path's expected-outflow bound (design §2.5; OMEGA-DELTA-0300
//!   loss rule, SEC-2026-098): the sidecar computes the expected total outflow
//!   (BOLT11 amount + phoenixd's documented 0.4% pay fee, rounded up) so the
//!   Rust-side expected-vs-actual settle comparison has its bound; a payment
//!   settling for MORE than expected auto-sets the spend kill fail-closed.

export type PhoenixdNetwork = "signet" | "regtest" | "mainnet";

import { errorEnvelope, type ErrorCode } from "./protocol.js";
import { redact } from "./redact.js";

/** The phoenixd REST base URL env (design §9.3): the tailnet host, never a public host. */
export const PHOENIXD_URL_ENV = "OMEGA_SOVEREIGN_WALLET_PHOENIXD_URL";
/** The phoenixd full-access API key env (the `http-password`; env-only, redaction-registered). */
export const PHOENIXD_API_KEY_ENV = "OMEGA_SOVEREIGN_WALLET_PHOENIXD_API_KEY";

/** Default REST port (phoenixd --http-bind-port default; verified in Phoenixd.kt). */
export const PHOENIXD_REST_DEFAULT_PORT = 9740;

/**
 * phoenixd's documented Lightning pay fee: 0.4% of the invoice amount
 * (design §2.5). Expressed in basis points. [REQUIRES VERIFICATION: the exact
 * rounding/absence of a reported fee is confirmed against the founder's node
 * at staging; the payinvoice response DOES report the actual routingFeeSat, so
 * the loss rule's ACTUAL side is exact regardless.]
 */
export const PHOENIXD_PAY_FEE_BASIS_POINTS = 40;

/** The phoenixd request timeout (node-unreachable surfaces as INTERNAL, retryable). */
export const PHOENIXD_REQUEST_TIMEOUT_MS = 30_000;

export interface PhoenixdConfig {
  /** e.g. `http://<tailscale-host>:9740` — the REST base over Tailscale/SSH (D4). */
  baseUrl: string;
  /** The full-access http-password. Env-only; redaction-registered by the caller. */
  apiKey: string;
  network: PhoenixdNetwork;
  allowMainnet: boolean;
  timeoutMs?: number;
}

/** GET /getinfo (ApiType.NodeInfo). `chain`/`blockHeight` are nullable on the wire. */
export interface NodeInfoResponse {
  nodeId: string;
  channels: unknown[];
  chain: string | null;
  blockHeight: number | null;
  version: string;
}

/** POST /createinvoice (ApiType.GeneratedInvoice). */
export interface CreateInvoiceResponse {
  amountSat: number | null;
  paymentHash: string;
  serialized: string;
}

/** POST /payinvoice success (ApiType.PaymentSent, discriminator `payment_sent`). */
export interface PaymentSentResponse {
  type: "payment_sent";
  recipientAmountSat: number;
  routingFeeSat: number;
  paymentId: string;
  paymentHash: string;
  paymentPreimage: string;
}

/** POST /payinvoice failure (ApiType.PaymentFailed, discriminator `payment_failed`). */
export interface PaymentFailedResponse {
  type: "payment_failed";
  paymentHash: string | null;
  offerId: string | null;
  reason: string;
}

export type PayInvoiceResponse = PaymentSentResponse | PaymentFailedResponse;

export class PhoenixdErrorImpl extends Error {
  readonly envelope: ReturnType<typeof errorEnvelope>;
  constructor(envelope: ReturnType<typeof errorEnvelope>) {
    super(envelope.message);
    this.envelope = envelope;
  }
}

/**
 * Map a phoenixd/HTTP condition to the sidecar's typed envelope (design §2.3).
 * Every branch is explicit; the fund-moving refusals are never blindly
 * retryable (protocol.ts `isBlindRetryUnsafe` covers DEADLINE_EXCEEDED /
 * ABORTED / WAIT_TIMEOUT / CANCELED).
 */
export function mapPhoenixdError(
  status: number | null,
  message: string,
  opts: { retryableDefault?: boolean } = {},
): ReturnType<typeof errorEnvelope> {
  const redactedMessage = redact(message);
  if (status === null) {
    // Connection failure / timeout: the node or the Tailscale path is down.
    return errorEnvelope("INTERNAL", `phoenixd node unreachable: ${redactedMessage}`, {
      details: "node-unreachable",
      retryable: true,
      remediation: "verify the phoenixd node is running and the Tailscale/SSH path to it",
    });
  }
  if (status === 401 || status === 403) {
    // Wrong API key (RV-C1: HTTP Basic with the full-access http-password).
    return errorEnvelope("INTERNAL", `phoenixd rejected the API key: ${redactedMessage}`, {
      details: `http ${status} auth`,
      retryable: false,
      remediation: `verify ${PHOENIXD_API_KEY_ENV} (the phoenixd http-password; never logged)`,
    });
  }
  if (status === 400) {
    return errorEnvelope("INVALID_ARGS", redactedMessage, {
      details: `http ${status}`,
      remediation: "fix the request fields",
    });
  }
  if (status === 404) {
    return errorEnvelope("INTERNAL", `phoenixd unknown endpoint: ${redactedMessage}`, {
      details: `http ${status}`,
      retryable: false,
      remediation: "verify the phoenixd API version matches the client's surface",
    });
  }
  if (status >= 500) {
    return errorEnvelope("INTERNAL", `phoenixd error: ${redactedMessage}`, {
      details: `http ${status}`,
      retryable: opts.retryableDefault ?? true,
      remediation: "check the phoenixd node state (locked/syncing) before retrying fund-moving calls",
    });
  }
  return errorEnvelope("INTERNAL", redactedMessage, {
    details: `http ${status ?? "unknown"}`,
    retryable: opts.retryableDefault ?? false,
  });
}

/**
 * Map a `payment_failed` response body to the typed envelope (design §2.3:
 * a pay failure after acceptance is DEADLINE_EXCEEDED / ABORTED — never
 * blindly retried, because fund-moving RPCs must be checked before retry).
 */
export function mapPaymentFailed(reason: string): ReturnType<typeof errorEnvelope> {
  const lower = reason.toLowerCase();
  if (lower.includes("timeout") || lower.includes("deadline") || lower.includes("timed out")) {
    return errorEnvelope("DEADLINE_EXCEEDED", redact(reason), {
      retryable: false,
      remediation: "check the payment state before retrying (fund-moving RPCs are never blindly retried)",
    });
  }
  if (lower.includes("abort") || lower.includes("cancel")) {
    return errorEnvelope("ABORTED", redact(reason), {
      retryable: false,
      remediation: "check the payment state before retrying (fund-moving RPCs are never blindly retried)",
    });
  }
  return errorEnvelope("INTERNAL", `phoenixd pay failed: ${redact(reason)}`, {
    retryable: false,
    remediation: "check the payment state before retrying (fund-moving RPCs are never blindly retried)",
  });
}

export class PhoenixdClient {
  readonly #baseUrl: string;
  readonly #apiKey: string;
  readonly #timeoutMs: number;

  constructor(config: PhoenixdConfig) {
    this.#baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.#apiKey = config.apiKey;
    this.#timeoutMs = config.timeoutMs ?? PHOENIXD_REQUEST_TIMEOUT_MS;
  }

  get baseUrl(): string {
    return this.#baseUrl;
  }

  /** The HTTP Basic auth header (RV-C1: username arbitrary — only the password is validated). */
  #authHeader(): string {
    return `Basic ${Buffer.from(`phoenix:${this.#apiKey}`, "utf8").toString("base64")}`;
  }

  async #call(method: "GET" | "POST", path: string, formBody?: Record<string, string | number>): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    let response: Response;
    try {
      response = await fetch(`${this.#baseUrl}${path}`, {
        method,
        headers: {
          authorization: this.#authHeader(),
          ...(formBody ? { "content-type": "application/x-www-form-urlencoded" } : {}),
        },
        ...(formBody ? { body: new URLSearchParams(Object.entries(formBody).map(([k, v]) => [k, String(v)])) } : {}),
        signal: controller.signal,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // AbortError = the request timeout (or a local abort); node-unreachable.
      throw new PhoenixdErrorImpl(mapPhoenixdError(null, message));
    } finally {
      clearTimeout(timeout);
    }
    const text = await response.text();
    if (!response.ok) {
      throw new PhoenixdErrorImpl(mapPhoenixdError(response.status, text));
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new PhoenixdErrorImpl(
        errorEnvelope("INTERNAL", "phoenixd returned a non-JSON response", {
          remediation: "verify the phoenixd REST surface answers JSON",
        }),
      );
    }
  }

  /** GET /getinfo — the node identity/reachability probe (RV-C3). */
  async getInfo(): Promise<NodeInfoResponse> {
    return (await this.#call("GET", "/getinfo")) as NodeInfoResponse;
  }

  /**
   * SEC-2026-050 (rail form, 0303): probe the node and report its chain field
   * when present. `null` when getinfo exposes no chain — the assertion is then
   * carried by the env gate + the invoice HRP guard (design §2.6.3). Throws a
   * typed INTERNAL (node-unreachable, retryable) when the probe fails.
   */
  async probeChain(): Promise<string | null> {
    const info = await this.getInfo();
    return typeof info.chain === "string" && info.chain.length > 0 ? info.chain : null;
  }

  /**
   * POST /createinvoice (form-encoded; RV-C1: either password works). The
   * description limit is phoenixd's (128 chars, Api.kt); a 400 surfaces as
   * INVALID_ARGS with the server's message.
   */
  async createInvoice(amountSat: number, description: string): Promise<CreateInvoiceResponse> {
    const result = (await this.#call("POST", "/createinvoice", {
      amountSat,
      description,
    })) as CreateInvoiceResponse;
    if (typeof result.serialized !== "string" || result.serialized.length === 0) {
      throw new PhoenixdErrorImpl(
        errorEnvelope("INTERNAL", "phoenixd createinvoice did not return a serialized BOLT11", {
          remediation: "verify the phoenixd REST surface answers GeneratedInvoice",
        }),
      );
    }
    return result;
  }

  /**
   * POST /payinvoice (form-encoded; full-access only). Returns the typed
   * success/failure envelope; a `payment_failed` body throws the mapped
   * envelope (DEADLINE_EXCEEDED / ABORTED / INTERNAL — never blindly retried).
   */
  async payInvoice(invoice: string): Promise<PaymentSentResponse> {
    const result = (await this.#call("POST", "/payinvoice", { invoice })) as PayInvoiceResponse;
    if (result.type === "payment_failed") {
      throw new PhoenixdErrorImpl(mapPaymentFailed(result.reason));
    }
    if (result.type !== "payment_sent" || typeof result.paymentPreimage !== "string") {
      throw new PhoenixdErrorImpl(
        errorEnvelope("INTERNAL", "phoenixd payinvoice did not answer a payment_sent shape", {
          remediation: "verify the phoenixd REST surface answers PaymentSent",
        }),
      );
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// Guards (moved from wavelength.ts with the rail; semantics unchanged — 0286,
// re-anchored to this module by 0303)
// ---------------------------------------------------------------------------

/**
 * SEC-2026-050 (revised by OMEGA-DELTA-0286; rail form re-anchored by 0303):
 * the node's REPORTED network must equal the configured network. `mainnet` is
 * refused UNLESS the wallet is configured mainnet AND the allow-mainnet opt-in
 * is present — the assertion never trusts the env alone. `MAINNET_REFUSED` and
 * the fail-closed teardown stay. When the reported value is absent (`null`),
 * the assertion is carried by the env gate + the invoice HRP guard (the
 * honest state: "rail network = configured network, enforced at the grammar +
 * guard" — design §2.6.3).
 */
export function assertNetworkMatches(
  configured: string,
  reported: string | null,
  allowMainnet: boolean,
): void {
  if (reported === null) {
    // No chain field on the rail's getinfo: the env gate + HRP guard carry
    // the assertion (design §2.6.3). Fail-closed direction preserved.
    return;
  }
  if (reported === "mainnet" && !(configured === "mainnet" && allowMainnet)) {
    throw new PhoenixdErrorImpl(
      errorEnvelope(
        "MAINNET_REFUSED",
        `MAINNET_REFUSED: the node reported network mainnet; refusing (SEC-2026-050; OMEGA-DELTA-0286; rail form OMEGA-DELTA-0303)`,
      ),
    );
  }
  if (reported !== configured) {
    throw new PhoenixdErrorImpl(
      errorEnvelope(
        "INTERNAL",
        `INTERNAL: the node reported network ${reported}, expected ${configured}; refusing to continue (SEC-2026-050)`,
        { remediation: "re-point the phoenixd connection to a node on the configured network" },
      ),
    );
  }
}

/**
 * BOLT11 HRP guard (design §3.4; OMEGA-DELTA-0286, moved to the phoenixd rail
 * by 0303): the invoice prefix must match the configured network on mint AND
 * pay. signet/regtest behavior is unchanged (`lnbc` refused); a
 * mainnet-configured wallet accepts `lnbc` (still excluding `lnbcrt`) and
 * refuses `lntbs`/`lntb` as mismatched-HRP.
 */
export function assertInvoiceNetwork(configured: string, invoice: string): void {
  if (configured === "mainnet") {
    // lnbc = mainnet; lnbcrt = regtest (starts with lnbc too, so exclude it).
    if (!invoice.startsWith("lnbc") || invoice.startsWith("lnbcrt")) {
      throw new PhoenixdErrorImpl(
        errorEnvelope(
          "INVALID_ARGS",
          `invoice prefix ${invoice.slice(0, 5)} does not match the configured network ${configured}`,
        ),
      );
    }
    return;
  }
  // lnbc = mainnet; lnbcrt = regtest (starts with lnbc too, so exclude it).
  if (invoice.startsWith("lnbc") && !invoice.startsWith("lnbcrt")) {
    throw new PhoenixdErrorImpl(
      errorEnvelope("MAINNET_REFUSED", "mainnet BOLT11 invoices are never paid or minted"),
    );
  }
  const expectedPrefixes = configured === "regtest" ? ["lnbcrt"] : ["lntbs", "lntb"];
  if (!expectedPrefixes.some((p) => invoice.startsWith(p))) {
    throw new PhoenixdErrorImpl(
      errorEnvelope(
        "INVALID_ARGS",
        `invoice prefix ${invoice.slice(0, 5)} does not match the configured network ${configured}`,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// BOLT11 amount + expected-outflow helpers (design §2.5 — the loss-rule bound)
// ---------------------------------------------------------------------------

/**
 * Parse the BOLT11 amount (hrp digits + optional m/u/n/p multiplier) into
 * sats. `null` when the amount is absent (pay-any) or unparseable — the loss
 * rule must not false-trigger on unknown quotes (client.rs semantics;
 * `total_outflow_known = false` exactly as the waved era's prepare-send).
 *
 * BOLT-11 hrp grammar: `ln` + currency (`bc`/`bcrt`/`tbs`/`tb`) + optional
 * amount (digits + ONE optional multiplier letter) + `1` + data. The '1'
 * inside the amount digits is NOT the separator, so the separator is located
 * after the amount, never via a bare `find('1')` (mirrors the Rust
 * `bolt11_amount_sats` in spend_policy.rs).
 */
export function bolt11AmountSats(invoice: string): number | null {
  const lower = invoice.trim().toLowerCase();
  let rest = lower.startsWith("ln") ? lower.slice(2) : "";
  if (rest.startsWith("bcrt")) rest = rest.slice(4);
  else if (rest.startsWith("tbs")) rest = rest.slice(3);
  else if (rest.startsWith("bc")) rest = rest.slice(2);
  else if (rest.startsWith("tb")) rest = rest.slice(2);
  else return null;
  let digits = "";
  for (const char of rest) {
    if (char >= "0" && char <= "9") digits += char;
    else break;
  }
  if (digits.length === 0) return null;
  const multiplier = rest[digits.length] ?? "";
  const amountWidth = digits.length + (multiplier.length > 0 ? 1 : 0);
  if (!rest.slice(amountWidth).startsWith("1")) return null;
  const base = Number.parseInt(digits, 10);
  if (!Number.isSafeInteger(base)) return null;
  switch (multiplier) {
    case "":
      return base * 100_000_000;
    case "m":
      return base * 100_000;
    case "u":
      return base * 100;
    // n = 0.1 sat, p = 0.0001 sat: round UP so the bound never under-counts.
    case "n":
      return Math.ceil(base / 10);
    case "p":
      return Math.ceil(base / 10_000);
    default:
      return null;
  }
}

/**
 * The expected total outflow for the loss-rule bound (design §2.5):
 * BOLT11 amount + phoenixd's documented pay fee (0.4%, rounded up).
 * `null` when the amount is unknown (pay-any) — `total_outflow_known=false`.
 */
export function expectedTotalOutflowSat(invoice: string): { expected: number; known: boolean } {
  const amount = bolt11AmountSats(invoice);
  if (amount === null) return { expected: 0, known: false };
  const fee = Math.ceil((amount * PHOENIXD_PAY_FEE_BASIS_POINTS) / 10_000);
  return { expected: amount + fee, known: true };
}

/** The expected fee component of the bound (0.4% rounded up; 0 when unknown). */
export function expectedFeeSat(invoice: string): number {
  const amount = bolt11AmountSats(invoice);
  if (amount === null) return 0;
  return Math.ceil((amount * PHOENIXD_PAY_FEE_BASIS_POINTS) / 10_000);
}