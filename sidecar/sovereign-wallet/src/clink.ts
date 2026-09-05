/**
 * CLINK Offers/Debits layer (OMEGA-DELTA-0306; design §3, WP-C4)
 *
 * The sidecar is the app's CLINK node-service endpoint: it subscribes to
 * kinds 21001 (Offers) and 21002 (Debits) addressed to the app's service
 * pubkey on the configured strfry relay(s), NIP-44 decrypts, validates with
 * the SDK's validators, and answers on the same channel.
 *
 * Authority law (D2, SEC-2026-106): this module is TRANSPORT ONLY. It never
 * becomes an authority and never pays outside the host-initiated
 * `pay-debit` path — the Rust `pay_debit_invoice` wrapper (client.rs) runs
 * `authorize_sovereign_spend` + the spend policy BEFORE the sidecar touches
 * phoenixd. A Debit is queued here; it is never paid here.
 *
 * Flood control (SEC-2026-106b): the pending-debit queue is bounded (global
 * cap) with a per-pubkey cap; overflow answers GFY code 4 (rate limited)
 * WITHOUT queueing, and never reaches phoenixd.
 *
 * Flag: `OMEGA_CLINK_LAYER=1` enables the listener. OFF (default) = the
 * sidecar is phoenixd-rail-only; no Nostr pool is ever constructed and no
 * relay socket is ever opened (tested).
 */

import { nip44, verifyEvent, finalizeEvent, getPublicKey } from "@shocknet/clink-sdk";
import {
  CLINK_OFFER_KIND,
  CLINK_DEBIT_KIND,
  CLINK_VERSION,
  validateNdebitData,
  validateNofferData,
} from "@shocknet/clink-sdk";
import type { Event } from "nostr-tools";
import { redact } from "./redact.js";

export const CLINK_LAYER_ENV = "OMEGA_CLINK_LAYER";
export const CLINK_RELAY_ENV = "OMEGA_CLINK_RELAY_URL";
export const CLINK_SERVICE_KEY_ENV = "OMEGA_CLINK_SERVICE_KEY";

/** GFY error codes (CLINK spec §3.1). */
export const GFY_DENIED = 1;
export const GFY_TEMPORARY = 2;
export const GFY_EXPIRED = 3;
export const GFY_RATE_LIMITED = 4;
export const GFY_INVALID_AMOUNT = 5;
export const GFY_INVALID_REQUEST = 6;

/** Bounded queue: global cap + per-pubkey cap (SEC-2026-106b). */
export const PENDING_DEBIT_GLOBAL_CAP = 64;
export const PENDING_DEBIT_PER_PUBKEY_CAP = 4;

export interface PendingDebit {
  /** The request event id (the 21002 `e` tag the reply must reference). */
  debitId: string;
  /** The VERIFIED event author pubkey — the only acceptable principal. */
  authorPubkey: string;
  invoice: string;
  amountSat?: number;
  description?: string;
  receivedAtMs: number;
}

export interface DebitPayOutcome {
  status: "ok" | "GFY";
  preimage?: string;
  gfyCode?: number;
  gfyError?: string;
}

/** The relay transport the listener talks through (test seam — CI never touches a live relay). */
export interface RelayAdapter {
  subscribe(
    kinds: number[],
    toPubkey: string,
    onEvent: (event: Event) => void | Promise<void>,
  ): () => void;
  publish(event: Event): Promise<void>;
  close(): void;
}

export interface ClinkListenerDeps {
  /** The CLINK service signing key (hex 64; env-injected, redaction-registered). */
  serviceKeyHex: string;
  relayUrls: string[];
  /** The sidecar's mint path (the SAME one-mint-surface as the L-402 gateway). */
  mintInvoice: (amtSat: number, memo: string) => Promise<{ invoice: string; paymentHash: string }>;
  /** The sidecar's phoenixd pay path (host-initiated only). */
  payInvoice: (invoice: string) => Promise<{ preimage: string; actualAmountSat?: string }>;
  /** Read the environment-level kill BEFORE any mint/pay (0300 closure). */
  isKilled: () => boolean;
  relay: RelayAdapter;
  log: (message: string) => void;
}

/** The 21002/21001 reply the service publishes (kind + p/e/clink_version tags; NIP-44 body). */
function serviceReplyEvent(
  serviceKeyHex: string,
  requestEvent: Event,
  kind: number,
  body: unknown,
): Event {
  const content = nip44.encrypt(
    JSON.stringify(body),
    nip44.getConversationKey(hexToBytes(serviceKeyHex), requestEvent.pubkey),
  );
  const unsigned = {
    kind,
    content,
    created_at: Math.floor(Date.now() / 1000),
    pubkey: getPublicKey(hexToBytes(serviceKeyHex)),
    tags: [
      ["p", requestEvent.pubkey],
      ["e", requestEvent.id],
      ["clink_version", CLINK_VERSION],
    ],
  };
  return finalizeEvent(unsigned, hexToBytes(serviceKeyHex));
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export class ClinkListener {
  readonly #deps: ClinkListenerDeps;
  readonly #servicePubkey: string;
  #pendingDebits: Map<string, PendingDebit> = new Map();
  #unsubscribe: (() => void) | null = null;
  #stopped = true;

  constructor(deps: ClinkListenerDeps) {
    this.#deps = deps;
    this.#servicePubkey = getPublicKey(hexToBytes(deps.serviceKeyHex));
  }

  get servicePubkey(): string {
    return this.#servicePubkey;
  }

  get enabled(): boolean {
    return !this.#stopped;
  }

  /** Subscribe to kinds 21001/21002 addressed to the service pubkey. */
  start(): void {
    if (!this.#stopped) return;
    this.#stopped = false;
    this.#unsubscribe = this.#deps.relay.subscribe(
      [CLINK_OFFER_KIND, CLINK_DEBIT_KIND],
      this.#servicePubkey,
      (event) => this.#handleInbound(event),
    );
    this.#deps.log(`clink: listener started on ${redact(this.#deps.relayUrls.join(","))}`);
  }

  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.#unsubscribe?.();
    this.#unsubscribe = null;
    this.#pendingDebits.clear();
    this.#deps.relay.close();
    this.#deps.log("clink: listener stopped");
  }

  /**
   * Inbound event handling (SEC-2026-106a): the event SIGNATURE is verified
   * first; the verified author pubkey is the only principal that may pay.
   */
  async #handleInbound(event: Event): Promise<void> {
    if (this.#stopped) return;
    if (event.kind !== CLINK_OFFER_KIND && event.kind !== CLINK_DEBIT_KIND) return;
    if (!verifyEvent(event)) {
      this.#deps.log(`clink: ignored unverified ${event.kind} event ${event.id}`);
      return;
    }
    if (event.pubkey === this.#servicePubkey) {
      // Never self-echo: the service ignores its own events.
      return;
    }
    const hasP = (event.tags ?? []).some((tag) => tag[0] === "p" && tag[1] === this.#servicePubkey);
    if (!hasP) return;
    const version = (event.tags ?? []).find((tag) => tag[0] === "clink_version")?.[1];
    if (version !== CLINK_VERSION) {
      this.#deps.log(`clink: ignored ${event.kind} event with clink_version ${String(version)}`);
      return;
    }
    const conversationKey = nip44.getConversationKey(
      hexToBytes(this.#deps.serviceKeyHex),
      event.pubkey,
    );
    let body: unknown;
    try {
      body = JSON.parse(nip44.decrypt(event.content, conversationKey)) as unknown;
    } catch (error) {
      this.#deps.log(`clink: ignored ${event.kind} event with undecryptable content (${event.id})`);
      return;
    }
    if (event.kind === CLINK_OFFER_KIND) {
      await this.#handleOffer(event, body);
    } else {
      await this.#handleDebit(event, body);
    }
  }

  /** 21001 Offer: mint via phoenixd and reply with the BOLT11 (or an error shape). */
  async #handleOffer(requestEvent: Event, body: unknown): Promise<void> {
    try {
      const data = validateNofferData(body);
      if (!data.offer || typeof data.offer !== "string" || data.offer.length === 0) {
        await this.#reply(requestEvent, CLINK_OFFER_KIND, { error: "missing offer id", code: 1 });
        return;
      }
      if (this.#deps.isKilled()) {
        await this.#reply(requestEvent, CLINK_OFFER_KIND, { error: "service halted", code: 2 });
        return;
      }
      const amountSat = typeof data.amount_sats === "number" ? data.amount_sats : 0;
      const memo = typeof data.description === "string" ? data.description.slice(0, 100) : "clink offer";
      const { invoice } = await this.#deps.mintInvoice(amountSat, memo);
      await this.#reply(requestEvent, CLINK_OFFER_KIND, { bolt11: invoice });
    } catch (error) {
      this.#deps.log(`clink: offer mint failed (${redact(String((error as Error)?.message ?? error))})`);
      await this.#reply(requestEvent, CLINK_OFFER_KIND, { error: "temporary failure", code: 2 });
    }
  }

  /** 21002 Debit: validate + flood-gate + QUEUE. Never pays here (host-initiated). */
  async #handleDebit(requestEvent: Event, body: unknown): Promise<void> {
    try {
      const data = validateNdebitData(body);
      if (!data.bolt11 || typeof data.bolt11 !== "string" || data.bolt11.length === 0) {
        await this.#reply(requestEvent, CLINK_DEBIT_KIND, { res: "GFY", error: "invalid request: missing bolt11", code: GFY_INVALID_REQUEST });
        return;
      }
      // Flood control (SEC-2026-106b): bounded queue + per-pubkey cap.
      if (this.#pendingDebits.size >= PENDING_DEBIT_GLOBAL_CAP) {
        await this.#reply(requestEvent, CLINK_DEBIT_KIND, { res: "GFY", error: "queue full", code: GFY_RATE_LIMITED });
        return;
      }
      const perPubkey = [...this.#pendingDebits.values()].filter(
        (debit) => debit.authorPubkey === requestEvent.pubkey,
      ).length;
      if (perPubkey >= PENDING_DEBIT_PER_PUBKEY_CAP) {
        await this.#reply(requestEvent, CLINK_DEBIT_KIND, { res: "GFY", error: "too many pending debits", code: GFY_RATE_LIMITED });
        return;
      }
      const debit: PendingDebit = {
        debitId: requestEvent.id,
        authorPubkey: requestEvent.pubkey,
        invoice: data.bolt11,
        amountSat: typeof data.amount_sats === "number" ? data.amount_sats : undefined,
        description: typeof data.description === "string" ? data.description.slice(0, 100) : undefined,
        receivedAtMs: Date.now(),
      };
      this.#pendingDebits.set(debit.debitId, debit);
      this.#deps.log(`clink: queued debit ${debit.debitId} from ${debit.authorPubkey.slice(0, 12)}…`);
    } catch (error) {
      this.#deps.log(`clink: debit validation failed (${redact(String((error as Error)?.message ?? error))})`);
      await this.#reply(requestEvent, CLINK_DEBIT_KIND, { res: "GFY", error: "invalid request", code: GFY_INVALID_REQUEST });
    }
  }

  /** The host-initiated settlement (Rust pay_debit_invoice → stdio pay-debit). */
  async payDebit(
    debitId: string,
    principal: string,
  ): Promise<{ outcome: DebitPayOutcome; debit: PendingDebit | null }> {
    const debit = this.#pendingDebits.get(debitId);
    if (!debit) {
      return { outcome: { status: "GFY", gfyCode: GFY_INVALID_REQUEST, gfyError: "unknown debit" }, debit: null };
    }
    // SEC-2026-106a: the paying principal MUST be the verified event author.
    if (debit.authorPubkey.toLowerCase() !== principal.toLowerCase()) {
      this.#pendingDebits.delete(debitId);
      return { outcome: { status: "GFY", gfyCode: GFY_DENIED, gfyError: "principal mismatch" }, debit };
    }
    if (this.#deps.isKilled()) {
      this.#pendingDebits.delete(debitId);
      return { outcome: { status: "GFY", gfyCode: GFY_DENIED, gfyError: "service halted" }, debit };
    }
    try {
      const paid = await this.#deps.payInvoice(debit.invoice);
      this.#pendingDebits.delete(debitId);
      await this.#reply(
        { id: debit.debitId, pubkey: debit.authorPubkey } as Event,
        CLINK_DEBIT_KIND,
        { res: "ok", preimage: paid.preimage },
      );
      return { outcome: { status: "ok", preimage: paid.preimage }, debit };
    } catch (error) {
      this.#pendingDebits.delete(debitId);
      const gfyError = `payment failed: ${redact(String((error as Error)?.message ?? error))}`;
      await this.#reply(
        { id: debit.debitId, pubkey: debit.authorPubkey } as Event,
        CLINK_DEBIT_KIND,
        { res: "GFY", error: gfyError, code: GFY_TEMPORARY },
      );
      return { outcome: { status: "GFY", gfyCode: GFY_TEMPORARY, gfyError }, debit };
    }
  }

  /** Refuse a queued debit (no mandate / killed / policy) WITHOUT paying — GFY 1. */
  async refuseDebit(debitId: string, code: number, error: string): Promise<boolean> {
    const debit = this.#pendingDebits.get(debitId);
    if (!debit) return false;
    this.#pendingDebits.delete(debitId);
    await this.#reply(
      { id: debit.debitId, pubkey: debit.authorPubkey } as Event,
      CLINK_DEBIT_KIND,
      { res: "GFY", error, code },
    );
    return true;
  }

  /** Publish an encrypted reply to the requestor on the service channel. */
  async #reply(requestEvent: Event, kind: number, body: unknown): Promise<void> {
    const reply = serviceReplyEvent(this.#deps.serviceKeyHex, requestEvent, kind, body);
    await this.#deps.relay.publish(reply);
  }

  /** Read-only view of the pending-debit queue (the host poller's input). */
  pendingDebits(): PendingDebit[] {
    return [...this.#pendingDebits.values()];
  }

  /** Read-only status for the operator surface. */
  status(): { enabled: boolean; pendingDebits: number; servicePubkey: string } {
    return {
      enabled: !this.#stopped,
      pendingDebits: this.#pendingDebits.size,
      servicePubkey: this.#servicePubkey,
    };
  }
}