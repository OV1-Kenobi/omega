//! CLINK Offers/Debits layer tests (OMEGA-DELTA-0306, design §3, WP-C4).
//!
//! The ClinkListener is exercised through a FAKE relay adapter — CI never
//! touches a live strfry relay. The real SimplePool adapter is covered by
//! the delta 0306 check (install-gate + wiring presence), not by network
//! tests. Key invariants verified here:
//! - SEC-2026-106a: the paying principal MUST be the verified event author
//!   (the signature's pubkey — never a content field); a mismatch refuses
//!   with GFY 1 denied and NO pay call.
//! - SEC-2026-106b: the pending-debit queue is bounded (global + per-pubkey
//!   caps); overflow answers GFY 4 rate limited WITHOUT queueing.
//! - The listener is transport-only: it queues Debits and never pays on its
//!   own — payment happens ONLY through the host-initiated `payDebit`.
//! - The 0300 kill refuses the offer mint and the debit settlement.

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  CLINK_DEBIT_KIND,
  CLINK_OFFER_KIND,
  CLINK_VERSION,
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  nip44,
} from "@shocknet/clink-sdk";
import type { Event } from "nostr-tools";

import { ClinkListener, GFY_DENIED, GFY_RATE_LIMITED, PENDING_DEBIT_GLOBAL_CAP, PENDING_DEBIT_PER_PUBKEY_CAP, type RelayAdapter } from "../dist/clink.js";

/** In-memory relay seam: captures publishes, can inject inbound events. */
class FakeRelay implements RelayAdapter {
  published: Event[] = [];
  subscribed: Array<{ kinds: number[]; toPubkey: string }> = [];
  handler: ((event: Event) => void) | null = null;
  closed = false;

  subscribe(
    kinds: number[],
    toPubkey: string,
    onEvent: (event: Event) => void,
  ): () => void {
    this.subscribed.push({ kinds, toPubkey });
    this.handler = onEvent;
    return () => {
      this.handler = null;
    };
  }

  async publish(event: Event): Promise<void> {
    this.published.push(event);
  }

  close(): void {
    this.closed = true;
  }

  /** Deliver an inbound event to the listener (the relay's onevent path). */
  async deliver(event: Event): Promise<void> {
    if (this.handler) {
      await this.handler(event);
    }
  }
}

/** Build a signed 21002 Debit request addressed to the service pubkey. */
function signedDebitRequest(opts: {
  servicePubkey: string;
  privateKey: Uint8Array;
  body: unknown;
  kind?: number;
}): Event {
  const content = nip44.encrypt(
    JSON.stringify(opts.body),
    nip44.getConversationKey(opts.privateKey, opts.servicePubkey),
  );
  return finalizeEvent(
    {
      kind: opts.kind ?? CLINK_DEBIT_KIND,
      content,
      created_at: Math.floor(Date.now() / 1000),
      pubkey: getPublicKey(opts.privateKey),
      tags: [
        ["p", opts.servicePubkey],
        ["clink_version", CLINK_VERSION],
      ],
    },
    opts.privateKey,
  );
}

function makeListener(opts: {
  payCalls?: Array<{ invoice: string }>;
  mintCalls?: Array<{ amtSat: number; memo: string }>;
  killed?: boolean;
  relay?: FakeRelay;
}): { listener: ClinkListener; relay: FakeRelay; serviceKeyHex: string; servicePubkey: string; payCalls: Array<{ invoice: string }>; mintCalls: Array<{ amtSat: number; memo: string }> } {
  const serviceKeyHex = Buffer.from(generateSecretKey()).toString("hex");
  const servicePubkey = getPublicKey(Buffer.from(serviceKeyHex, "hex"));
  const relay = opts.relay ?? new FakeRelay();
  const payCalls = opts.payCalls ?? [];
  const mintCalls = opts.mintCalls ?? [];
  const listener = new ClinkListener({
    serviceKeyHex,
    relayUrls: ["wss://relay.invalid"],
    mintInvoice: async (amtSat, memo) => {
      mintCalls.push({ amtSat, memo });
      return { invoice: `lnbc${amtSat}u1pfixture`, paymentHash: "a".repeat(64) };
    },
    payInvoice: async (invoice) => {
      payCalls.push({ invoice });
      return { preimage: "b".repeat(64), actualAmountSat: "1004" };
    },
    isKilled: () => opts.killed ?? false,
    relay,
    log: () => {},
  });
  return { listener, relay, serviceKeyHex, servicePubkey, payCalls, mintCalls };
}

describe("CLINK listener (OMEGA-DELTA-0306)", () => {
  it("starts a subscription for kinds 21001/21002 addressed to the service pubkey", () => {
    const { listener, relay, servicePubkey } = makeListener({});
    listener.start();
    assert.equal(relay.subscribed.length, 1);
    assert.deepEqual(relay.subscribed[0]!.kinds, [CLINK_OFFER_KIND, CLINK_DEBIT_KIND]);
    assert.equal(relay.subscribed[0]!.toPubkey, servicePubkey);
    listener.stop();
  });

  it("queues a verified 21002 Debit; payment happens ONLY via host-initiated payDebit (transport-only)", async () => {
    const { listener, relay, servicePubkey, payCalls } = makeListener({});
    listener.start();
    const payerKey = generateSecretKey();
    const request = signedDebitRequest({
      servicePubkey,
      privateKey: payerKey,
      body: { bolt11: "lnbc10u1p0example", description: "test debit" },
    });
    await relay.deliver(request);
    // Queued, NOT paid — the transport never pays on its own.
    assert.equal(payCalls.length, 0);
    const pending = listener.pendingDebits();
    assert.equal(pending.length, 1);
    assert.equal(pending[0]!.authorPubkey, getPublicKey(payerKey));
    // Host-initiated settlement with the verified author as principal pays.
    const result = await listener.payDebit(request.id, getPublicKey(payerKey));
    assert.equal(result.outcome.status, "ok");
    assert.equal(payCalls.length, 1);
    assert.equal(payCalls[0]!.invoice, "lnbc10u1p0example");
    // The success response was published on the 21002 channel.
    const replies = relay.published.filter((event) => event.kind === CLINK_DEBIT_KIND);
    assert.equal(replies.length, 1);
    const reply = replies[0]!;
    assert.equal(reply.tags.some((tag) => tag[0] === "e" && tag[1] === request.id), true);
    assert.equal(reply.tags.some((tag) => tag[0] === "p" && tag[1] === getPublicKey(payerKey)), true);
    listener.stop();
  });

  it("SEC-2026-106a: a principal that is NOT the verified event author is refused with GFY 1 denied and NO pay call", async () => {
    const { listener, relay, servicePubkey, payCalls } = makeListener({});
    listener.start();
    const payerKey = generateSecretKey();
    const attackerKey = generateSecretKey();
    const request = signedDebitRequest({
      servicePubkey,
      privateKey: payerKey,
      body: { bolt11: "lnbc10u1p0example" },
    });
    await relay.deliver(request);
    const result = await listener.payDebit(request.id, getPublicKey(attackerKey));
    assert.equal(result.outcome.status, "GFY");
    assert.equal(result.outcome.gfyCode, GFY_DENIED);
    assert.equal(payCalls.length, 0, "the phoenixd pay path must never be reached");
    listener.stop();
  });

  it("SEC-2026-106b: the per-pubkey cap refuses additional debits with GFY 4 rate limited", async () => {
    const { listener, relay, servicePubkey, serviceKeyHex } = makeListener({});
    listener.start();
    const payerKey = generateSecretKey();
    for (let i = 0; i < PENDING_DEBIT_PER_PUBKEY_CAP; i += 1) {
      await relay.deliver(
        signedDebitRequest({
          servicePubkey,
          privateKey: payerKey,
          body: { bolt11: `lnbc10u1p0example${i}` },
        }),
      );
    }
    assert.equal(listener.pendingDebits().length, PENDING_DEBIT_PER_PUBKEY_CAP);
    // One more from the SAME pubkey is refused.
    const overflow = signedDebitRequest({
      servicePubkey,
      privateKey: payerKey,
      body: { bolt11: "lnbc10u1p0example-overflow" },
    });
    await relay.deliver(overflow);
    assert.equal(listener.pendingDebits().length, PENDING_DEBIT_PER_PUBKEY_CAP, "no overflow queued");
    const gfy = relay.published.filter(
      (event) => event.kind === CLINK_DEBIT_KIND && event.tags.some((tag) => tag[0] === "e" && tag[1] === overflow.id),
    );
    assert.equal(gfy.length, 1, "an overflow refusal is published on the 21002 channel");
    const decrypted = JSON.parse(
      nip44.decrypt(gfy[0]!.content, nip44.getConversationKey(Buffer.from(serviceKeyHex, "hex"), getPublicKey(payerKey))),
    ) as { res: string; code: number };
    assert.equal(decrypted.res, "GFY");
    assert.equal(decrypted.code, GFY_RATE_LIMITED);
    listener.stop();
  });

  it("SEC-2026-106b: the global cap bounds the whole queue", async () => {
    const { listener, relay, servicePubkey } = makeListener({});
    listener.start();
    // Saturate with distinct pubkeys up to the global cap.
    for (let i = 0; i < PENDING_DEBIT_GLOBAL_CAP; i += 1) {
      const payerKey = generateSecretKey();
      await relay.deliver(
        signedDebitRequest({
          servicePubkey,
          privateKey: payerKey,
          body: { bolt11: `lnbc10u1p0example-${i}` },
        }),
      );
    }
    assert.equal(listener.pendingDebits().length, PENDING_DEBIT_GLOBAL_CAP);
    const overflowKey = generateSecretKey();
    await relay.deliver(
      signedDebitRequest({
        servicePubkey,
        privateKey: overflowKey,
        body: { bolt11: "lnbc10u1p0example-global-overflow" },
      }),
    );
    assert.equal(listener.pendingDebits().length, PENDING_DEBIT_GLOBAL_CAP, "the global cap holds");
    listener.stop();
  });

  it("rejects an unverified (unsigned) event before any queueing", async () => {
    const { listener, relay, servicePubkey } = makeListener({});
    listener.start();
    const forged = {
      kind: CLINK_DEBIT_KIND,
      content: "forged",
      created_at: Math.floor(Date.now() / 1000),
      pubkey: "ab".repeat(32),
      tags: [
        ["p", servicePubkey],
        ["clink_version", CLINK_VERSION],
      ],
      id: "cd".repeat(32),
      sig: "ef".repeat(64),
    } as Event;
    await relay.deliver(forged);
    assert.equal(listener.pendingDebits().length, 0, "an unverified event must never queue");
    listener.stop();
  });

  it("rejects an event not addressed to the service pubkey", async () => {
    const { listener, relay, servicePubkey } = makeListener({});
    listener.start();
    const payerKey = generateSecretKey();
    const wrongRecipient = signedDebitRequest({
      servicePubkey: "aa".repeat(32), // a DIFFERENT service pubkey
      privateKey: payerKey,
      body: { bolt11: "lnbc10u1p0example" },
    });
    // Rewrite the p tag to the wrong recipient (the sender addressed another service).
    await relay.deliver(wrongRecipient);
    assert.equal(listener.pendingDebits().length, 0, "events for another service are ignored");
    // A valid one still queues (sanity).
    await relay.deliver(
      signedDebitRequest({
        servicePubkey,
        privateKey: payerKey,
        body: { bolt11: "lnbc10u1p0example-ok" },
      }),
    );
    assert.equal(listener.pendingDebits().length, 1);
    listener.stop();
  });

  it("mints a 21001 Offer through the same one-mint-surface and replies with the BOLT11", async () => {
    const { listener, relay, servicePubkey, serviceKeyHex, mintCalls } = makeListener({});
    listener.start();
    const payerKey = generateSecretKey();
    const request = signedDebitRequest({
      servicePubkey,
      privateKey: payerKey,
      kind: CLINK_OFFER_KIND,
      body: { offer: "my-offer-id", amount_sats: 500, description: "demo offer" },
    });
    await relay.deliver(request);
    assert.equal(mintCalls.length, 1);
    assert.equal(mintCalls[0]!.amtSat, 500);
    const replies = relay.published.filter((event) => event.kind === CLINK_OFFER_KIND);
    assert.equal(replies.length, 1);
    const body = JSON.parse(
      nip44.decrypt(replies[0]!.content, nip44.getConversationKey(Buffer.from(serviceKeyHex, "hex"), getPublicKey(payerKey))),
    ) as { bolt11: string };
    assert.match(body.bolt11, /^lnbc/);
    listener.stop();
  });

  it("the 0300 kill refuses the offer mint with the typed halt (SPEND_HALTED shape, no phoenixd mint)", async () => {
    const { listener, relay, servicePubkey, serviceKeyHex, mintCalls } = makeListener({ killed: true });
    listener.start();
    const payerKey = generateSecretKey();
    const request = signedDebitRequest({
      servicePubkey,
      privateKey: payerKey,
      kind: CLINK_OFFER_KIND,
      body: { offer: "my-offer-id", amount_sats: 500 },
    });
    await relay.deliver(request);
    assert.equal(mintCalls.length, 0, "a killed surface must not mint");
    const replies = relay.published.filter((event) => event.kind === CLINK_OFFER_KIND);
    assert.equal(replies.length, 1);
    const body = JSON.parse(
      nip44.decrypt(replies[0]!.content, nip44.getConversationKey(Buffer.from(serviceKeyHex, "hex"), getPublicKey(payerKey))),
    ) as { error: string; code: number };
    assert.equal(body.code, 2, "temporary failure on a killed mint");
    listener.stop();
  });

  it("a killed surface refuses the debit settlement (GFY denied, no pay call)", async () => {
    const { listener, relay, servicePubkey, payCalls } = makeListener({ killed: true });
    listener.start();
    const payerKey = generateSecretKey();
    const request = signedDebitRequest({
      servicePubkey,
      privateKey: payerKey,
      body: { bolt11: "lnbc10u1p0example" },
    });
    await relay.deliver(request);
    const result = await listener.payDebit(request.id, getPublicKey(payerKey));
    assert.equal(result.outcome.status, "GFY");
    assert.equal(result.outcome.gfyCode, GFY_DENIED);
    assert.equal(payCalls.length, 0);
    listener.stop();
  });

  it("refuseDebit publishes GFY without paying and drops the queue entry", async () => {
    const { listener, relay, servicePubkey } = makeListener({});
    listener.start();
    const payerKey = generateSecretKey();
    const request = signedDebitRequest({
      servicePubkey,
      privateKey: payerKey,
      body: { bolt11: "lnbc10u1p0example" },
    });
    await relay.deliver(request);
    assert.equal(listener.pendingDebits().length, 1);
    const refused = await listener.refuseDebit(request.id, GFY_DENIED, "denied by host policy");
    assert.equal(refused, true);
    assert.equal(listener.pendingDebits().length, 0);
    const gfy = relay.published.filter(
      (event) => event.kind === CLINK_DEBIT_KIND && event.tags.some((tag) => tag[0] === "e" && tag[1] === request.id),
    );
    assert.equal(gfy.length, 1);
    listener.stop();
  });

  it("stop() clears the queue and unsubscribes (teardown)", async () => {
    const { listener, relay, servicePubkey } = makeListener({});
    listener.start();
    const payerKey = generateSecretKey();
    await relay.deliver(
      signedDebitRequest({
        servicePubkey,
        privateKey: payerKey,
        body: { bolt11: "lnbc10u1p0example" },
      }),
    );
    assert.equal(listener.pendingDebits().length, 1);
    listener.stop();
    assert.equal(listener.pendingDebits().length, 0);
    assert.equal(relay.closed, true);
  });
});