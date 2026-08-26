//! Shared test fixture: build a minimal but well-formed signet BOLT11 invoice
//! whose `p` field carries a chosen payment hash (BOLT-11 encoding verified
//! against the spec examples in the WP-2 audit and the BOLT-11 spec).
//! Used by `fake-waved.mjs` and the WP-6 L-402 tests.

import { bech32 } from "@scure/base";

/**
 * Build a minimal signet BOLT11 (hrp `lntbs100u` = 100 μBTC = 10000 sats) with
 * `p` (payment hash), `s` (payment secret), and `d` (description) fields.
 * No signature field — the gateway only reads the `p` field, so the invoice
 * is structurally sufficient for the tests.
 */
export function buildTestBolt11(paymentHashHex) {
  const words = [];
  // 35-bit timestamp (7 words of 5 bits).
  const ts = BigInt(Math.floor(Date.now() / 1000));
  for (let i = 34; i >= 0; i -= 5) words.push(Number((ts >> BigInt(i)) & 0x1fn));
  // Tagged fields: type (5 bits) | data_length (10 bits, big-endian) |
  // data (data_length x 5 bits) — per BOLT-11.
  const pushField = (tag, dataBytes) => {
    const dataWords = bech32.toWords(dataBytes);
    words.push(tag, (dataWords.length >> 5) & 31, dataWords.length & 31, ...dataWords);
  };
  pushField(1, Buffer.from(paymentHashHex, "hex")); // p: payment hash (32 bytes)
  pushField(16, Buffer.from("c".repeat(64), "hex")); // s: payment secret (32 bytes)
  pushField(13, Buffer.from("fake waved demo invoice", "utf8")); // d
  // BOLT11 invoices exceed bech32's default 90-char cap; pass an explicit limit.
  return bech32.encode("lntbs100u", words, 4096);
}