/**
 * Public Tip API Client (OMEGA-DELTA-0304 / SEC-2026-087 revision)
 *
 * Replaces the waved getinfo probe as the wallet-height source.
 * Primary: mempool.space/api/blocks/tip/height
 * Fallback: blockstream.info/api/blocks/tip/height
 * Both return the tip height as a plain integer (text/plain).
 *
 * TTL cache (default 30s), fail-closed on any error/timeout/non-integer response.
 * Safe-direction staleness: a stale cached height only delays an escrow
 * timeout refund, never causes a premature release/refund.
 */

import { TIP_HEIGHT_UNAVAILABLE } from "./protocol.js";
import { redact } from "./redact.js";

const TIP_API_TTL_MS_DEFAULT = 30_000;
const TIP_HEIGHT_MAX = 0x7fffffff; // sanity cap ~2B blocks

const PRIMARY_URL = "https://mempool.space/api/blocks/tip/height";
const FALLBACK_URL = "https://blockstream.info/api/blocks/tip/height";

const TTL_MS = parseInt(process.env.OMEGA_TIP_API_TTL_MS ?? "") || TIP_API_TTL_MS_DEFAULT;
const PRIMARY_URL_OVERRIDE = process.env.OMEGA_TIP_API_PRIMARY_URL || PRIMARY_URL;
const FALLBACK_URL_OVERRIDE = process.env.OMEGA_TIP_API_FALLBACK_URL || FALLBACK_URL;

let cachedTip: { height: number; expiresAt: number } | null = null;

export interface BlockHeightResult {
  block_height: number;
}

export function tipHeightUnavailable(message?: string): Error {
  const env = TIP_HEIGHT_UNAVAILABLE;
  const msg = message || "observed tip height unavailable from public API";
  return new Error(JSON.stringify({
    code: TIP_HEIGHT_UNAVAILABLE,
    message,
    details: "",
    retryable: false,
    remediation: "check public tip API reachability (mempool.space / blockstream.info); the escrow timeout gate fails closed on this error",
  }));
}

let cachedTip: { height: number; expiresAt: number } | null = null;

async function fetchTipHeight(url: string): Promise<number> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Sigma/CLINK-tip-client" },
    });
    clearTimeout(timeout);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    const text = await response.text();
    const trimmed = text.trim();
    if (!/^\d+$/.test(trimmed)) {
      throw new Error(`non-integer response: ${trimmed}`);
    }
    const height = parseInt(trimmed, 10);
    if (height < 0 || height > 0x7fffffff) {
      throw new Error(`height out of sanity range: ${height}`);
    }
    return height;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

async function getTipHeightInternal(): Promise<number> {
  // Try primary
  try {
    return await fetchTipHeight(PRIMARY_URL_OVERRIDE);
  } catch (e) {
    // Try fallback
    try {
      return await fetchTipHeight(FALLBACK_URL_OVERRIDE);
    } catch (e2) {
      throw tipHeightUnavailable(
        `primary: ${(e as Error).message}; fallback: ${(e2 as Error).message}`
      );
    }
  }
}

export async function getTipHeight(): Promise<number> {
  const now = Date.now();
  // Check cache
  if (cachedTip && cachedTip.expiresAt > Date.now()) {
    return cachedTip.height;
  }
  // Fetch fresh
  const height = await getTipHeightInternal();
  cachedTip = { height, expiresAt: Date.now() + TTL_MS };
  return height;
}

export function resetTipCacheForTesting(): void {
  cachedTip = null;
}

export function getTipCacheInfo(): { cached: boolean; height: number | null; expiresAt: number | null } {
  if (cachedTip) {
    return { cached: true, height: cachedTip.height, expiresAt: cachedTip.expiresAt };
  }
  return { cached: false, height: null, expiresAt: null };
}

// Config constants (exported for tests)
export const PRIMARY_URL_OVERRIDE = PRIMARY_URL_OVERRIDE;
export const FALLBACK_URL_OVERRIDE = FALLBACK_URL_OVERRIDE;
export const TTL_MS = TTL_MS;
export const TIP_HEIGHT_MAX = TIP_HEIGHT_MAX;
export const PRIMARY_URL = PRIMARY_URL;
export const FALLBACK_URL = FALLBACK_URL;