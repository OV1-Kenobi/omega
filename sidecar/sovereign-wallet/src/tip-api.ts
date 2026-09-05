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

export const TIP_API_TTL_MS_DEFAULT = 30_000;
export const TIP_HEIGHT_MAX = 0x7fffffff; // sanity cap ~2B blocks

export const PRIMARY_URL = "https://mempool.space/api/blocks/tip/height";
export const FALLBACK_URL = "https://blockstream.info/api/blocks/tip/height";

export const TTL_MS: number =
  Number.parseInt(process.env.OMEGA_TIP_API_TTL_MS ?? "", 10) || TIP_API_TTL_MS_DEFAULT;
export const PRIMARY_URL_OVERRIDE: string =
  process.env.OMEGA_TIP_API_PRIMARY_URL || PRIMARY_URL;
export const FALLBACK_URL_OVERRIDE: string =
  process.env.OMEGA_TIP_API_FALLBACK_URL || FALLBACK_URL;

/** Fail-closed tip error (the escrow gate substitutes nothing on this). */
export const TIP_HEIGHT_UNAVAILABLE = "TIP_HEIGHT_UNAVAILABLE";

let cachedTip: { height: number; expiresAt: number } | null = null;

export function tipHeightUnavailable(message?: string): Error {
  const msg = message || "observed tip height unavailable from public API";
  return new Error(
    JSON.stringify({
      code: TIP_HEIGHT_UNAVAILABLE,
      message: msg,
      details: "",
      retryable: false,
      remediation:
        "check public tip API reachability (mempool.space / blockstream.info); the escrow timeout gate fails closed on this error",
    }),
  );
}

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
      throw new Error(`non-integer response body`);
    }
    const height = Number.parseInt(trimmed, 10);
    if (!Number.isSafeInteger(height) || height < 0 || height > TIP_HEIGHT_MAX) {
      throw new Error(`height out of sanity range`);
    }
    return height;
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
}

async function getTipHeightInternal(): Promise<number> {
  // Try primary first; fall back once before failing closed.
  try {
    return await fetchTipHeight(PRIMARY_URL_OVERRIDE);
  } catch (primaryError) {
    try {
      return await fetchTipHeight(FALLBACK_URL_OVERRIDE);
    } catch (fallbackError) {
      throw tipHeightUnavailable(
        `primary and fallback tip endpoints failed (${(primaryError as Error).message}; ${(fallbackError as Error).message})`,
      );
    }
  }
}

export async function getTipHeight(): Promise<number> {
  // Test seam (design §4.1): force the fail-closed path without network.
  // Never set in production; shipped defaults always attempt the endpoints.
  if (process.env.OMEGA_TIP_API_DISABLE === "1") {
    throw tipHeightUnavailable("tip API disabled by OMEGA_TIP_API_DISABLE (test seam)");
  }
  const now = Date.now();
  if (cachedTip && cachedTip.expiresAt > now) {
    return cachedTip.height;
  }
  const height = await getTipHeightInternal();
  cachedTip = { height, expiresAt: Date.now() + TTL_MS };
  return height;
}

export function resetTipCacheForTesting(): void {
  cachedTip = null;
}

export function getTipCacheInfo(): {
  cached: boolean;
  height: number | null;
  expiresAt: number | null;
} {
  if (cachedTip) {
    return { cached: true, height: cachedTip.height, expiresAt: cachedTip.expiresAt };
  }
  return { cached: false, height: null, expiresAt: null };
}
