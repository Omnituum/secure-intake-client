/**
 * Crypto capability detection.
 *
 * Only checks WebCrypto availability at module scope.
 * Kyber status is determined lazily — either via an explicit probe
 * or by the first hybrid encryption attempt.
 *
 * No @omnituum/pqc-shared import here (prevents WASM side effects).
 */

import type { CryptoCapability } from "./types.js";

let cachedCapability: CryptoCapability | null = null;

/**
 * Check browser crypto capability.
 *
 * - `available`: true if WebCrypto exists (can encrypt with X25519)
 * - `kyber`: starts as false; set to true after a successful hybrid load
 *
 * @param force - If true, bypass cache and re-check
 */
export async function checkCryptoCapability(
  force = false
): Promise<CryptoCapability> {
  if (cachedCapability && !force) return cachedCapability;

  const webCrypto = typeof globalThis.crypto?.getRandomValues === "function";
  const available = webCrypto;

  // Kyber status is NOT probed here — no WASM import at page load.
  // It stays false until tryLoadHybrid() succeeds during submit.
  // The badge will show "X25519 fallback" initially, then upgrade
  // to "PQC hybrid" after a successful hybrid operation.
  const kyber = false;

  cachedCapability = {
    available,
    webCrypto,
    kyber,
    error: !webCrypto ? "Missing: WebCrypto" : undefined,
  };

  return cachedCapability;
}

/**
 * Update the cached kyber status after a successful hybrid load.
 * Called internally by the submit path when hybrid encryption succeeds.
 */
export function setCachedKyberStatus(kyber: boolean): void {
  if (cachedCapability) {
    cachedCapability = { ...cachedCapability, kyber };
  }
}

/**
 * Clear cached capability to force re-check on next call.
 */
export function resetCryptoCapabilityCache(): void {
  cachedCapability = null;
}
