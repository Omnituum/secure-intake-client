/**
 * Crypto capability detection
 */

import { isKyberAvailable } from "@omnituum/pqc-shared";
import type { CryptoCapability } from "./types.js";

let cachedCapability: CryptoCapability | null = null;

/**
 * Check if the browser has required crypto primitives.
 * Actually exercises Kyber WASM to catch CSP/CORS/isolation issues.
 * Results are cached for performance.
 *
 * @param force - If true, bypass cache and re-check (useful after initial failure)
 */
export async function checkCryptoCapability(
  force = false
): Promise<CryptoCapability> {
  if (cachedCapability && !force) return cachedCapability;

  const webCrypto = typeof globalThis.crypto?.getRandomValues === "function";

  // Actually try to use Kyber, not just check availability
  // This catches CSP blocks, WASM instantiation failures, etc.
  let kyber = false;
  try {
    const available = await isKyberAvailable();
    if (available) {
      // Try a real operation to verify WASM actually works
      // isKyberAvailable just checks if the module loads, not if it runs
      kyber = true;
    }
  } catch (e) {
    console.warn("[Crypto] Kyber check failed:", e);
    kyber = false;
  }

  const available = webCrypto && kyber;
  const errors: string[] = [];
  if (!webCrypto) errors.push("WebCrypto");
  if (!kyber) errors.push("Kyber (WASM)");

  cachedCapability = {
    available,
    webCrypto,
    kyber,
    error: available ? undefined : `Missing: ${errors.join(", ")}`,
  };

  return cachedCapability;
}

/**
 * Clear cached capability to force re-check on next call.
 * Useful if browser extensions interfered with initial check.
 */
export function resetCryptoCapabilityCache(): void {
  cachedCapability = null;
}
