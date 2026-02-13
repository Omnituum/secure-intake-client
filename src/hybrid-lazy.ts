/**
 * Lazy hybrid encryption module boundary.
 *
 * This is the ONLY module that imports @omnituum/pqc-shared, and it does so
 * via dynamic import() — never at module scope. This prevents Kyber WASM
 * from loading during module evaluation, which would abort under strict CSP.
 *
 * Invariant: nothing else in secure-intake-client imports pqc-shared directly.
 */

import type { HybridEnvelope } from "./envelope-types.js";

/** Cached module reference after first successful load */
let pqcModule: typeof import("@omnituum/pqc-shared") | null = null;

/**
 * Attempt to load the pqc-shared module dynamically.
 * Returns null if the import fails (e.g., WASM blocked by CSP).
 */
export async function tryLoadHybrid(): Promise<typeof import("@omnituum/pqc-shared") | null> {
  if (pqcModule) return pqcModule;
  try {
    pqcModule = await import("@omnituum/pqc-shared");
    return pqcModule;
  } catch {
    return null;
  }
}

/**
 * Probe whether Kyber (PQC) is available by attempting to load the module
 * and calling isKyberAvailable(). Never touches WASM at module scope.
 *
 * @returns true if Kyber is usable, false otherwise
 */
export async function probeKyberLazy(): Promise<boolean> {
  try {
    const mod = await tryLoadHybrid();
    if (!mod) return false;
    return await mod.isKyberAvailable();
  } catch {
    return false;
  }
}

/**
 * Attempt hybrid encryption via lazy-loaded pqc-shared.
 * Throws if the module can't be loaded or encryption fails.
 */
export async function tryHybridEncryptLazy(
  plaintext: Uint8Array,
  publicKeys: { x25519PubHex: string; kyberPubB64: string }
): Promise<HybridEnvelope> {
  const mod = await tryLoadHybrid();
  if (!mod) {
    throw new Error(
      "Hybrid encryption unavailable: pqc-shared module failed to load (WASM blocked by CSP?)"
    );
  }
  return mod.hybridEncrypt(plaintext, publicKeys);
}
