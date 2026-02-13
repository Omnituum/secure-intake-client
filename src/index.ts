/**
 * @omnituum/secure-intake-client
 *
 * Post-quantum encrypted intake form submission client.
 *
 * @example
 * ```ts
 * import { submitSecureIntake, checkCryptoCapability } from "@omnituum/secure-intake-client";
 *
 * const config = {
 *   endpoint: "/api/intake",
 *   publicKeys: {
 *     x25519PubHex: "...",
 *     kyberPubB64: "...",
 *   },
 *   canonicalize: (data) => ({
 *     kind: "my_form",
 *     email: data.email.trim().toLowerCase(),
 *     // ... normalize fields for deterministic hashing
 *   }),
 * };
 *
 * // Check capability first
 * const crypto = await checkCryptoCapability();
 * if (!crypto.available) {
 *   console.error(crypto.error);
 * }
 *
 * // Submit
 * const result = await submitSecureIntake(formData, config);
 * if (result.ok) {
 *   console.log("Submitted:", result.id, result.status);
 * }
 * ```
 */

// Core submission
export { submitSecureIntake, encryptX25519Only } from "./submit.js";

// Crypto capability
export {
  checkCryptoCapability,
  resetCryptoCapabilityCache,
} from "./capability.js";

// ID generation (for consumers who need to compute IDs client-side)
export { generateRequestId, bytesToHex } from "./id.js";

// Normalization utilities
export {
  normalizeMultiline,
  normalizeEmail,
  normalizeStringArray,
} from "./normalize.js";

// Rate limiting (for testing/advanced use)
export { resetRateLimit } from "./ratelimit.js";

// Types
export type {
  IntakeConfig,
  SubmitOptions,
  SubmitResult,
  CryptoCapability,
  RateLimitConfig,
  PendingSubmission,
  HybridPublicKeys,
  DowngradeEvent,
} from "./types.js";
