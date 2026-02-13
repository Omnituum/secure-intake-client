/**
 * @omnituum/secure-intake-client
 *
 * Post-quantum encrypted intake form submission client.
 * Zero top-level imports from @omnituum/pqc-shared — hybrid encryption
 * is loaded lazily via dynamic import to prevent WASM side effects
 * under strict CSP.
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

export type { HybridEnvelope } from "./envelope-types.js";
