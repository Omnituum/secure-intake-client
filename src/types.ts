/**
 * Shared types for secure intake client
 */

/**
 * Public keys for hybrid encryption (matches pqc-shared HybridPublicKeys).
 * Defined locally to avoid any pqc-shared import.
 */
export interface HybridPublicKeys {
  x25519PubHex: string;
  kyberPubB64: string;
}

/**
 * Result of a submission attempt
 */
export type SubmitResult =
  | { ok: true; id: string; status: "created" | "duplicate" }
  | { ok: false; error: string };

/**
 * Crypto capability check result
 */
export interface CryptoCapability {
  available: boolean;
  webCrypto: boolean;
  kyber: boolean;
  error?: string;
}

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  /** Maximum submissions per window */
  max: number;
  /** Window duration in milliseconds */
  windowMs: number;
}

/**
 * Configuration for intake client
 */
export interface IntakeConfig {
  /** API endpoint URL (e.g., "/api/intake" or full URL) */
  endpoint: string;

  /** Organization's public keys for hybrid encryption */
  publicKeys: {
    x25519PubHex: string;
    kyberPubB64: string;
  };

  /**
   * Canonicalization function for the payload.
   * Must return a deterministic, sorted object suitable for JSON.stringify.
   * The result is used for both encryption and ID generation.
   */
  canonicalize: (payload: unknown) => Record<string, unknown>;

  /** Wire protocol version (default: "loggie.intake.v1") */
  version?: string;

  /** Max plaintext size in bytes before encryption (default: 32KB) */
  maxPlaintextBytes?: number;

  /** Max envelope size in bytes after encryption (default: 56KB) */
  maxEnvelopeBytes?: number;

  /** Pending submission TTL in milliseconds (default: 5 min) */
  pendingTtlMs?: number;

  /** sessionStorage key for pending submissions (default: "loggie.intake.pending") */
  storageKey?: string;

  /** Rate limit config, or false to disable (default: { max: 2, windowMs: 60000 }) */
  rateLimit?: RateLimitConfig | false;

  /** Require Kyber to be available (default: false - falls back gracefully) */
  requireKyber?: boolean;

  /**
   * Callback fired when encryption downgrades from hybrid to X25519-only.
   * Local-only by default (console.warn). Provide a callback to pipe
   * to your own telemetry. Never fires in strict mode (requireKyber: true)
   * because strict mode throws instead of downgrading.
   */
  onDowngrade?: (event: DowngradeEvent) => void;

  /**
   * Include raw error messages in downgrade events (default: false).
   * When false, only the enum reason code is included — safe for telemetry.
   * Enable only for local debugging; raw errors may contain internal paths.
   */
  debugDowngrade?: boolean;
}

/**
 * Known downgrade reason codes.
 * Only these values are emitted in the `reason` field by default.
 * Raw error details are never included unless `debugDowngrade: true` is set.
 */
export type DowngradeReason =
  | "wasm_blocked"       // WASM compilation blocked by CSP
  | "module_load_failed" // dynamic import() of pqc-shared failed
  | "kyber_unavailable"  // Kyber runtime reports not available
  | "encrypt_failed"     // hybridEncrypt threw during execution
  | "unknown";           // catch-all for unexpected errors

/**
 * Structured event emitted when PQC encryption is unavailable
 * and the client falls back to X25519-only.
 *
 * Safe to forward to telemetry: `reason` is an enum code (never a raw
 * error message), `userAgent` and `cspHint` are the only contextual
 * fields, and `rawError` is only present when `debugDowngrade: true`.
 */
export interface DowngradeEvent {
  /** Fixed event name for structured logging */
  event: "omnituum.crypto.downgrade";
  /** Enum code for why hybrid encryption failed (safe to log) */
  reason: DowngradeReason;
  /** Suite used for the actual envelope */
  suite: string;
  /** Whether PQC was used (always false for downgrades) */
  pqcUsed: false;
  /** Policy setting at time of downgrade */
  requireKyber: false;
  /** Browser user agent, if available */
  userAgent?: string;
  /** Hint about CSP configuration, if detectable */
  cspHint?: string;
  /** Raw error message — only present when config.debugDowngrade is true */
  rawError?: string;
}

/**
 * Submission options
 */
export interface SubmitOptions {
  /** Honeypot field value - if set, submission is silently dropped */
  honeypot?: string;
}

/**
 * Pending submission state (stored in sessionStorage)
 */
export interface PendingSubmission {
  /** Deterministic request ID (BLAKE3 hash of normalized payload) */
  id: string;
  /** Timestamp when pending was set */
  ts: number;
}
