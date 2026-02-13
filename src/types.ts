/**
 * Shared types for secure intake client
 */

// Re-export from pqc-shared for consumers
export type { HybridPublicKeys } from "@omnituum/pqc-shared";

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
}

/**
 * Structured event emitted when PQC encryption is unavailable
 * and the client falls back to X25519-only.
 */
export interface DowngradeEvent {
  /** Fixed event name for structured logging */
  event: "omnituum.crypto.downgrade";
  /** Why hybrid encryption failed */
  reason: string;
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
