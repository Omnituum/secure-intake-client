/**
 * Core submission logic.
 *
 * Zero top-level imports from @omnituum/pqc-shared.
 * All primitives come from local ./primitives.ts (pure JS).
 * Hybrid encryption is lazy-loaded via ./hybrid-lazy.ts.
 */

import {
  nacl,
  rand32,
  rand24,
  b64,
  toHex,
  fromHex,
  hkdfSha256,
  u8,
  secretboxRaw,
  ENVELOPE_VERSION,
  ENVELOPE_AEAD,
} from "./primitives.js";
import { tryHybridEncryptLazy } from "./hybrid-lazy.js";
import { setCachedKyberStatus } from "./capability.js";
import type { IntakeConfig, SubmitOptions, SubmitResult, DowngradeEvent, DowngradeReason } from "./types.js";
import type { OmniHybridV1 } from "@omnituum/envelope-registry";
import { generateRequestId } from "./id.js";
import { checkCryptoCapability } from "./capability.js";
import {
  getPendingId,
  setPendingId,
  clearPendingSubmission,
} from "./pending.js";
import { checkRateLimit, recordSubmit } from "./ratelimit.js";

// Defaults
const DEFAULT_VERSION = "loggie.intake.v1";
const DEFAULT_MAX_PLAINTEXT = 32 * 1024; // 32KB
const DEFAULT_MAX_ENVELOPE = 56 * 1024; // 56KB

/**
 * Submit an encrypted intake request.
 *
 * @param payload - Raw payload data (will be canonicalized by config.canonicalize)
 * @param config - Intake configuration
 * @param opts - Submission options
 * @returns Submission result
 */
export async function submitSecureIntake(
  payload: unknown,
  config: IntakeConfig,
  opts: SubmitOptions = {}
): Promise<SubmitResult> {
  try {
    // Honeypot check - bots often fill hidden fields
    if (opts.honeypot) {
      return { ok: true, id: "", status: "created" };
    }

    // Canonicalize payload
    const canonicalized = config.canonicalize(payload);

    // Generate deterministic ID
    const id = generateRequestId(canonicalized);

    // Get config values with defaults
    const storageKey = config.storageKey ?? "loggie.intake.pending";
    const pendingTtlMs = config.pendingTtlMs ?? 5 * 60 * 1000;
    const maxPlaintext = config.maxPlaintextBytes ?? DEFAULT_MAX_PLAINTEXT;
    const maxEnvelope = config.maxEnvelopeBytes ?? DEFAULT_MAX_ENVELOPE;
    const version = config.version ?? DEFAULT_VERSION;

    // Check if this is a retry of a pending submission
    const pendingId = getPendingId(storageKey, pendingTtlMs);
    const isRetry = pendingId === id;

    // Rate limit check (bypassed for retries)
    if (!checkRateLimit(config.rateLimit, isRetry)) {
      return {
        ok: false,
        error:
          "Too many submissions. Please wait a moment before trying again.",
      };
    }

    // Check crypto capability (WebCrypto only — no WASM probe)
    const crypto = await checkCryptoCapability();
    if (!crypto.available) {
      return {
        ok: false,
        error: `Your browser cannot securely submit this form. ${crypto.error}. Please use a modern browser (Chrome, Firefox, Safari, Edge).`,
      };
    }

    const requireKyber = config.requireKyber === true;
    const attemptHybrid = config.attemptHybrid !== false; // default true

    // Encrypt canonicalized payload
    const plaintext = JSON.stringify(canonicalized);
    const encoder = new TextEncoder();

    // Size guard before encryption
    const plaintextBytes = encoder.encode(plaintext);
    if (plaintextBytes.length > maxPlaintext) {
      return {
        ok: false,
        error: `Submission too large (${Math.round(plaintextBytes.length / 1024)}KB). Please shorten your responses.`,
      };
    }

    // Encrypt: attempt hybrid (lazy), fall back to X25519-only if allowed
    let encrypted: OmniHybridV1;
    let pqcUsed = false;

    if (!attemptHybrid) {
      // Hybrid explicitly disabled — go straight to X25519-only.
      // No WASM chunk loaded, no dynamic import, no abort risk.
      encrypted = await encryptX25519Only(plaintextBytes, config.publicKeys.x25519PubHex);
    } else {
      try {
        // This dynamically imports pqc-shared — the ONLY place it's loaded.
        // Under strict CSP this will fail, and we fall back below.
        encrypted = await tryHybridEncryptLazy(plaintextBytes, {
          x25519PubHex: config.publicKeys.x25519PubHex,
          kyberPubB64: config.publicKeys.kyberPubB64,
        });
        pqcUsed = true;
        // Update capability cache now that hybrid succeeded
        setCachedKyberStatus(true);
      } catch (hybridErr) {
        if (requireKyber) {
          // Strict mode: no fallback allowed
          return {
            ok: false,
            error: "Post-quantum encryption unavailable in this environment (WASM blocked by CSP or unsupported browser). Cannot submit in strict hybrid mode.",
          };
        }
        // Best-effort mode: fall back to X25519-only
        const rawMsg = hybridErr instanceof Error ? hybridErr.message : String(hybridErr);
        const reason: DowngradeReason = classifyDowngradeReason(rawMsg);
        const downgradeEvent: DowngradeEvent = {
          event: "omnituum.crypto.downgrade",
          reason,
          suite: X25519_ONLY_SUITE,
          pqcUsed: false,
          requireKyber: false,
          userAgent: typeof navigator !== "undefined" ? navigator.userAgent : undefined,
          cspHint: reason === "wasm_blocked"
            ? "WASM compilation likely blocked by Content-Security-Policy"
            : undefined,
          ...(config.debugDowngrade ? { rawError: rawMsg } : {}),
        };
        console.warn("[Intake] Crypto downgrade:", downgradeEvent);
        config.onDowngrade?.(downgradeEvent);
        encrypted = await encryptX25519Only(plaintextBytes, config.publicKeys.x25519PubHex);
      }
    }

    // Build envelope with pqcUsed flag for truthful reporting
    const envelope = {
      v: version,
      id,
      pqcUsed,
      encrypted: JSON.stringify(encrypted),
    };

    const envelopeJson = JSON.stringify(envelope);

    // Size guard after encryption (catches base64 expansion)
    if (envelopeJson.length > maxEnvelope) {
      return {
        ok: false,
        error: `Encrypted submission too large. Please shorten your responses.`,
      };
    }

    // Mark as pending before network call
    setPendingId(id, storageKey);

    // Submit to intake endpoint
    const response = await fetch(config.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: envelopeJson,
    });

    const status = response.status;

    if (status === 201 || status === 200) {
      const result = await response.json();
      clearPendingSubmission(storageKey);
      if (result.ok) {
        recordSubmit();
        return { ok: true, id: result.id, status: result.status };
      }
      return { ok: false, error: result.error || "Unknown error" };
    }

    if (status >= 400 && status < 500) {
      clearPendingSubmission(storageKey);
      const errorData = await response.json().catch(() => ({}));
      return {
        ok: false,
        error: errorData.error || `Request error: ${status}`,
      };
    }

    const errorData = await response.json().catch(() => ({}));
    return {
      ok: false,
      error: errorData.error || `Server error: ${status}. Please try again.`,
    };
  } catch (err) {
    console.error("Intake submission error:", err);
    return {
      ok: false,
      error:
        err instanceof Error
          ? err.message
          : "Submission failed. Please try again.",
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Downgrade reason classification
// ═══════════════════════════════════════════════════════════════════════════

/** Map raw error messages to a safe enum code (never exposes internal paths). */
function classifyDowngradeReason(msg: string): DowngradeReason {
  const lower = msg.toLowerCase();
  if (lower.includes("csp") || lower.includes("wasm") || lower.includes("webassembly"))
    return "wasm_blocked";
  if (lower.includes("failed to load") || lower.includes("module") || lower.includes("import"))
    return "module_load_failed";
  if (lower.includes("unavailable") || lower.includes("not available"))
    return "kyber_unavailable";
  if (lower.includes("encrypt"))
    return "encrypt_failed";
  return "unknown";
}

// ═══════════════════════════════════════════════════════════════════════════
// X25519-ONLY ENCRYPTION (pure JS, no WASM, no pqc-shared)
// ═══════════════════════════════════════════════════════════════════════════

/** Suite identifier for X25519-only envelopes (no Kyber) */
const X25519_ONLY_SUITE = "x25519" as const;

function hkdfFlex(ikm: Uint8Array, salt: string, info: string): Uint8Array {
  return hkdfSha256(ikm, { salt: u8(salt), info: u8(info), length: 32 });
}

/**
 * Encrypt using X25519 ECDH only (classical, no WASM required).
 * Produces an envelope structurally compatible with OmniHybridV1
 * but with empty Kyber fields and suite set to "x25519".
 *
 * @internal Exported for golden-vector tests
 */
export async function encryptX25519Only(
  plaintext: Uint8Array,
  recipientX25519PubHex: string
): Promise<OmniHybridV1> {
  // 1. Generate random content key
  const CK = rand32();

  // 2. Encrypt content with content key (NaCl secretbox)
  const contentNonce = rand24();
  const ciphertext = secretboxRaw(CK, plaintext, contentNonce);

  // 3. Wrap content key with X25519 ECDH
  const ephKp = nacl.box.keyPair();
  const recipientPk = fromHex(recipientX25519PubHex);
  const shared = nacl.scalarMult(ephKp.secretKey, recipientPk);
  const kek = hkdfFlex(shared, "omnituum/x25519", "wrap-ck");
  const wrapNonce = rand24();
  const wrapped = secretboxRaw(kek, CK, wrapNonce);

  return {
    v: ENVELOPE_VERSION,
    suite: X25519_ONLY_SUITE,
    aead: ENVELOPE_AEAD,
    x25519Epk: toHex(ephKp.publicKey),
    x25519Wrap: {
      nonce: b64(wrapNonce),
      wrapped: b64(wrapped),
    },
    kyberKemCt: "",
    kyberWrap: { nonce: "", wrapped: "" },
    contentNonce: b64(contentNonce),
    ciphertext: b64(ciphertext),
    meta: {
      createdAt: new Date().toISOString(),
    },
  };
}
