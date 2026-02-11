/**
 * Core submission logic
 */

import { hybridEncrypt } from "@omnituum/pqc-shared";
import type { IntakeConfig, SubmitOptions, SubmitResult } from "./types.js";
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
const DEFAULT_MAX_ENVELOPE = 56 * 1024; // 56KB (leaves headroom for HTTP overhead under 64KB server limit)

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
    // Don't even call the endpoint, just fake success
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

    // Check crypto capability (defense in depth - UI should block too)
    const crypto = await checkCryptoCapability();
    if (!crypto.available) {
      return {
        ok: false,
        error: `Your browser cannot securely submit this form. ${crypto.error}. Please use a modern browser (Chrome, Firefox, Safari, Edge).`,
      };
    }

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

    const encrypted = await hybridEncrypt(plaintextBytes, {
      x25519PubHex: config.publicKeys.x25519PubHex,
      kyberPubB64: config.publicKeys.kyberPubB64,
    });

    // Build envelope
    const envelope = {
      v: version,
      id,
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

    // Mark as pending before network call (minimal: just ID)
    setPendingId(id, storageKey);

    // Submit to intake endpoint
    const response = await fetch(config.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: envelopeJson,
    });

    const status = response.status;

    // Handle response based on status
    if (status === 201 || status === 200) {
      // Success or duplicate - clear pending
      const result = await response.json();
      clearPendingSubmission(storageKey);
      if (result.ok) {
        recordSubmit();
        return { ok: true, id: result.id, status: result.status };
      }
      // Unexpected: 2xx but ok=false
      return { ok: false, error: result.error || "Unknown error" };
    }

    if (status >= 400 && status < 500) {
      // Client error (4xx) - won't succeed by retrying, clear pending
      clearPendingSubmission(storageKey);
      const errorData = await response.json().catch(() => ({}));
      return {
        ok: false,
        error: errorData.error || `Request error: ${status}`,
      };
    }

    // Server error (5xx) or other - keep pending for retry
    const errorData = await response.json().catch(() => ({}));
    return {
      ok: false,
      error: errorData.error || `Server error: ${status}. Please try again.`,
    };
  } catch (err) {
    // Network error - keep pending for retry
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
