/**
 * Pilot Access Form Preset
 *
 * Pre-configured client for the Loggie pilot access request form.
 *
 * @example
 * ```ts
 * import { createPilotAccessClient } from "@omnituum/secure-intake-client/presets/pilot-access";
 *
 * const client = createPilotAccessClient({
 *   endpoint: "/api/intake",
 *   publicKeys: {
 *     x25519PubHex: import.meta.env.VITE_OMNITUUM_X25519_PUB_HEX,
 *     kyberPubB64: import.meta.env.VITE_OMNITUUM_KYBER_PUB_B64,
 *   },
 * });
 *
 * const result = await client.submit(formData, "request_pilot_access");
 * ```
 */

import { submitSecureIntake } from "../submit.js";
import { checkCryptoCapability, resetCryptoCapabilityCache } from "../capability.js";
import { normalizeMultiline, normalizeEmail, normalizeStringArray } from "../normalize.js";
import { generateRequestId } from "../id.js";
import type { IntakeConfig, SubmitResult, CryptoCapability } from "../types.js";

/**
 * Pilot access request form data shape
 */
export interface RequestFormData {
  email: string;
  company: string;
  system: string;
  useCase: string;
  timeline: string;
  compliance: string[];
}

/**
 * Request kind for pilot access forms
 */
export type PilotAccessKind = "request_access" | "request_pilot_access";

/**
 * Configuration for pilot access client (without canonicalize - we provide it)
 */
export type PilotAccessConfig = Omit<IntakeConfig, "canonicalize">;

/**
 * Canonicalize pilot access form data for deterministic hashing.
 *
 * @param data - Raw form data
 * @param kind - Request kind
 * @returns Canonicalized payload
 */
export function canonicalizePilotAccessPayload(
  data: RequestFormData,
  kind: PilotAccessKind
): Record<string, unknown> {
  return {
    kind,
    email: normalizeEmail(data.email),
    company: data.company.trim(),
    system: normalizeMultiline(data.system),
    useCase: data.useCase,
    timeline: data.timeline,
    compliance: normalizeStringArray(data.compliance),
  };
}

/**
 * Pilot access client interface
 */
export interface PilotAccessClient {
  /**
   * Submit a pilot access request.
   *
   * @param data - Form data
   * @param kind - Request kind (default: "request_pilot_access")
   * @param honeypot - Honeypot field value (should be empty for real users)
   */
  submit(
    data: RequestFormData,
    kind?: PilotAccessKind,
    honeypot?: string
  ): Promise<SubmitResult>;

  /**
   * Check browser crypto capability.
   *
   * @param force - Force re-check (bypass cache)
   */
  checkCryptoCapability(force?: boolean): Promise<CryptoCapability>;

  /**
   * Reset crypto capability cache.
   */
  resetCryptoCapabilityCache(): void;

  /**
   * Generate request ID for given form data without submitting.
   * Useful for deduplication checks.
   */
  generateId(data: RequestFormData, kind?: PilotAccessKind): string;
}

/**
 * Create a pilot access client with the given configuration.
 *
 * @param config - Configuration (endpoint + publicKeys required)
 * @returns Pilot access client
 */
export function createPilotAccessClient(
  config: PilotAccessConfig
): PilotAccessClient {
  return {
    submit(
      data: RequestFormData,
      kind: PilotAccessKind = "request_pilot_access",
      honeypot?: string
    ): Promise<SubmitResult> {
      return submitSecureIntake(
        data,
        {
          ...config,
          canonicalize: (payload) =>
            canonicalizePilotAccessPayload(payload as RequestFormData, kind),
        },
        { honeypot }
      );
    },

    checkCryptoCapability,
    resetCryptoCapabilityCache,

    generateId(
      data: RequestFormData,
      kind: PilotAccessKind = "request_pilot_access"
    ): string {
      return generateRequestId(canonicalizePilotAccessPayload(data, kind));
    },
  };
}

// Re-export types for convenience
export type { SubmitResult, CryptoCapability } from "../types.js";
