/**
 * Deterministic ID generation
 */

import { blake3 } from "./primitives.js";

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Generate deterministic request ID from canonicalized payload.
 * Uses BLAKE3 hash of JSON-serialized payload.
 *
 * @param canonicalized - Object returned by config.canonicalize()
 * @returns 64-character hex string (BLAKE3 hash)
 */
export function generateRequestId(
  canonicalized: Record<string, unknown>
): string {
  const json = JSON.stringify(canonicalized);
  const encoder = new TextEncoder();
  const hash = blake3(encoder.encode(json));
  return bytesToHex(hash);
}
