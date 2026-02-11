/**
 * Client-side rate limiting
 */

import type { RateLimitConfig } from "./types.js";

const DEFAULT_WINDOW_MS = 60 * 1000; // 1 minute
const DEFAULT_MAX = 2;

// Per-instance tracking (resets on page reload)
const submitTimestamps: number[] = [];

/**
 * Check if rate limit allows submission.
 *
 * @param config - Rate limit configuration
 * @param isRetry - If true, bypass rate limit (retries are always allowed)
 * @returns true if submission is allowed
 */
export function checkRateLimit(
  config: RateLimitConfig | false | undefined,
  isRetry: boolean
): boolean {
  // Disabled
  if (config === false) return true;

  // Retries bypass rate limit
  if (isRetry) return true;

  const windowMs = config?.windowMs ?? DEFAULT_WINDOW_MS;
  const max = config?.max ?? DEFAULT_MAX;
  const now = Date.now();

  // Remove timestamps outside window
  while (
    submitTimestamps.length > 0 &&
    submitTimestamps[0] < now - windowMs
  ) {
    submitTimestamps.shift();
  }

  return submitTimestamps.length < max;
}

/**
 * Record a successful submission for rate limiting.
 */
export function recordSubmit(): void {
  submitTimestamps.push(Date.now());
}

/**
 * Reset rate limit state (for testing).
 */
export function resetRateLimit(): void {
  submitTimestamps.length = 0;
}
