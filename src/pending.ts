/**
 * Pending submission tracking (sessionStorage-based idempotency)
 */

import type { PendingSubmission } from "./types.js";

const DEFAULT_STORAGE_KEY = "loggie.intake.pending";
const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Get pending submission ID if one exists and hasn't expired.
 */
export function getPendingId(
  storageKey = DEFAULT_STORAGE_KEY,
  ttlMs = DEFAULT_TTL_MS
): string | null {
  try {
    const raw = sessionStorage.getItem(storageKey);
    if (!raw) return null;
    const pending = JSON.parse(raw) as PendingSubmission;
    // Expire after TTL
    if (Date.now() - pending.ts > ttlMs) {
      clearPendingSubmission(storageKey);
      return null;
    }
    return pending.id;
  } catch {
    return null;
  }
}

/**
 * Set pending submission ID.
 */
export function setPendingId(
  id: string,
  storageKey = DEFAULT_STORAGE_KEY
): void {
  try {
    const pending: PendingSubmission = { id, ts: Date.now() };
    sessionStorage.setItem(storageKey, JSON.stringify(pending));
  } catch {
    // sessionStorage quota exceeded or unavailable - proceed without persistence
  }
}

/**
 * Clear pending submission.
 */
export function clearPendingSubmission(
  storageKey = DEFAULT_STORAGE_KEY
): void {
  try {
    sessionStorage.removeItem(storageKey);
  } catch {
    // Ignore errors
  }
}
