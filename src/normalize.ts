/**
 * Normalization utilities for consistent hashing
 */

/**
 * Normalize multiline text for consistent hashing.
 * Collapses Windows (\r\n) and old Mac (\r) line endings to Unix (\n).
 * Apply to any textarea or multiline field to prevent platform-dependent IDs.
 */
export function normalizeMultiline(s: string): string {
  return s.trim().replace(/\r\n?/g, "\n");
}

/**
 * Normalize email for consistent hashing.
 * Trims whitespace and lowercases.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Normalize a string array for consistent hashing.
 * Returns a sorted copy.
 */
export function normalizeStringArray(arr: string[]): string[] {
  return [...arr].sort();
}
