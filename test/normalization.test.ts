/**
 * Unit tests for intake normalization
 *
 * Verifies:
 * - Newline canonicalization produces identical IDs across platforms
 * - normalizeMultiline helper works correctly
 *
 * Usage: npx tsx test/normalization.test.ts
 */

import { normalizeMultiline, generateRequestId } from "../src/index.js";
import { canonicalizePilotAccessPayload } from "../src/presets/pilot-access.js";
import type { RequestFormData } from "../src/presets/pilot-access.js";

function fail(msg: string): never {
  console.error(`✘ ${msg}`);
  process.exit(1);
}

function pass(msg: string): void {
  console.log(`✓ ${msg}`);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: normalizeMultiline helper
// ═══════════════════════════════════════════════════════════════════════════

const multilineTests = [
  { input: "hello\r\nworld", expected: "hello\nworld", desc: "Windows CRLF" },
  { input: "hello\rworld", expected: "hello\nworld", desc: "Old Mac CR" },
  { input: "hello\nworld", expected: "hello\nworld", desc: "Unix LF (unchanged)" },
  { input: "  hello\r\n  ", expected: "hello", desc: "Trims + normalizes" },
  { input: "a\r\nb\rc\nd", expected: "a\nb\nc\nd", desc: "Mixed line endings" },
];

for (const { input, expected, desc } of multilineTests) {
  const result = normalizeMultiline(input);
  if (result !== expected) {
    fail(
      `normalizeMultiline(${desc}): expected ${JSON.stringify(expected)}, got ${JSON.stringify(result)}`
    );
  }
  pass(`normalizeMultiline: ${desc}`);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Same content with different newlines → same ID (golden test)
// ═══════════════════════════════════════════════════════════════════════════

const baseFormData: RequestFormData = {
  email: "test@example.com",
  company: "Acme Corp",
  system: "Line one\nLine two\nLine three",
  useCase: "ai-audit",
  timeline: "q2-2025",
  compliance: ["soc2", "gdpr"],
};

// Same content with Windows line endings
const windowsFormData: RequestFormData = {
  ...baseFormData,
  system: "Line one\r\nLine two\r\nLine three",
};

// Same content with old Mac line endings
const oldMacFormData: RequestFormData = {
  ...baseFormData,
  system: "Line one\rLine two\rLine three",
};

// Same content with mixed line endings (chaotic paste)
const mixedFormData: RequestFormData = {
  ...baseFormData,
  system: "Line one\r\nLine two\rLine three",
};

const kind = "request_pilot_access" as const;

const unixNormalized = canonicalizePilotAccessPayload(baseFormData, kind);
const windowsNormalized = canonicalizePilotAccessPayload(windowsFormData, kind);
const oldMacNormalized = canonicalizePilotAccessPayload(oldMacFormData, kind);
const mixedNormalized = canonicalizePilotAccessPayload(mixedFormData, kind);

const unixId = generateRequestId(unixNormalized);
const windowsId = generateRequestId(windowsNormalized);
const oldMacId = generateRequestId(oldMacNormalized);
const mixedId = generateRequestId(mixedNormalized);

if (unixId !== windowsId) {
  fail(
    `Windows CRLF produced different ID:\n  Unix: ${unixId}\n  Windows: ${windowsId}`
  );
}
pass("Windows CRLF → same ID as Unix LF");

if (unixId !== oldMacId) {
  fail(
    `Old Mac CR produced different ID:\n  Unix: ${unixId}\n  Old Mac: ${oldMacId}`
  );
}
pass("Old Mac CR → same ID as Unix LF");

if (unixId !== mixedId) {
  fail(
    `Mixed line endings produced different ID:\n  Unix: ${unixId}\n  Mixed: ${mixedId}`
  );
}
pass("Mixed line endings → same ID as Unix LF");

// ═══════════════════════════════════════════════════════════════════════════
// Test: ID is deterministic (same input → same output)
// ═══════════════════════════════════════════════════════════════════════════

const id1 = generateRequestId(canonicalizePilotAccessPayload(baseFormData, kind));
const id2 = generateRequestId(canonicalizePilotAccessPayload(baseFormData, kind));

if (id1 !== id2) {
  fail(`ID not deterministic: ${id1} !== ${id2}`);
}
pass("ID is deterministic");

// Print the canonical ID for reference
console.log(`\n  Canonical ID: ${unixId.slice(0, 16)}...`);

console.log("\n✅ Normalization tests passed\n");
