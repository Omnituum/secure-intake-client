/**
 * Crypto roundtrip + hybrid AND-property tests.
 *
 * Verifies:
 * - Vector A: Hybrid v2 (X25519 + ML-KEM-1024) encrypt → decrypt roundtrip,
 *   and that the envelope is v2-shaped (single AND-combined `ckWrap`, no
 *   independent per-primitive wraps).
 * - AND property: an attacker who compromises ONLY the classical (X25519)
 *   secret, or ONLY the post-quantum (ML-KEM) secret, cannot decrypt a v2
 *   envelope. Both secrets are required.
 * - Vector B: X25519-only classical fallback still roundtrips (legacy shape,
 *   emitted only on the explicit downgrade path — gated separately by #5).
 *
 * Usage: npx tsx test/crypto-roundtrip.test.ts
 */

// pqc-shared is imported here ONLY for the decrypt side (simulating the
// operator/admin). In the actual client bundle, pqc-shared is never loaded at
// module scope.
import {
  hybridEncrypt,
  hybridDecryptToString,
  generateHybridIdentity,
  getPublicKeys,
  getSecretKeys,
  ENVELOPE_AEAD,
} from "@omnituum/pqc-shared";
import type { HybridSecretKeys, HybridIdentity } from "@omnituum/pqc-shared";
import { encryptX25519Only } from "../src/submit.js";

// Frozen v2 wire values (see envelope-registry OmniHybridV2).
const HYBRID_V2_VERSION = "omnituum.hybrid.v2";
const HYBRID_V2_SUITE = "x25519+mlkem1024";

// ═══════════════════════════════════════════════════════════════════════════
// Test harness
// ═══════════════════════════════════════════════════════════════════════════

let passed = 0;
let failed = 0;

function pass(msg: string): void {
  console.log(`✓ ${msg}`);
  passed++;
}
function fail(msg: string): void {
  console.error(`✘ ${msg}`);
  failed++;
}
function assert(condition: boolean, msg: string): void {
  condition ? pass(msg) : fail(msg);
}

/** Assert that an async decrypt attempt does NOT succeed (throws or wrong pt). */
async function assertCannotDecrypt(
  fn: () => Promise<string>,
  expectedPlaintext: string,
  msg: string
): Promise<void> {
  try {
    const out = await fn();
    if (out === expectedPlaintext) fail(`${msg} (UNEXPECTEDLY DECRYPTED)`);
    else pass(`${msg} (returned non-matching output, not the plaintext)`);
  } catch {
    pass(`${msg} (rejected)`);
  }
}

const TEST_PLAINTEXT = '{"kind":"test","message":"v2 hybrid roundtrip"}';
const TEST_PLAINTEXT_BYTES = new TextEncoder().encode(TEST_PLAINTEXT);

// ═══════════════════════════════════════════════════════════════════════════
// Identities (generated fresh — models a real recipient + an unrelated attacker)
// ═══════════════════════════════════════════════════════════════════════════

async function mustGenerate(name: string): Promise<HybridIdentity> {
  const id = await generateHybridIdentity(name);
  if (!id) throw new Error(`Failed to generate identity: ${name} (Kyber unavailable?)`);
  return id;
}

// ═══════════════════════════════════════════════════════════════════════════
// Vector A: Hybrid v2 roundtrip + shape
// ═══════════════════════════════════════════════════════════════════════════

async function testVectorA(recipient: HybridIdentity): Promise<void> {
  console.log("\n── Vector A: Hybrid v2 encrypt → decrypt ──");

  const envelope = await hybridEncrypt(TEST_PLAINTEXT_BYTES, getPublicKeys(recipient));

  assert(envelope.v === HYBRID_V2_VERSION, `v = "${HYBRID_V2_VERSION}"`);
  assert(envelope.suite === HYBRID_V2_SUITE, `suite = "${HYBRID_V2_SUITE}"`);
  assert(envelope.aead === ENVELOPE_AEAD, `aead = "${ENVELOPE_AEAD}"`);
  assert(envelope.x25519Epk.length === 64, "x25519Epk is 64 hex chars");
  assert(envelope.kyberKemCt.length > 0, "kyberKemCt is non-empty");

  // v2 shape: a SINGLE combined wrap, not independent per-primitive wraps.
  const anyEnv = envelope as unknown as Record<string, unknown>;
  assert("ckWrap" in anyEnv, "has single AND-combined 'ckWrap'");
  assert(!("x25519Wrap" in anyEnv), "no legacy 'x25519Wrap'");
  assert(!("kyberWrap" in anyEnv), "no legacy 'kyberWrap'");

  const decrypted = await hybridDecryptToString(envelope, getSecretKeys(recipient));
  assert(decrypted === TEST_PLAINTEXT, "v2 roundtrip: plaintext matches (both secrets)");
}

// ═══════════════════════════════════════════════════════════════════════════
// AND property: neither secret alone can decrypt a v2 envelope
// ═══════════════════════════════════════════════════════════════════════════

async function testAndProperty(
  recipient: HybridIdentity,
  attacker: HybridIdentity
): Promise<void> {
  console.log("\n── Hybrid v2 AND property (both secrets required) ──");

  const envelope = await hybridEncrypt(TEST_PLAINTEXT_BYTES, getPublicKeys(recipient));
  const recip = getSecretKeys(recipient);
  const atk = getSecretKeys(attacker);

  // Attacker compromised ONLY the classical half: has the recipient's X25519
  // secret, but only their own (wrong) ML-KEM secret.
  const classicalOnly: HybridSecretKeys = {
    x25519SecHex: recip.x25519SecHex,
    kyberSecB64: atk.kyberSecB64,
  };
  await assertCannotDecrypt(
    () => hybridDecryptToString(envelope, classicalOnly),
    TEST_PLAINTEXT,
    "X25519 secret alone cannot decrypt v2 (post-quantum break required too)"
  );

  // Attacker compromised ONLY the post-quantum half: has the recipient's
  // ML-KEM secret, but only their own (wrong) X25519 secret.
  const pqOnly: HybridSecretKeys = {
    x25519SecHex: atk.x25519SecHex,
    kyberSecB64: recip.kyberSecB64,
  };
  await assertCannotDecrypt(
    () => hybridDecryptToString(envelope, pqOnly),
    TEST_PLAINTEXT,
    "ML-KEM secret alone cannot decrypt v2 (classical break required too)"
  );

  // Sanity: both together still works.
  const ok = await hybridDecryptToString(envelope, recip);
  assert(ok === TEST_PLAINTEXT, "both secrets together decrypt correctly");
}

// ═══════════════════════════════════════════════════════════════════════════
// Vector B: X25519-only classical fallback still roundtrips (legacy shape)
// ═══════════════════════════════════════════════════════════════════════════

async function testVectorB(recipient: HybridIdentity): Promise<void> {
  console.log("\n── Vector B: X25519-only fallback → decrypt ──");

  const envelope = await encryptX25519Only(
    TEST_PLAINTEXT_BYTES,
    getPublicKeys(recipient).x25519PubHex
  );

  assert(envelope.suite === "x25519", 'suite = "x25519" (classical fallback)');
  assert(envelope.kyberKemCt === "", "kyberKemCt is empty (no PQC)");

  const decrypted = await hybridDecryptToString(envelope as any, getSecretKeys(recipient));
  assert(decrypted === TEST_PLAINTEXT, "X25519-only roundtrip: plaintext matches");
}

// ═══════════════════════════════════════════════════════════════════════════
// Run
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  console.log("Crypto roundtrip & hybrid AND-property tests");
  console.log("============================================");

  try {
    const recipient = await mustGenerate("recipient");
    const attacker = await mustGenerate("attacker");

    await testVectorA(recipient);
    await testAndProperty(recipient, attacker);
    await testVectorB(recipient);
  } catch (err) {
    console.error("\nFatal error:", err);
    process.exit(1);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error("\n✘ TESTS FAILED\n");
    process.exit(1);
  }
  console.log("\n✅ All crypto roundtrip tests passed\n");
}

main();
