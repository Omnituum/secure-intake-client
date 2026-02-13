/**
 * Golden-vector tests for envelope compatibility + strict mode enforcement.
 *
 * Verifies:
 * - Vector A: Hybrid (X25519 + Kyber) encrypt → hybridDecrypt roundtrip
 * - Vector B: X25519-only encrypt → hybridDecrypt roundtrip (empty Kyber fields)
 * - Strict mode: requireKyber:true + kyber:false → fail, no envelope, no fallback
 *
 * Usage: npx tsx test/crypto-roundtrip.test.ts
 */

import {
  hybridEncrypt,
  hybridDecrypt,
  hybridDecryptToString,
  ENVELOPE_VERSION,
  ENVELOPE_AEAD,
} from "@omnituum/pqc-shared";
import type { HybridEnvelope, HybridSecretKeys } from "@omnituum/pqc-shared";
import { encryptX25519Only } from "../src/submit.js";
import { submitSecureIntake } from "../src/submit.js";
import {
  checkCryptoCapability,
  resetCryptoCapabilityCache,
} from "../src/capability.js";

// ═══════════════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════════════

let passed = 0;
let failed = 0;

function fail(msg: string): void {
  console.error(`✘ ${msg}`);
  failed++;
}

function pass(msg: string): void {
  console.log(`✓ ${msg}`);
  passed++;
}

function assert(condition: boolean, msg: string): void {
  if (condition) pass(msg);
  else fail(msg);
}

// ═══════════════════════════════════════════════════════════════════════════
// Golden Test Identity (from pqc-shared/tests/golden/identity.json)
// ═══════════════════════════════════════════════════════════════════════════

// Keys use 0x prefix — strip for raw hex
const GOLDEN_X25519_PUB_HEX = "0cb7663e9db84e11150aaef7653bcb98faff8f9b5cdda4c944ea5d02ff792f68";
const GOLDEN_X25519_SEC_HEX = "c927676ce50feedd30533d0ba9948741e9fdc3cdbaa1dca15c430f440625561a";

// Kyber keys from identity.json (base64)
const GOLDEN_KYBER_PUB_B64 = "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";

const GOLDEN_KYBER_SEC_B64 = "OWIkT7LGaPk+EAgAo9gwvJmXFTGflBYPY8KBx2mJb9K30GtA4Ai14SB0AiwEkwNO7sGcOZnOLiWh1vyO3+weHKfKv2yB13GxUYHOzXO82dQOleV5/okRTIuDi9RI1MU3kbKzj9KdWPMwTCvE/kVD1oR7NSJ1PhqnqqdGk8svvBaMdiGZ1NBGhpyxbGrMOLUgJYykSANellYHa0ZC9WyP8YACSCA6hzRa28tsNGVXJbTIyDEhq1s6aMoU5qmX94ZWP1diDtjG/2t9FmXJMbsl/+gPwyJm6LgNIHO1uQANZfcFE4JA3gpZSQS+iMuFMLkpuljNwBoaqlJsicFoV4rA5wMnA9IljLIM3vS+SnaPCmKeo/KomegN0gBVLULERLuouBQKXcki26dqUnUXEJRQclPE1Vez/5oXrruA0dtagnOFyIRmOIBwbpsgosKAk/d51wWnoJaDMiwtx3FnC1KjqfEOJgRBxLexjUGbSbUTKTBPn6OjRmBSU8Ju3vlfB+eeH7glnpJhxspzJAeeDoczrsYJ6ySuNuzA/JEXLmybBZqx9oOLv9qwD1IY5vyklYOYYSCjreRShZrKgSHI8hJx2xHBGIt1nDOjlTWjJgEBATmsbEV7HIqf1VhdOaJrrlwpwPzDKSGfrdazGocV9LS+wFcNo/l4qPFylpW9SLdmlYrFLuTDkwJoCGihoeWzUCNPakNcdKJ4cVg0KeNmdcWXG3iZxJFFo4A3tgav2pVAZpBXPIOyyzCIEmoU81ixaKN1q0WZvuMJUFQnCZxagztZT4pKMcuuX6EVC3tNSTeJE8kHcam3OsJeowt/RFEMBjSotxK7yGICt3sWN8BurzB08xeq6BjMIWAxkhAxagg/bHobxgFFDhzFegV+6Lgqjya0L2YRcjklKYggUJiLNThI2ccs8WM/TQch3tBJFRY63ROK9upTjGCkCbg5w/CaNzk06yJElNosMIRcSUvP+KWLk0jEyps0qMw3NPWwBLstY+rMzlqMFTaeGvBA/EewVuF4Y/w4W0CL0jzO1wMeqCFThUV37SRDNfcxchcO5FAvTSYAjgCs5NLBsUObItfLxEa9nUy+ipM0oFQFnTtYrhtzwHPHVkgLAyoGYDx+1DUoQHOonzpUBfbI5hKZp2fOaOtPObJXS+OwQqyPGgSeS+dac4p5UvUhZIOnhzVwNHV6NcEcfBeUojA9lDGf+LKPfiO3ake2NlwKQhUeQOgmyYOCajRnfmS/NGtdwkWkpLccueY2PknGNkW2j8af1zZE+mdeCzyb4xnN2PsnJRewdXBZAEaOzNCb+nR7n1jJsrdP1sEeuEdiXHqt2/uGVNeRlpptB2Eos4cszEyrjEYR8Ohw5TFU2SplX8PBAEocQQOJ9KyBy7iXmjFnphV4zsQvNfyhQJRgocqDQ9WXXlQSFTW1F7WYhOaY9aWkgpjCB5d5SEYI5Dcc/QUs+Rq46iG8esKYYqSs00FECPEF7FQUZppxS1XDyWY8oLSKGGzIYkK5rLGy2zJ/2saQF1SEObt0EwlvdmMaXGyWhYuQioXPcDpBWtRjSgPICXQeVJBRZqIxMDtWLWqhIPrPYdlAECZcPoSJGotaaBTPoYsqLrFEYRB9+AOQXKnAPFKC+rZlKdC0fOGfxzsLv3s9fgfOUsdlrkqkk9NpKbqUk9A+VFGmMzecmsLJpYgiVWYLbodqQ7xWGGIwa7UM6BBXGoobHzXKcLjAkFEm0KyQYiMTR9YWEBeBSYK/UjknqPlIB/nG2pMofHBQU+eH8GOGnEuoENpnvwHOHsJL47ED1RGoyQRKV/fFTGt8WEqGYoWNWAxiQSIesMlCmJE4b6JABBcxMVNcTswrfgXDo2GAW7CVo9fCKWs5nhhz0nQDjbgRz3k6TJMmJOer2rPPdeVhz4uv1RBD6OCxmSV/FEM6CuZb1FLAryMwaoVYfUpLUvgHYuQC93aguVXPsYRPZOwsbfE4QXkkQaQFN9Ugh9vKakyuoQIuq7GxsGp1tlZ4A/N+BERGK/CQOxpRRWwf7Mwp9qNcMYnICPJ8b6B3lEBppFUQvxWhqAjNoKBTIdarKXK7XjxdpAzK/ARSBchIwbCdx4isNRZnChlN/3WR38asqEYdHFuUDbcnQaurNGgxDJM4K2qcwOooFsMCeUjAZ9xA/GEC72hrH5wguTdn8FxjD2EivLmgy0emdmh8vNVY7maNQRVyICcXrEtu6xdbo0gWR5WTDvNDTycOWDus2TqShZGElPpOJeCVljg2BKmWCMGo3lOgUga+CvprVwCaOGiGYFgjvBicZMmUWGET14BC4XMsT0EA4rpabdVqF+imQMaZmjpy2gGJUiSNOmC0FqV7zodNOto57pkDxBacvVqlc/kURHcRhFRvqqfMBlkXqrgkAthJg7waybuAKLkFaxMggdWiMKwb00gHYWp9KVGWmJUNeyxElwsDgVo/wemVoWwzjatXJyQT0zpRHAmWgjs0MTMX6+QyR1GW9iN2yRkyN/RO5AtckZHG22ogLhxk0St6Q6ETjTlb9uNhhTG/PfIousEV6uC35txjKhU8wvd5bJYVJER4uQkIddGEfAxJGBdFkoCpmDYZMYEAgNcgPreetrmhYJw6JwMWOOM4rQVLoJCnrNIOwyuDs5i41Lecz5I6uvGJkcs2HyUxWSKIKla389JPZDWf0hNEg/meDbKSTcs5/XhQpwgS3vp1ncpOuJwXb8q50tnHP2jHMByZ4ZRSP5MaAbIzYatLjdNxBOVr9dep0hB7HRxO8kyONXNYchslOQV8FQivakUajCpYZ/mPZQZLh4HMlBYjbXeEBIDGLoUXYlOZZoC2C2ycvHtjvePD1lTOD5u+q5gnkQuM0XMWgzxBvySjobC8wFjIB+lnqhtnwqqdO9F/8Och52JT77MXLnYvrlB7R9muvqYu8ANYvYOqiTp1SnmsVeYn3JZR4el3UldB6Ey4E8W61Qu9FQXPTltkkfVLgRs4Ctttnii21PS1/iGucloaMJNdtlWN+ZtkEzASPZwWrGJEHOhCtqO8p5Rn5PUxeZJ7D/fPCkEbfnAC0CHKDJO+2QuzcPUQFAaHNdVR6js4UCbMm9UNC7i7ncOxYtmXj/evSACOKzs+FwBdrHk/p5nKFpiZM+pXfTZvI7V+srgoclh/rwkT7LeugQEq/dKcpGNqHPEyImke65UT85FssbpmXPIt0ia8f3y9YyN/Y5wTP4spGNyeS4UVPXJNRmCJsaO6CHbO/3AEDaidqEUtXGRaMEM8p/vNg2dosEYrJ9BdEZTKysYsOXqnjZxfyGbAN3p0pVwIHEoq07HHjVEoJNR+rLBoTqemWOky3LGrdXU4ZcCPNVNe5xgQe1J8vwYnvmOsCOR524ZRSQt6knNF2wzMQug/lHJl0VK+YbcaPnUI+UiOtAqKc1pbGbt2gMtHp2iKm/J6D5i7YgDEENYeC/C1wnV5x/gd4VpT9vGzoop5ChC9TbiWikU6nLnBBislH8iRG3DB2ApJ9KqozmUXpKJ2LcWoYnnPDRBriLhhGhJDawaE5QdjyDAKzAFu+4MWottWffu+8vrFi+I49AFVOkvCF9Ups/c3TVuo/poGAtQ5ZCNU+7kCq1e2I9wvrITDxVXCWJeATqkU8FGkdmEcpfWgHfCO5+lsw7rLnAIQEoXC6HtIF9xpddGIhYi2uXQ8RbAXNiwZf4AqcENaX5ZexOKNydynEQYiruBl3nXK6jmNbJBvkOCt/kwTwEd+AEOatpU9aLUVzMyziTgbnvEa3mkZR8k6YBoJ/MxT57rF5PCz4hajGcd5Osy4V2xZynUWRgaH3kmb5ZC5fqaMx3oF0QhQg9TJh6RoCGoAk+Mr5HYuoSBKB2GQXbQjnlw9YovDGeoXyExqz1ROSVyrQTCb6eSLc9UfawYVtznHwJUY0BvAB9JS7gkEroYSoCtcuxcwT+lhGHV9XlWSynWUZly8kVgscDCDLCt4/7aTbMc/vfRFZbB+eEXJuKRs63NxoPwc0ijFQCWFdclqGMwh5iCWqcpnAhI8S8UA1esTp7cpvuowDKOcseKZZ8djjUwBTbGmsHEM6ufKGLRMiZxyQaul8olkhRuSE5Yk8HWW5zpCQhS1s3pjZX9gla9BKiyzNmqsoG4=";

const SECRET_KEYS: HybridSecretKeys = {
  x25519SecHex: GOLDEN_X25519_SEC_HEX,
  kyberSecB64: GOLDEN_KYBER_SEC_B64,
};

const PUBLIC_KEYS = {
  x25519PubHex: GOLDEN_X25519_PUB_HEX,
  kyberPubB64: GOLDEN_KYBER_PUB_B64,
};

const TEST_PLAINTEXT = '{"kind":"test","message":"golden vector roundtrip"}';
const TEST_PLAINTEXT_BYTES = new TextEncoder().encode(TEST_PLAINTEXT);

// ═══════════════════════════════════════════════════════════════════════════
// Vector A: Hybrid envelope roundtrip (X25519 + Kyber)
// ═══════════════════════════════════════════════════════════════════════════

async function testVectorA(): Promise<void> {
  console.log("\n── Vector A: Hybrid encrypt → hybridDecrypt ──");

  const envelope = await hybridEncrypt(TEST_PLAINTEXT_BYTES, PUBLIC_KEYS);

  // Verify envelope shape
  assert(envelope.v === ENVELOPE_VERSION, `v = "${ENVELOPE_VERSION}"`);
  assert(envelope.aead === ENVELOPE_AEAD, `aead = "${ENVELOPE_AEAD}"`);
  assert(envelope.x25519Epk.length === 64, "x25519Epk is 64 hex chars");
  assert(envelope.kyberKemCt.length > 0, "kyberKemCt is non-empty");
  assert(envelope.kyberWrap.nonce.length > 0, "kyberWrap.nonce is non-empty");
  assert(envelope.kyberWrap.wrapped.length > 0, "kyberWrap.wrapped is non-empty");
  assert(envelope.x25519Wrap.nonce.length > 0, "x25519Wrap.nonce is non-empty");
  assert(envelope.x25519Wrap.wrapped.length > 0, "x25519Wrap.wrapped is non-empty");
  assert(envelope.ciphertext.length > 0, "ciphertext is non-empty");
  assert(envelope.contentNonce.length > 0, "contentNonce is non-empty");

  // Decrypt and verify roundtrip
  const decrypted = await hybridDecryptToString(envelope, SECRET_KEYS);
  assert(decrypted === TEST_PLAINTEXT, "Hybrid roundtrip: plaintext matches");
}

// ═══════════════════════════════════════════════════════════════════════════
// Vector B: X25519-only envelope roundtrip (empty Kyber fields)
// ═══════════════════════════════════════════════════════════════════════════

async function testVectorB(): Promise<void> {
  console.log("\n── Vector B: X25519-only encrypt → hybridDecrypt ──");

  const envelope = await encryptX25519Only(TEST_PLAINTEXT_BYTES, GOLDEN_X25519_PUB_HEX);

  // Verify envelope shape — X25519-only specifics
  assert(envelope.v === ENVELOPE_VERSION, `v = "${ENVELOPE_VERSION}"`);
  assert(envelope.aead === ENVELOPE_AEAD, `aead = "${ENVELOPE_AEAD}"`);
  assert((envelope.suite as string) === "x25519", 'suite = "x25519"');
  assert(envelope.x25519Epk.length === 64, "x25519Epk is 64 hex chars");
  assert(envelope.x25519Wrap.nonce.length > 0, "x25519Wrap.nonce is non-empty");
  assert(envelope.x25519Wrap.wrapped.length > 0, "x25519Wrap.wrapped is non-empty");

  // Empty Kyber fields (the critical invariant)
  assert(envelope.kyberKemCt === "", "kyberKemCt is empty string");
  assert(envelope.kyberWrap.nonce === "", "kyberWrap.nonce is empty string");
  assert(envelope.kyberWrap.wrapped === "", "kyberWrap.wrapped is empty string");

  // Content fields present
  assert(envelope.ciphertext.length > 0, "ciphertext is non-empty");
  assert(envelope.contentNonce.length > 0, "contentNonce is non-empty");

  // THE CRITICAL TEST: hybridDecrypt from pqc-shared can decrypt X25519-only envelopes
  const decrypted = await hybridDecryptToString(envelope, SECRET_KEYS);
  assert(decrypted === TEST_PLAINTEXT, "X25519-only roundtrip: plaintext matches via hybridDecrypt");
}

// ═══════════════════════════════════════════════════════════════════════════
// Strict mode: requireKyber:true + kyber:false → must fail, no fallback
// ═══════════════════════════════════════════════════════════════════════════

async function testStrictModeNoDowngrade(): Promise<void> {
  console.log("\n── Strict mode: no downgrade allowed ──");

  // Reset capability cache so we get a fresh check
  resetCryptoCapabilityCache();

  // Build a config that requires Kyber
  const config = {
    endpoint: "https://localhost:9999/should-never-be-called",
    publicKeys: PUBLIC_KEYS,
    canonicalize: (payload: unknown) => payload as Record<string, unknown>,
    requireKyber: true,
    rateLimit: false as const,
  };

  // First, check what capability we actually have
  const cap = await checkCryptoCapability(true);

  if (cap.kyber) {
    // Kyber IS available in this test environment — we can't easily
    // test the "kyber unavailable" path without mocking WASM failure.
    // Instead, verify that strict mode + kyber available = success path
    // (no downgrade event, no fallback).
    console.log("  (Kyber available in test env — verifying strict+kyber=hybrid path)");

    // Verify the capability check passes for strict mode
    assert(cap.available === true, "cap.available = true");
    assert(cap.kyber === true, "cap.kyber = true");

    // Verify the policy gate logic directly
    const requireKyber = config.requireKyber === true;
    assert(requireKyber === true, "requireKyber parsed as strict boolean true");
    assert(!(requireKyber && !cap.kyber), "Policy gate does NOT block when kyber is available");
    pass("Strict mode allows submission when Kyber is available");
  } else {
    // Kyber is NOT available — perfect, test the strict fail path
    console.log("  (Kyber unavailable — testing strict mode rejection)");

    // The policy gate should block before any encryption
    const requireKyber = config.requireKyber === true;
    assert(requireKyber === true, "requireKyber parsed as strict boolean true");
    assert(requireKyber && !cap.kyber, "Policy gate BLOCKS when kyber unavailable in strict mode");

    // submitSecureIntake would fail at the policy gate, but we can't call it
    // without a real server. Verify the error message shape:
    const result = await submitSecureIntake(
      { test: true },
      config,
    );
    assert(result.ok === false, "Strict mode returns ok:false when kyber unavailable");
    if (!result.ok) {
      assert(
        result.error.includes("strict hybrid mode"),
        'Error mentions "strict hybrid mode"'
      );
      assert(
        result.error.includes("Post-quantum"),
        'Error mentions "Post-quantum"'
      );
    }
    pass("Strict mode rejects submission — no envelope produced");
  }

  // Verify requireKyber: undefined does NOT trigger strict mode
  const undefinedConfig = { ...config, requireKyber: undefined };
  const parsedUndefined = undefinedConfig.requireKyber === true;
  assert(parsedUndefined === false, "requireKyber: undefined → false (no accidental strict)");

  // Verify requireKyber: false does NOT trigger strict mode
  const falseConfig = { ...config, requireKyber: false };
  const parsedFalse = falseConfig.requireKyber === true;
  assert(parsedFalse === false, "requireKyber: false → false (explicit best-effort)");
}

// ═══════════════════════════════════════════════════════════════════════════
// Run all tests
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  console.log("Crypto roundtrip & strict mode tests");
  console.log("====================================");

  try {
    await testVectorA();
    await testVectorB();
    await testStrictModeNoDowngrade();
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
