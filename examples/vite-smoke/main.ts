/**
 * Smoke test for @omnituum/secure-intake-client
 *
 * Verifies:
 * 1. Package imports correctly in Vite bundler
 * 2. Crypto capability detection works (WebCrypto + Kyber WASM)
 * 3. ID generation produces consistent results
 */

import {
  checkCryptoCapability,
  generateRequestId,
  normalizeMultiline,
} from "@omnituum/secure-intake-client";

const cryptoStatus = document.getElementById("crypto-status")!;
const idStatus = document.getElementById("id-status")!;
const output = document.getElementById("output")!;

const results: Record<string, unknown> = {};

async function runTests() {
  // Test 1: Crypto capability
  try {
    const crypto = await checkCryptoCapability();
    results.cryptoCapability = crypto;

    if (crypto.available) {
      cryptoStatus.className = "status pass";
      cryptoStatus.textContent = `✅ Crypto available (WebCrypto: ${crypto.webCrypto}, Kyber: ${crypto.kyber})`;
    } else {
      cryptoStatus.className = "status fail";
      cryptoStatus.textContent = `❌ Crypto not available: ${crypto.error}`;
    }
  } catch (e) {
    cryptoStatus.className = "status fail";
    cryptoStatus.textContent = `❌ Crypto check failed: ${e}`;
    results.cryptoError = String(e);
  }

  // Test 2: ID generation
  try {
    const testPayload = {
      kind: "test",
      email: "test@example.com",
      message: normalizeMultiline("Hello\r\nWorld"),
    };

    const id = generateRequestId(testPayload);
    results.generatedId = id;
    results.idLength = id.length;

    // Verify determinism
    const id2 = generateRequestId(testPayload);
    const isDeterministic = id === id2;
    results.isDeterministic = isDeterministic;

    if (id.length === 64 && isDeterministic) {
      idStatus.className = "status pass";
      idStatus.textContent = `✅ ID generation working (${id.slice(0, 16)}...)`;
    } else {
      idStatus.className = "status fail";
      idStatus.textContent = `❌ ID generation issue (length: ${id.length}, deterministic: ${isDeterministic})`;
    }
  } catch (e) {
    idStatus.className = "status fail";
    idStatus.textContent = `❌ ID generation failed: ${e}`;
    results.idError = String(e);
  }

  // Display full results
  output.textContent = JSON.stringify(results, null, 2);
}

runTests();
