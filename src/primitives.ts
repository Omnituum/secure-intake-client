/**
 * Pure-JS cryptographic primitives for secure-intake-client.
 *
 * These replicate the exact algorithms from @omnituum/pqc-shared/primitives
 * but without importing pqc-shared's barrel export (which triggers Kyber
 * WASM initialization as a side effect).
 *
 * Dependencies: @noble/hashes (pure JS), tweetnacl (pure JS)
 */

import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { blake3 as nobleBlake3 } from "@noble/hashes/blake3.js";
import nacl from "tweetnacl";

// ═══════════════════════════════════════════════════════════════════════════
// TEXT ENCODING
// ═══════════════════════════════════════════════════════════════════════════

const textEncoder = new TextEncoder();

export function u8(s: string | Uint8Array): Uint8Array {
  return typeof s === "string" ? textEncoder.encode(s) : s;
}

// ═══════════════════════════════════════════════════════════════════════════
// BASE64
// ═══════════════════════════════════════════════════════════════════════════

export function b64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// ═══════════════════════════════════════════════════════════════════════════
// HEX
// ═══════════════════════════════════════════════════════════════════════════

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  const normalized = s.length % 2 ? "0" + s : s;
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// RANDOMNESS (Web Crypto API)
// ═══════════════════════════════════════════════════════════════════════════

export function rand32(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

export function rand24(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(24));
}

// ═══════════════════════════════════════════════════════════════════════════
// HASHING
// ═══════════════════════════════════════════════════════════════════════════

export function blake3(data: Uint8Array): Uint8Array {
  return nobleBlake3(data);
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY DERIVATION (HKDF-SHA-256, RFC 5869)
// ═══════════════════════════════════════════════════════════════════════════

export function hkdfSha256(
  ikm: Uint8Array,
  opts?: { salt?: Uint8Array; info?: Uint8Array; length?: number }
): Uint8Array {
  const salt = opts?.salt ?? new Uint8Array(32);
  const info = opts?.info ?? new Uint8Array(0);
  const L = opts?.length ?? 32;

  // Extract
  const prk = hmac(nobleSha256, salt, ikm);

  // Expand
  let t = new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  for (let i = 1; i <= Math.ceil(L / 32); i++) {
    const input = new Uint8Array(t.length + info.length + 1);
    input.set(t, 0);
    input.set(info, t.length);
    input[input.length - 1] = i;
    t = new Uint8Array(hmac(nobleSha256, prk, input));
    chunks.push(t);
  }

  const out = new Uint8Array(L);
  let off = 0;
  for (const c of chunks) {
    out.set(c.subarray(0, L - off), off);
    off += c.length;
    if (off >= L) break;
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// SYMMETRIC ENCRYPTION (NaCl secretbox = XSalsa20-Poly1305)
// ═══════════════════════════════════════════════════════════════════════════

export function secretboxRaw(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  return nacl.secretbox(plaintext, nonce, key);
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS (from canonical envelope registry)
// ═══════════════════════════════════════════════════════════════════════════

import { OMNI_VERSIONS } from '@omnituum/envelope-registry';

export const ENVELOPE_VERSION = OMNI_VERSIONS.HYBRID_V1;
export const ENVELOPE_AEAD = "xsalsa20poly1305";

// Re-export nacl for X25519 operations
export { nacl };
