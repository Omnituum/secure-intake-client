/**
 * Local HybridEnvelope type definition.
 *
 * Matches @omnituum/pqc-shared HybridEnvelope exactly but defined locally
 * to avoid importing pqc-shared (which triggers WASM side effects).
 */

export interface HybridEnvelope {
  v: string;
  suite: string;
  aead: string;
  x25519Epk: string;
  x25519Wrap: { nonce: string; wrapped: string };
  kyberKemCt: string;
  kyberWrap: { nonce: string; wrapped: string };
  contentNonce: string;
  ciphertext: string;
  meta: { createdAt: string; senderName?: string; senderId?: string };
}
