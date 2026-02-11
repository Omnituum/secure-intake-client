# Security Policy

## Boundary Invariant

**The server NEVER receives plaintext PII.**

All form data is:
1. Canonicalized (deterministic field ordering, normalization)
2. Encrypted client-side using hybrid X25519 + Kyber-1024
3. Transmitted as an opaque `encrypted` blob

The server receives only:
- `v`: Wire protocol version
- `id`: BLAKE3 hash of canonicalized payload (for deduplication)
- `encrypted`: Ciphertext (not decryptable without org private key)

## Cryptographic Primitives

| Primitive | Purpose | Library |
|-----------|---------|---------|
| X25519 | Key agreement (classical) | `@noble/curves` via `@omnituum/pqc-shared` |
| Kyber-1024 | Key encapsulation (post-quantum) | `kyber-crystals` WASM |
| AES-256-GCM | Symmetric encryption | Web Crypto API |
| BLAKE3 | Deterministic ID hashing | `@noble/hashes` |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately:

1. **Do not** open a public GitHub issue
2. Email: security@omnituum.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact

We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.

## Security Considerations for Consumers

### WASM Loading

Kyber encryption uses WASM. Ensure your CSP allows:
```
script-src 'wasm-unsafe-eval'
```

Or use a WASM-compatible CSP policy for your deployment target.

### Key Management

- Store org public keys in environment variables, not source code
- Rotate keys periodically (coordinate with server-side key management)
- The `id` field is a hash of normalized plaintext - while not directly reversible, avoid exposing it unnecessarily

### Rate Limiting

Client-side rate limiting is defense-in-depth only. Always implement server-side rate limiting.
