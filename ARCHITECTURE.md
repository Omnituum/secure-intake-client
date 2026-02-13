# Omnituum Secure Intake — Architecture & Implementation Guide

> Reference architecture for the encrypted intake form system.
> Use this document when building new apps that collect intake submissions.

## System Overview

The intake system is a three-layer architecture with a hard security boundary: **the server never receives plaintext PII.**

```
+------------------------------------------------------------------+
|  Layer 1: CLIENT LIBRARY  (@omnituum/secure-intake-client)       |
|  NPM package consumed by any frontend app                        |
|  - Hybrid encryption (X25519 + Kyber-1024)                       |
|  - Deterministic BLAKE3 IDs for deduplication                    |
|  - Canonicalization, rate limiting, idempotency                  |
|  - Preset system for reusable form configs                       |
+------------------------------------------------------------------+
|  Layer 2: SERVER BACKEND  (@omnituum/secure-intake-cloudflare)   |
|  Cloudflare Pages Functions + D1 SQLite                          |
|  - Ciphertext-only storage (NEVER decrypts)                      |
|  - CORS allowlist, HMAC verification, IP hashing                 |
|  - Admin API with Cloudflare Access SSO                          |
|  - Browser-based admin UI (decrypts in-memory only)              |
+------------------------------------------------------------------+
|  Layer 3: FRONTEND APP  (e.g., marketing-pilot)                  |
|  React SPA hosted on Cloudflare Pages                            |
|  - Form UI components with modal + hash routing                  |
|  - Imports client library, configures endpoint + public keys     |
|  - Pure static site — NO server functions needed                 |
+------------------------------------------------------------------+
```

## Core Security Invariant

All encryption happens **client-side in the browser**. The server stores ciphertext verbatim in D1 and cannot decrypt it. Decryption happens either:

- In the **admin browser UI** (keys held in JS memory only, never persisted), or
- **Offline via CLI** scripts with the org identity key file.

Private keys never exist on the server, in environment variables, or in any deployed artifact.

## Data Flow

| Step | Where   | What Happens |
|------|---------|--------------|
| 1    | Browser | User fills form |
| 2    | Browser | `canonicalize()` normalizes fields (lowercase email, sort arrays, LF line endings) |
| 3    | Browser | `BLAKE3(canonicalized)` produces deterministic 64-char hex ID |
| 4    | Browser | `hybridEncrypt()` with X25519 + Kyber-1024 via AES-256-GCM |
| 5    | Browser | POST envelope `{ v, id, encrypted }` to `/api/intake` |
| 6    | Server  | Validate envelope shape, verify HMAC (optional), hash IP |
| 7    | Server  | INSERT ciphertext into D1 (`UNIQUE` on `id` for dedup) |
| 8    | Server  | Return `{ ok, id, status: "created" | "duplicate" }` |
| 9    | Offline | Operator decrypts with private key (never on server) |

## Wire Protocol

```json
{
  "v": "loggie.intake.v1",
  "id": "64-char-hex-blake3-hash",
  "encrypted": "{x25519Ciphertext, kyberCiphertext, nonce, ciphertext}"
}
```

The `v` field allows future protocol versions. The `id` field enables idempotent retries and server-side deduplication without the server needing to decrypt.

## Cryptographic Primitives

| Primitive       | Purpose                       | Library                          |
|-----------------|-------------------------------|----------------------------------|
| X25519          | Classical key agreement (ECDH)| `@noble/curves` via `@omnituum/pqc-shared` |
| Kyber-1024      | Post-quantum key encapsulation| `kyber-crystals` WASM            |
| AES-256-GCM     | Symmetric encryption          | Web Crypto API                   |
| BLAKE3          | Deterministic ID hashing      | `@noble/hashes`                  |
| HMAC-SHA256     | Request authentication (opt.) | Web Crypto API (server-side)     |

## Client Library API

### Generic API (custom form shapes)

```typescript
import {
  submitSecureIntake,
  checkCryptoCapability,
  normalizeEmail,
  normalizeMultiline,
} from "@omnituum/secure-intake-client";

const config = {
  endpoint: "/api/intake",
  publicKeys: {
    x25519PubHex: "...",
    kyberPubB64: "...",
  },
  canonicalize: (data) => ({
    kind: "my_custom_form",
    email: normalizeEmail(data.email),
    name: data.name.trim(),
    message: normalizeMultiline(data.message),
    tags: [...data.tags].sort(),
  }),
};

const crypto = await checkCryptoCapability();
if (!crypto.available) {
  // Show fallback UI — browser lacks WebCrypto or Kyber WASM
  return;
}

const result = await submitSecureIntake(formData, config);
```

### Preset API (reusable form configs)

```typescript
import { createPilotAccessClient } from "@omnituum/secure-intake-client/presets/pilot-access";

const client = createPilotAccessClient({
  endpoint: "https://secure-intake.pages.dev/api/intake",
  publicKeys: {
    x25519PubHex: import.meta.env.VITE_OMNITUUM_X25519_PUB_HEX,
    kyberPubB64: import.meta.env.VITE_OMNITUUM_KYBER_PUB_B64,
  },
});

const result = await client.submit(formData, "request_pilot_access");
```

### Canonicalization Contract

The `canonicalize` function **MUST**:

1. Return a **deterministic** object (same input = same output, always)
2. Include **all** fields that should affect the request ID
3. **Normalize** fields consistently:
   - Emails: `normalizeEmail()` (trim + lowercase)
   - Multiline text: `normalizeMultiline()` (CRLF/CR to LF, trim)
   - Arrays: sorted copy `[...arr].sort()`
   - Strings: `.trim()`

Violation of this contract breaks idempotency and deduplication.

### Configuration Defaults

| Config Key         | Default                         | Notes                        |
|--------------------|---------------------------------|------------------------------|
| `version`          | `"loggie.intake.v1"`            | Wire protocol version        |
| `maxPlaintextBytes`| `32,768` (32 KB)               | Guard before encryption      |
| `maxEnvelopeBytes` | `57,344` (56 KB)               | Guard after encryption       |
| `pendingTtlMs`     | `300,000` (5 min)              | Retry window in sessionStorage |
| `storageKey`       | `"loggie.intake.pending"`       | sessionStorage key           |
| `rateLimit`        | `{ max: 2, windowMs: 60000 }`  | Client-side, 2/min           |

## Server Architecture (secure-intake-cloudflare)

### D1 Schema

```sql
-- Core storage
CREATE TABLE intake_requests (
  id               TEXT PRIMARY KEY,   -- BLAKE3 hash (64-char hex)
  v                TEXT NOT NULL,      -- Wire protocol version
  encrypted_json   TEXT NOT NULL,      -- Ciphertext (verbatim from client)
  received_at      TEXT NOT NULL,      -- ISO 8601
  ip_hash          TEXT,               -- SHA-256 of salted IP
  ua               TEXT,               -- User-Agent (clamped 512 bytes)
  ref              TEXT,               -- Referrer (query stripped, clamped 1024 bytes)
  status           TEXT DEFAULT 'new', -- Admin workflow state
  processed_at     TEXT,
  note             TEXT,
  viewed_at        TEXT
);

-- Audit trail
CREATE TABLE intake_events (
  rowid     INTEGER PRIMARY KEY AUTOINCREMENT,
  intake_id TEXT NOT NULL REFERENCES intake_requests(id),
  event     TEXT NOT NULL,   -- "viewed", "mark-processed", "note-updated", "unprocessed"
  actor     TEXT,            -- Admin email from Cloudflare Access
  at        TEXT NOT NULL,   -- ISO 8601
  meta      TEXT             -- Optional JSON metadata
);
```

### Server-Side Validation (what the server checks)

1. Method is POST, Content-Type is `application/json`
2. Body size within `MAX_BODY_BYTES` (64 KB default)
3. Envelope has required fields: `v`, `id`, `encrypted`
4. `id` is 64-char lowercase hex
5. `v` is in `ALLOWED_VERSIONS`
6. HMAC-SHA256 matches (if `INTAKE_HMAC_SECRET` configured)
7. CORS origin is in `ALLOWED_ORIGINS`

### What the Server Does NOT Do

- Decrypt ciphertext (no private keys available)
- Recompute the BLAKE3 ID (trusts client hash)
- Log plaintext (impossible without keys)
- Store raw IP addresses (hashed with salt)

### Server Environment Variables

| Variable              | Required | Description |
|-----------------------|----------|-------------|
| `ALLOWED_ORIGINS`     | Yes      | Comma-separated CORS allowlist |
| `INTAKE_IP_SALT`      | Yes      | 64-char hex for IP hashing (`openssl rand -hex 32`) |
| `INTAKE_HMAC_SECRET`  | No       | Enables HMAC request authentication |
| `ADMIN_EMAILS`        | No       | Comma-separated admin email allowlist |
| `ADMIN_UI_ORIGIN`     | No       | CORS origin for admin API |
| `NOTIFY_WEBHOOK_URL`  | No       | Webhook for new submission notifications (metadata only) |
| `MAX_BODY_BYTES`      | No       | Request body limit (default 64 KB) |
| `ALLOWED_VERSIONS`    | No       | Protocol versions (default `loggie.intake.v1`) |

## Reference Implementation: marketing-pilot

The `marketing-pilot` app is the canonical example of a frontend consuming this system.

### Key Files

| File | Role |
|------|------|
| `src/lib/env.ts` | Initializes `createPilotAccessClient()` with public keys from env |
| `src/lib/requestAccess.ts` | Thin wrapper: `submitRequestAccess(formData, kind)` |
| `src/components/RequestPilotAccessForm.tsx` | React form with useState for state, validation, error handling |
| `src/components/RequestAccessModal.tsx` | Accessible modal with focus trapping, ESC close, backdrop close |
| `src/context/RequestAccessContext.tsx` | React Context so any CTA button can open the modal |
| `src/hooks/useRequestAccessModal.ts` | Hash-based routing (`#request-access`) for deep-linkable modal |
| `.env` | Public keys: `VITE_OMNITUUM_X25519_PUB_HEX`, `VITE_OMNITUUM_KYBER_PUB_B64` |
| `wrangler.toml` | Pure static SPA config (no functions, no D1 binding) |

### Frontend Pattern

```
User clicks CTA  -->  URL hash set to #request-access
                 -->  Modal opens (via hashchange listener)
                 -->  User fills form
                 -->  handleSubmit() calls client.submit(formData)
                 -->  Client encrypts, POSTs to shared backend
                 -->  Success: show confirmation
                 -->  Error: show retry message
                 -->  Modal closes, hash cleared
```

The app is a **pure static SPA** — it has no `functions/` directory and no D1 binding. All intake storage is handled by the shared `secure-intake-cloudflare` deployment.

## Adding a New Intake Form — Checklist

### 1. Define the form schema

```typescript
interface MyFormData {
  email: string;
  name: string;
  message: string;
  // ... your fields
}
```

### 2. Write a canonicalize function (or create a preset)

```typescript
// Option A: inline canonicalize
const config = {
  endpoint: "https://secure-intake.pages.dev/api/intake",
  publicKeys: { x25519PubHex: "...", kyberPubB64: "..." },
  canonicalize: (data: MyFormData) => ({
    kind: "my_form_kind",
    email: normalizeEmail(data.email),
    name: data.name.trim(),
    message: normalizeMultiline(data.message),
  }),
};

// Option B: create a preset in src/presets/my-form.ts
// (follow the pattern in src/presets/pilot-access.ts)
```

### 3. Set environment variables

```bash
# .env (public keys — safe to commit)
VITE_OMNITUUM_X25519_PUB_HEX=<64-char-hex>
VITE_OMNITUUM_KYBER_PUB_B64=<base64-string>
```

### 4. Build the form UI

Follow the marketing-pilot pattern:
- React form component with `useState` for `formData`, `isSubmitting`, `isSubmitted`, `submitError`
- Call `checkCryptoCapability()` before showing the form
- Use a honeypot field for spam prevention
- Show "Encrypting & Submitting..." during submission

### 5. Register the app's origin on the server

Add your app's production URL to the `ALLOWED_ORIGINS` environment variable on the `secure-intake-cloudflare` deployment:

```bash
wrangler pages secret put ALLOWED_ORIGINS
# Enter: https://existing-app.pages.dev,https://your-new-app.pages.dev
```

### 6. Test the full round-trip

```bash
# Smoke test the endpoint
node scripts/smoke-post.mjs https://secure-intake.pages.dev

# E2E: encrypt, submit, then decrypt offline
node scripts/test-e2e-intake.mjs

# Verify normalization determinism
node scripts/test-normalization.mjs
```

## Design Decisions & Rationale

| Decision | Choice | Why |
|----------|--------|-----|
| Hybrid crypto (X25519 + Kyber) | Post-quantum forward secrecy | Protect today's data against future quantum attacks |
| BLAKE3 for IDs | Deterministic dedup | Same form + same canonicalization = same ID, enabling safe retries |
| Client-side rate limiting | Defense-in-depth | Pair with Cloudflare WAF for server-side limits |
| sessionStorage for pending | Idempotent retries | Survives page reload within TTL; cleared on tab close |
| D1 SQLite for storage | Simple, cost-effective | No R2 or KV needed for structured ciphertext |
| No server-side decryption | Zero-knowledge storage | Even if server is compromised, PII is not exposed |
| IP hashing with secret salt | Privacy-preserving | Compliance-friendly; raw IPs never stored |
| Referrer query stripping | Prevent PII leakage | Tokens in URLs don't end up in the database |
| Admin decryption in-browser | Key never leaves operator | Cloudflare Access gates the API; key lives in JS memory only |

## Key Rotation

```bash
# Generate new org identity
node scripts/decrypt-intake.mjs --gen-org-identity ./secrets/org.identity.new.json

# Print public keys for deployment
node scripts/decrypt-intake.mjs --print-pub ./secrets/org.identity.new.json

# Update VITE_OMNITUUM_X25519_PUB_HEX and VITE_OMNITUUM_KYBER_PUB_B64
# in each consuming app's .env, then redeploy

# Keep the old identity file to decrypt old submissions
```

Old submissions remain encrypted with the old key. Both identity files are needed to decrypt the full history.
