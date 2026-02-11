# @omnituum/secure-intake-client

Post-quantum encrypted intake form submission client.

## Installation

```bash
pnpm add @omnituum/secure-intake-client
```

## Usage

### Generic API

```ts
import {
  submitSecureIntake,
  checkCryptoCapability,
} from "@omnituum/secure-intake-client";

const config = {
  endpoint: "/api/intake",
  publicKeys: {
    x25519PubHex: "...",
    kyberPubB64: "...",
  },
  canonicalize: (data) => ({
    kind: "my_form",
    email: data.email.trim().toLowerCase(),
    name: data.name.trim(),
    // ... normalize all fields for deterministic hashing
  }),
};

// Check capability first
const crypto = await checkCryptoCapability();
if (!crypto.available) {
  console.error("Crypto not available:", crypto.error);
  return;
}

// Submit
const result = await submitSecureIntake(formData, config);
if (result.ok) {
  console.log("Submitted:", result.id, result.status);
} else {
  console.error("Failed:", result.error);
}
```

### Pilot Access Preset

```ts
import { createPilotAccessClient } from "@omnituum/secure-intake-client/presets/pilot-access";

const client = createPilotAccessClient({
  endpoint: "/api/intake",
  publicKeys: {
    x25519PubHex: import.meta.env.VITE_OMNITUUM_X25519_PUB_HEX,
    kyberPubB64: import.meta.env.VITE_OMNITUUM_KYBER_PUB_B64,
  },
});

// Check capability
const crypto = await client.checkCryptoCapability();

// Submit
const result = await client.submit(formData, "request_pilot_access");
```

## Wire Format

Submissions are sent as JSON with this shape:

```json
{
  "v": "loggie.intake.v1",
  "id": "abc123...",
  "encrypted": "{\"x25519Ciphertext\":\"...\",\"kyberCiphertext\":\"...\",\"nonce\":\"...\",\"ciphertext\":\"...\"}"
}
```

- `v` - Wire protocol version
- `id` - Deterministic BLAKE3 hash of canonicalized payload (64 hex chars)
- `encrypted` - JSON-encoded hybrid encryption result

## Canonicalization Contract

The `canonicalize` function must:

1. Return a **deterministic** object (same input = same output)
2. Include **all** fields that should affect the request ID
3. **Normalize** fields consistently:
   - Emails: `trim().toLowerCase()`
   - Multiline text: `normalizeMultiline()` (Unix line endings)
   - Arrays: sorted copy `[...arr].sort()`
   - Strings: `trim()`

The canonicalized object is:
- JSON-stringified and hashed with BLAKE3 to produce the `id`
- JSON-stringified and encrypted for transmission

## Configuration Options

```ts
interface IntakeConfig {
  endpoint: string; // API URL
  publicKeys: {
    x25519PubHex: string;
    kyberPubB64: string;
  };
  canonicalize: (payload: unknown) => Record<string, unknown>;

  // Optional with defaults
  version?: string; // "loggie.intake.v1"
  maxPlaintextBytes?: number; // 32KB
  maxEnvelopeBytes?: number; // 56KB
  pendingTtlMs?: number; // 5 min
  storageKey?: string; // "loggie.intake.pending"
  rateLimit?: { max: number; windowMs: number } | false; // { max: 2, windowMs: 60000 }
}
```

## Features

- **Hybrid encryption**: X25519 + Kyber (post-quantum)
- **Idempotency**: Deterministic IDs prevent duplicates
- **Retry support**: Pending submissions tracked in sessionStorage
- **Rate limiting**: Client-side throttling (bypassed for retries)
- **Size guards**: Pre-encryption and post-encryption limits
- **Honeypot**: Optional bot detection field
