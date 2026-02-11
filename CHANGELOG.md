# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-11

### Added

- Initial release
- Core `submitSecureIntake()` function with hybrid X25519 + Kyber encryption
- `checkCryptoCapability()` for browser capability detection
- Deterministic ID generation via BLAKE3 hash of canonicalized payload
- Client-side rate limiting with retry bypass
- Pending submission tracking via sessionStorage
- Normalization utilities: `normalizeMultiline()`, `normalizeEmail()`, `normalizeStringArray()`
- Pilot access preset: `createPilotAccessClient()` with typed form data
- Configurable policy knobs: `maxPlaintextBytes`, `maxEnvelopeBytes`, `pendingTtlMs`, `rateLimit`
