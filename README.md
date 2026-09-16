# TDCP Web — Reference Implementation 2.5

TDCP (The Data Cryptographic Protocol) is the protocol layer used by this application to separate encrypted data from authorization to operate on that data.

## Core invariant

> Copying the ciphertext does not copy the authorization.

The `.pkg` is storage. The Authorization Oracle is the control plane. The Gatekeeper is the only application path that may unlock a package.

## 2.5 corrections

- Security-relevant package metadata is authenticated through AES-GCM AAD.
- Package envelope integrity covers the complete serialized security envelope.
- The Gatekeeper validates envelope integrity and authoritative policy before authorization.
- Challenges are issued and tracked by the trusted control-plane flow and expire after 60 seconds; injected test challenges must be pre-registered.
- Oracle-issued grants are one-time; challenge/operation consumption occurs at grant issuance, and the wrap secret can only be released through a valid signed grant.
- View-Once is committed only after successful decryption, avoiding accidental consumption after a failed decrypt.
- Oracle signing keys are non-exportable in the development implementation.
- Version identifiers were advanced to `2.5-SEC`.
- The existing DCP UI, Google Drive storage, A/B/C ULTRA_CRITICAL mode, audit trail, WebAuthn providers and demo providers were retained.

## Security boundary

This build is a browser reference implementation. The Oracle, Gatekeeper and their in-memory state run in the same browser process. Therefore a fully compromised browser/JavaScript environment is **not** a trusted security boundary.

For production, the next step is a remote Authorization Authority backed by an HSM/KMS. The browser should receive only the minimum authorization material required for the operation, and the authority must persist policy, revocation, replay state and signing keys independently of the client.

Do not describe the current browser Oracle as a remote sovereign authority, TPM, HSM or hardware-backed security boundary.

## Cryptographic primitives

- AES-256-GCM for authenticated encryption.
- HKDF-SHA-256 for contextual key derivation.
- PBKDF2-HMAC-SHA-256 for the user passphrase factor.
- ECDSA P-256 for Oracle authorization grants.
- Cryptographically secure random nonces/identifiers from Web Crypto.

## ULTRA_CRITICAL

A/B/C provides cross-bound fragment integrity and controlled reconstruction. It is not a threshold-secret-sharing scheme. A/B/C must not be described as equivalent to Shamir Secret Sharing.

## Validation

The repository contains an automated TDCP security test suite covering encryption/decryption, authorization separation, tampering, replay, revocation, view-once, signature forgery, storage neutrality, A/B/C interlocking and bypass attempts.

Run:

```bash
npm test
npm run typecheck
npm run lint
npm run build
```

If dependencies are not installed in the environment, install them before running the commands above.

## Product position

Canonical product definition: **[`PRODUCT.md`](PRODUCT.md)** — TDCP separates encrypted packages from authorization to operate on them (*copying ciphertext does not copy authorization*).

**Build toward:** (1) protocol + Gatekeeper reference, (2) remote Authorization Authority, (3) TS SDK / integrator surface, (4) optional ATL Edge bridge later (design only).

**Not building next (~2 quarters):** full IRM SaaS parity, Firebase/Gemini control plane, HSM claims for the browser Oracle, Office plugins / email gateway / CASB listing.

**ICP:** secure data rooms, regulated file exchange, and agent pipelines that need operation-scoped unlocks with revoke/replay. See also [`MARKET.md`](MARKET.md), [`ROADMAP.md`](ROADMAP.md). Spanish founder summary: [`docs/PRODUCT_ES.md`](docs/PRODUCT_ES.md).

This version remains a serious protocol reference/demo, not a declaration of formal cryptographic security or production readiness (see [`AUDIT_2.5.1.md`](AUDIT_2.5.1.md)). The next commercial credibility milestone is a remote Authorization Authority with durable revoke/replay — not IRM feature parity.

## How to run

```bash
./scripts/start.sh
# open http://127.0.0.1:8080/
```

See also: `PRODUCT.md`, `ROADMAP.md`, `DEPLOY.md`, `ARCHITECTURE.md`, `MARKET.md`, `AUDIT_2.5.1.md`, `docs/PRODUCT_ES.md`.
Python sketch (demo only): `sdk/python/`.
