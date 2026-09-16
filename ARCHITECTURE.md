# TDCP Architecture

Product definition and Authority roadmap: see **`PRODUCT.md`** and **`ROADMAP.md`** (P0 remote Authorization Authority).

## Core invariant

> **Copying the ciphertext does not copy the authorization.**

A `.pkg` file is storage. Possession of ciphertext (and even the user passphrase factor) is not sufficient to unlock content. Authorization is mediated by a separate control plane.

## Control plane vs data plane

| Role | Responsibility |
|------|----------------|
| **Package (`.pkg`)** | Authenticated ciphertext + security envelope metadata (AES-GCM AAD). Neutral storage object. |
| **Authorization Oracle** | Policy evaluation, revocation/replay state, one-time ECDSA grants, per-document wrap secret. Does **not** receive plaintext or the content key. |
| **Gatekeeper** | Sole application path that may unlock a package: validates envelope integrity, obtains/verifies grants, then releases cryptographic material for the requested operation. |

## Gatekeeper

The Gatekeeper is the only trusted application entrypoint for decrypt / render / extract flows. UI panels must not bypass it. Security-relevant checks include:

- Envelope integrity over the complete serialized security envelope
- Authoritative policy before authorization
- One-time challenge/grant semantics (challenge consumption at grant issuance)
- View-Once commit only after successful decryption

## Oracle reference vs production

This repository ships a **browser / in-process Oracle** for the reference implementation:

- Signing keys and wrap secrets live in process/browser memory (`DEVELOPMENT_IN_MEMORY`)
- Revocation, replay, and challenge state are not durable remote state
- A compromised JavaScript environment is **not** a production security boundary

**Next architectural step:** a remote Authorization Authority backed by HSM/KMS (or platform Secure Key Store), with durable policy, revocation, replay, and signing-key state independent of the client. The browser should receive only the minimum material required for the authorized operation.

Do not describe the current browser Oracle as a remote sovereign authority, TPM, HSM, or hardware-backed boundary.

## Cryptographic building blocks (reference)

As documented in `README.md` / `AUDIT_2.5.1.md`:

- AES-256-GCM (authenticated encryption + AAD)
- HKDF-SHA-256 (contextual derivation)
- PBKDF2-HMAC-SHA-256 (passphrase factor; reference default iterations documented in audit)
- ECDSA P-256 (Oracle grants)
- Web Crypto CSPRNG for nonces/ids

## Non-claims

- A/B/C ULTRA_CRITICAL is **not** threshold secret sharing (not Shamir).
- Local runtime wiping is **not** a guarantee of physical RAM destruction.
- Mock NFC / device / biometric providers are **not** hardware security.
- Epoch revocation is authoritative only within the current reference runtime until state is persisted remotely.
- This build is a protocol reference/demo, **not** a declaration of formal cryptographic security or production readiness.
