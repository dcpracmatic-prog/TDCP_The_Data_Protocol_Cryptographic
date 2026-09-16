# TDCP Web 2.5.1 — Audit and polish notes

## Corrections applied

1. **Challenge one-time semantics**: the Oracle now consumes `operationId + challenge` when issuing the one-time grant. This closes the window in which one fresh challenge could mint multiple grants.
2. **Challenge issuance boundary**: normal Gatekeeper flow obtains challenges through `oracle.issueChallenge()`. Test-only injected challenges must already be registered.
3. **Challenge clock sanity**: challenges registered in the future are rejected.
4. **Package validation**: deserialization now checks protocol version, algorithm suite, top-level/metadata document and package identity, KDF iteration bounds, and IV/salt lengths.
5. **Explicit KDF parameter**: package metadata and AAD carry `kdfIterations`; the reference default is 600,000 PBKDF2-HMAC-SHA-256 iterations.

## Remaining architectural limitation

The Oracle is still an in-process browser reference implementation. A compromised JavaScript/browser environment can potentially inspect or alter the control plane. The production architecture must move authorization, revocation/replay state, signing keys, and the document wrap secret behind a remote Authorization Authority with durable state and an HSM/KMS-backed key boundary.

## Non-claims

- A/B/C is not threshold secret sharing.
- Local runtime wiping is not a guarantee of physical RAM destruction.
- Mock NFC/device/biometric providers are not hardware security.
- Epoch revocation is authoritative only within the current reference runtime until state is persisted remotely.
