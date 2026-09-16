# Integrator API — Gatekeeper unlock surface

**Rule:** External apps unlock TDCP packages **only** through the Gatekeeper. Do not call AES-GCM / PBKDF2 / wrap-secret APIs directly.

TypeScript is the product SDK path (`sdk/typescript/`). `sdk/python` remains a labeled demo sketch.

## Operations

| Operation | Intent |
|-----------|--------|
| `READ` | Obtain plaintext buffer for authorized reading |
| `RENDER_RAM` | Render in a controlled runtime session (RAM-oriented) |
| `EXTRACT` | Allow extraction only if policy + grant permit |
| `AUDIT_EXPORT` | Export audit-related material when permitted |

(Alias note: UI may say RENDER; wire type is `RENDER_RAM`.)

## Unlock (conceptual)

```ts
import { unlockViaGatekeeper } from '@tdcp/sdk'; // or relative sdk/typescript

const result = await unlockViaGatekeeper({
  packageData,          // TDCPPackage
  userPassword,
  requestedOperation: 'READ', // | 'RENDER_RAM' | 'EXTRACT' | 'AUDIT_EXPORT'
  nfcProvider,
  deviceProvider,
  biometricProvider,    // required for CRITICAL / ULTRA_CRITICAL
  // authority?: AuthorizationAuthority  // or TDCP_AUTHORITY_URL
});

if (!result.success) {
  // result.errorCode / result.errorMessage
}
```

## Errors (stable codes)

Integrators should branch on `errorCode`, not message text:

| Code | Meaning |
|------|---------|
| `PACKAGE_INTEGRITY_FAILED` | Envelope tamper / corrupt |
| `DOCUMENT_NOT_REGISTERED` | No Authority/Oracle policy for this package |
| `PACKAGE_POLICY_MISMATCH` | Package metadata ≠ authoritative policy |
| `AAD_CONTEXT_MISMATCH` | AAD binding failed |
| `BIOMETRIC_REQUIRED` | Policy requires presence check |
| `INVALID_CHALLENGE` | Challenge not issued / expired |
| `AUTHORIZATION_DENIED` / policy codes | Oracle/Authority denied (`DOCUMENT_REVOKED`, …) |
| `GRANT_VERIFICATION_FAILED` / signature codes | Grant failed local verification |
| `REPLAY_ATTACK_REJECTED` | One-time grant / wrap secret already consumed |
| `KEY_DERIVATION_FAILURE` | Wrap/unwrap failed |
| `DECRYPTION_AUTH_TAG_FAILED` | AES-GCM auth failed |

## Audit hooks

Pass an `AuditSink` implementing `recordEvent(...)`. The Gatekeeper records DENIED / SUCCESS / TAMPER / REPLAY outcomes. Default runtime uses the in-process tamper-evident sink (local demo — not a remote SIEM).

## Authority selection

- Default: in-process Oracle (demo)
- Production path: set `TDCP_AUTHORITY_URL` to the remote Authority base URL

See `docs/AUTHORITY.md`.
