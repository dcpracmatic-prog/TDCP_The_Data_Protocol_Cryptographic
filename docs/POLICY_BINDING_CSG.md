# TDCP PolicyBinding + CSG Operation Attestation

The Authority now emits a signed `PolicyBinding` together with every one-time `AuthorizationGrant`.

The binding is cryptographically tied to:
- `documentId`
- `grantId`
- `expiry`
- authorized channel edges and byte budgets
- `authorityKid`

Gatekeeper verifies the binding against the Authority public key and the exact grant before requesting the wrap secret.

A CSG operation attestation is then created over a canonical record containing the grant hash, PolicyBinding hash, device, operation and channel edges. This is an attestation of authorization context, not a replacement for the Authority.

`TDCP_CSG_ATTEST_REQUIRED=true` disables the local-development fallback for operation attestations and requires a configured remote CSG sidecar.
