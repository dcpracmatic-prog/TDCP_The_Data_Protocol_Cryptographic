# TDCP — PolicyBinding + CSG integration update

Implemented in this revision:

1. Authority emits a signed `PolicyBinding` together with every successful one-time grant.
2. Binding is tied to `documentId`, `grantId`, `expiry`, `authorityKid`, and channel edges/budgets.
3. Gatekeeper verifies the PolicyBinding against the Authority public key and the exact Grant before wrap-secret release.
4. Gatekeeper creates a CSG operation attestation containing Grant hash, PolicyBinding hash, device, operation and channel edges.
5. `TDCP_CSG_ATTEST_REQUIRED=true` forces remote CSG for operation attestation; otherwise local CSG remains development fallback.
6. Channel Guardian `EgressLink` no longer retains data-plane frames in memory; it tracks byte counters only.
7. Package creation accepts optional `channelEdges`; by default it binds `A -> B` to the plaintext byte budget.
8. Added integration tests for Authority-issued PolicyBinding and grant substitution resistance.

Validation performed:

- Changed TypeScript files pass Node type-stripping syntax checks.
- PolicyBinding integration tests: PASS (2/2).
- Local CSG operation attestation smoke test: PASS.
- Full TypeScript/test suite could not be completed because the supplied environment did not have all npm dependencies installed; `tsc` reported missing `@types/node` and `vite/client`, and the Authority suite also needs `@simplewebauthn/server`.

Security note:

The browser Gatekeeper verifies the signed binding and CSG attestation before releasing the wrap secret. The Node Channel Guardian package remains the data-plane enforcement component; browser-native transport enforcement is a separate deployment concern and is not falsely claimed as kernel/network isolation.
