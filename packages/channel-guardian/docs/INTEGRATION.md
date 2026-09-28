# Integration with TDCP

## Role boundary

The Channel Guardian protects **only** the communication channel between sensitive data and the encryption/authorization processes of TDCP.

| May do | Must not do |
|--------|-------------|
| Enforce allowed edges and byte budgets | Issue grants or evaluate business policy |
| Quarantine unauthorised egress | Hold wrap secrets or Authority private keys |
| Emit audit events for blocked traffic | Become a second unlock path |
| Verify Authority-signed `PolicyBinding` | Mutate policy after binding |

Unlock of TDCP packages remains **Gatekeeper-only**. The Guardian operates *after* a valid grant has been issued.

## Recommended flow

```
1. Client requests operation (READ / EXTRACT / …) via Gatekeeper.
2. Authority evaluates policy, issues one-time grant + PolicyBinding
   (signed channel edges + budgets for this documentId/grantId/expiry).
3. Application creates:
     const guardian = ChannelGuardian.fromBinding(binding, authorityPublicKey);
4. All data-plane frames for this operation go through:
     guardian.send("A->B", frame, chunkIdx);
5. On operation end (or expiry), discard the guardian instance.
6. Optionally attach guardian.auditEvents() to the TDCP audit sink
   and/or seal the operation event with CSG/Sello.
```

## Closing Family D (policy binding)

Vectors D1 / D1b / D2 are closed by construction:

- `ChannelGuardian.fromBinding` is the **only** constructor.
- Edges are materialised from the verified binding; there is no mutable `edges` map exposed to the application.
- Mutation after issuance invalidates the signature; the Guardian never re-reads a live mutable policy object.

## Environment / wiring (optional)

```bash
# No required env vars for the library itself.
# When used as a sidecar alongside TDCP Authority:
# TDCP_AUTHORITY_URL=http://127.0.0.1:8787
```

Authority-side: after issuing a grant, call `signPolicyBinding(policy, authorityPrivateKey, kid)` and return the binding to the client/session together with the grant material.

## Composition with CSG / Sello

- Channel Guardian → transport / egress plane.
- CSG Sello → integrity attestation of operation events (grant issue, unlock success, revoke).
- Neither plane issues TDCP grants or holds wrap secrets.

See also: TDCP `docs/CSG_SMART_TOKEN_BRIDGE.md`.

## Security honesty

- This package does not claim HSM/KMS protection of the Authority signing key.
- The browser/in-process TDCP Oracle remains a demo boundary; production path is remote Authority + (optionally) this Guardian on the data-plane path after grant issuance.
- License: Elastic License 2.0 (same family as TDCP / CSG).
