# @tdcp/channel-guardian

**Channel Guardian for TDCP** — egress protection with Authority-signed policy binding.

> Protects the communication channel between sensitive data and encryption/authorization processes.  
> Does **not** issue grants, evaluate business policy, or hold wrap secrets.

## Role boundary

| Responsibility | Owner |
|----------------|--------|
| Operation authorization / grants | TDCP Authority + Gatekeeper |
| Content integrity / event attestation | TDCP envelope + optional CSG/Sello |
| **Channel egress (edges, budgets, quarantine)** | **This component** |

The Guardian is materialised **after** a valid grant. It is never a second unlock path.

## Install (local path / monorepo)

```bash
# From TDCP repo root, after copying this package under packages/ or sdk/
cd packages/channel-guardian   # or wherever you place it
npm install
npm run build
```

## Quick usage

```ts
import {
  ChannelGuardian,
  signPolicyBinding,      // Authority-side helper
  generateAuthorityKeyPair,
} from "@tdcp/channel-guardian";

// --- Authority side (after issuing a grant) ---
const { publicKey, privateKey } = generateAuthorityKeyPair(); // or load from KMS/HSM
const policy = {
  documentId: "doc-001",
  grantId: "grant-abc",
  expiry: Date.now() + 60_000,
  edges: [
    { source: "A", destination: "B", expectedBytes: 2048, allowed: true },
    { source: "B", destination: "C", expectedBytes: 2048, allowed: true },
    { source: "C", destination: "D", expectedBytes: 2048, allowed: true },
    { source: "B", destination: "X", expectedBytes: 0, allowed: false },
  ],
};
const binding = signPolicyBinding(policy, privateKey, "authority-kid-1");

// --- Data-plane side (after Gatekeeper grant) ---
const guardian = ChannelGuardian.fromBinding(binding, publicKey);

const frame = Buffer.from("...");
guardian.send("A->B", frame, 0);   // allowed
guardian.send("B->X", frame, 1);   // blocked + quarantined

if (guardian.hasBlockedTraffic()) {
  // attach guardian.auditEvents() to TDCP audit sink
}
```

## Closing the residual Family-D vectors

| Vector | Mitigation |
|--------|------------|
| D1 / D1b — policy mutated after attestation | Links are built only from a verified `PolicyBinding`; no mutable edges map |
| D2 — links built from a different policy | `fromBinding` is the sole constructor; signature binds edges to grant |

See `docs/THREAT_MODEL.md` and `docs/INTEGRATION.md`.

## API surface

- `ChannelGuardian.fromBinding(binding, authorityPublicKey)` — only constructor
- `guardian.send(edgeKey, frame, chunkIdx)` → `{ accepted, droppedBytes }`
- `guardian.auditEvents()` / `hasBlockedTraffic()` / `deliveredSnapshot()`
- `signPolicyBinding` / `verifyPolicyBinding` / `generateAuthorityKeyPair` (Authority helpers)

## Tests

```bash
npm run build
node --test test/guardian.test.mjs
```

## License

Elastic License 2.0 (same family as TDCP / CSG). See `LICENSE`.

## Related

- TDCP: https://github.com/dcpracmatic-prog/TDCP_The_Data_Protocol_Cryptographic
- CSG / Sello: https://github.com/dcpracmatic-prog/CSG
- Bridge design: TDCP `docs/CSG_SMART_TOKEN_BRIDGE.md`
