# @tdcp/sdk (TypeScript)

Minimal **Gatekeeper-only** unlock helpers for TDCP integrators.

This folder is workspace-friendly (not necessarily published to npm yet). Import from the monorepo path or wire your bundler to `sdk/typescript/src/index.ts`.

## Usage

```ts
import { unlockViaGatekeeper, resolveAuthorizationAuthority } from '../sdk/typescript/src/index.ts';

const authority = resolveAuthorizationAuthority(); // or TDCP_AUTHORITY_URL

const result = await unlockViaGatekeeper({
  packageData,
  userPassword,
  requestedOperation: 'READ',
  nfcProvider,
  deviceProvider,
  biometricProvider,
  authority,
});
```

## Docs

- `docs/INTEGRATOR_API.md` — operations, errors, audit hooks
- `docs/AUTHORITY.md` — remote Authority
- `PRODUCT.md` — product wedge

**Python** under `sdk/python` is a demo sketch, not protocol parity.
