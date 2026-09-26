# CSG + Smart Token bridge (free / self-hosted)

**Status:** Design + optional client stubs. This repository does **not** vendor Smart-Token-Prod or CSG source trees.

**Constraint:** External apps and bridges unlock TDCP packages **only through the Gatekeeper**. Smart Token and CSG are additive planes (long-lived file defence + integrity attestation). They must not become a second control plane that bypasses grants.

## Goal

Compose three complementary, free-to-self-host components already published under the same organisation:

| Component | Role | Free path |
|-----------|------|-----------|
| **TDCP** | Protocol + Gatekeeper + Authority (operation-scoped unlock; copy ≠ authorization) | This repo |
| **Smart Token Prod** | Long-lived file protection (ML-KEM-768 + AES-256-GCM, autonomous friction 1→2→3) | Self-host `api/` (uvicorn) or SDK via `pip` from git tag |
| **CSG / Sello** | Cryptographic integrity seal + NotarioProtegido (conatus, damage_log, structural rupture) | Self-host thin HTTP wrapper over the Rust crate, or call from a Python/Rust sidecar |

No commercial SaaS, no paid KMS, and no third-party hosted service is required for the paths documented here.

## Trust model (additive planes)

| Plane | May hold | Must not hold |
|-------|----------|----------------|
| TDCP Authority | Signing keys, wrap secrets, revoke/replay | Plaintext, Smart Token master, CSG damage master |
| TDCP Gatekeeper | Ephemeral session material for one operation | Long-lived content keys, STP master across tasks |
| Smart Token API | `.stok` ciphertext + friction snapshot; master only in request header for the call | TDCP wrap secrets, Authority private keys |
| CSG Notario | Event seals, conatus state; damage master outside token | TDCP wrap secrets, STP master |
| Package / artifact store | `.pkg` and/or `.stok` ciphertext | Authorization |

Invariant retained: **copying ciphertext does not copy authorization.**

## Free deployment (local / single host)

### 1. Smart Token HTTP API

From a clone of [Smart-Token-Prod](https://github.com/dcpracmatic-prog/Smart-Token-Prod):

```bash
pip install -r api/requirements.txt
export SMART_TOKEN_API_KEY="$(openssl rand -hex 32)"
# Optional: SMART_TOKEN_STORAGE_BACKEND=local
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Endpoints used by the TDCP bridge:

- `GET /healthz`
- `POST /v1/artifacts` (multipart file + `X-Smart-Token-Master`)
- `POST /v1/artifacts/{artifact_id}/open` (`X-Smart-Token-Master`)
- `GET /v1/artifacts/{artifact_id}/friction`

Authentication: `Authorization: Bearer <SMART_TOKEN_API_KEY>`.

### 2. CSG / Sello (optional service)

The public surface is the Rust crate `sello-integridad` (`Notario`, `NotarioProtegido`, `Firmante`, `verificar_sello`). For HTTP interop without embedding Rust in the Node process:

- Run a minimal sidecar (Rust binary or Python binding) that exposes seal / verify over loopback, **or**
- Call the crate from an offline process and attach the resulting seal JSON to TDCP audit events.

Until a sidecar is present, TDCP treats CSG as a **design-time attestation hook**: document the event types to seal (grant issue, successful unlock, policy revoke) and keep the Notario master key out of the TDCP process.

### 3. Wire into TDCP (environment)

Optional variables (see `.env.example`):

```bash
# Smart Token (self-hosted)
SMART_TOKEN_API_URL=http://127.0.0.1:8000
SMART_TOKEN_API_KEY=   # same as SMART_TOKEN_API_KEY on the API process
# Master is never stored by TDCP; supply per operation only

# CSG sidecar (optional; leave unset to skip)
# CSG_SEAL_URL=http://127.0.0.1:8010
```

## Integration patterns (Gatekeeper-first)

### A. Protect long-lived artifact, then authorize with TDCP

1. Client or operator calls Smart Token `POST /v1/artifacts` with file + master → receives `artifact_id`.
2. Optionally wrap a reference (artifact_id + storage locator) inside a TDCP `.pkg` envelope, or keep `.stok` as the storage object and register policy on the Authority against a document id derived from the artifact.
3. Consumer requests unlock via **Gatekeeper** with the usual operation (`READ` / `EXTRACT` / …).
4. After a valid grant, the application may call Smart Token `open` **only** with the master supplied by the authorized operator path (never from long-lived agent memory).

### B. Attest operations with CSG

1. On successful Gatekeeper unlock or Authority grant issuance, build a canonical event payload (document id, operation, grant id, timestamp).
2. Submit to CSG NotarioProtegido (sidecar or offline seal).
3. Store the seal in the audit sink; verification is independent (`verificar_sello`).
4. Failed unauthorized seal attempts accumulate conatus; after threshold the Notario enters structural rupture until out-of-band recovery.

### C. What this bridge deliberately does **not** do

- Does not replace TDCP Authority with Smart Token friction state.
- Does not allow agents to hold STP master or CSG damage master across tasks.
- Does not claim HSM/KMS for any of the three components unless you add them yourself.
- Does not change TDCP crypto primitives or Gatekeeper security semantics.

## TypeScript client stub (this repo)

A minimal fetch-based client lives at `sdk/typescript/src/smart-token-client.ts` and is re-exported from the SDK index. It only talks to a self-hosted Smart Token API; no npm dependency beyond the platform `fetch`.

```ts
import { SmartTokenClient } from '../sdk/typescript/src/index.ts';

const stp = new SmartTokenClient({
  baseUrl: process.env.SMART_TOKEN_API_URL ?? 'http://127.0.0.1:8000',
  apiKey: process.env.SMART_TOKEN_API_KEY ?? '',
});

const health = await stp.healthz();
// protect / open require master per call — never persist it in TDCP state
```

CSG remains out-of-process; no Node binding is shipped in this update.

## Security honesty

- Smart Token master and CSG damage master are **operator secrets**, not Authority wrap secrets.
- Opaque denial and phase-3 hang are properties of Smart Token’s authenticated path; reimplementing open offline with `sk`+master reduces hardness to Argon2 (see Smart Token threat model).
- TDCP browser/in-process Oracle remains a **demo** boundary; production path is remote Authority + (optionally) these self-hosted sidecars behind the same network policy.
- All three projects use Elastic License 2.0 source-available terms: do not offer substantial features as a multi-tenant hosted service without complying with the license.

## Related documents

- Product definition: `PRODUCT.md`
- Architecture planes: `ARCHITECTURE.md`
- Integrator unlock surface: `docs/INTEGRATOR_API.md`
- ATL agent note (design only): `docs/ATL_EDGE_BRIDGE.md`
- Smart Token upstream: https://github.com/dcpracmatic-prog/Smart-Token-Prod
- CSG upstream: https://github.com/dcpracmatic-prog/CSG
