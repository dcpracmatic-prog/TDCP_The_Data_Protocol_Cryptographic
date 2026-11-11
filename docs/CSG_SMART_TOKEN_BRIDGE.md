# CSG + Smart Token bridge (free / self-hosted)

**Status (2026-11-11): FUNCIONANDO de extremo a extremo, verificado en local.** Smart Token API (`api/` en Smart-Token-Prod) habla el contrato exacto del cliente TDCP (`sdk/typescript/src/smart-token-client.ts`): protect → open → friction con roundtrip byte-idéntico. El sidecar CSG existe: `sidecar/` en el repo CSG (binario Rust `csg-sidecar` sobre el crate `sello-integridad`, loopback 127.0.0.1:8010) y el cliente TDCP (`src/protection/csg-client.ts`) sella y verifica contra él. Ejemplos verificados: `examples/smart-token-bridge-example.ts` y `examples/csg-seal-verify-example.ts`.

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

### 2. CSG / Sello (sidecar Rust, verificado)

The public surface is the Rust crate `sello-integridad` (`Notario`, `NotarioProtegido`, `Firmante`, `verificar_sello`). The HTTP sidecar ships in the CSG repo (`sidecar/`, binary `csg-sidecar`, thin wrapper over the crate — no crypto reimplemented):

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd <CSG repo>/sidecar
cargo build --release --offline
CSG_PORT=8010 ./target/release/csg-sidecar   # http://127.0.0.1:8010
```

Endpoints (contract of `src/protection/csg-client.ts`): `GET /healthz`, `GET /v1/status`, `POST /v1/seal` (content_base64 + label/attributes/proyecto_id/evento_id → sello `csg.sello.v1`), `POST /v1/verify` (content_base64 + sello → `{todo_valido, checks{content_digest_match, cuerpo_no_alterado, firma_notario_valida, aceptado}}`). Notario keys are ephemeral per process; each seal carries its `notario_pub`, so seals keep verifying after a restart, but the seal chain lives in memory. Until a sidecar is present, TDCP treats CSG as a **design-time attestation hook**: document the event types to seal (grant issue, successful unlock, policy revoke) and keep the Notario master key out of the TDCP process.

Verify from this repo:

```bash
CSG_SEAL_URL=http://127.0.0.1:8010 \
node --experimental-strip-types examples/csg-seal-verify-example.ts
# seal -> verify todo_valido:true; altered content -> todo_valido:false
```

### 3. Verify the Smart Token bridge too

```bash
# API running on :8000, then from this repo:
SMART_TOKEN_API_URL=http://127.0.0.1:8000 SMART_TOKEN_API_KEY=<same key> \
node --experimental-strip-types examples/smart-token-bridge-example.ts
# Verified 2026-11-11: protect 250 ms, open 210 ms, 1,019 bytes byte-identical, friction OK.
# Note: Smart Token API fix 2026-11-11 — local-storage open no longer deletes the artifact.
```

### 4. Wire into TDCP (environment)

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

## TypeScript clients (this repo)

Two minimal fetch-based clients live in this repo: `sdk/typescript/src/smart-token-client.ts` (Smart Token: healthz/protect/open/friction, re-exported from the SDK index) and `src/protection/csg-client.ts` (`CsgClient`: healthz/status/seal/verify against the CSG sidecar, plus `csgClientFromEnv()` reading `CSG_SEAL_URL` / `VITE_CSG_SEAL_URL`). Both only talk to self-hosted services on loopback; no npm dependency beyond the platform `fetch`.

```ts
import { SmartTokenClient } from '../sdk/typescript/src/index.ts';

const stp = new SmartTokenClient({
  baseUrl: process.env.SMART_TOKEN_API_URL ?? 'http://127.0.0.1:8000',
  apiKey: process.env.SMART_TOKEN_API_KEY ?? '',
});

const health = await stp.healthz();
// protect / open require master per call — never persist it in TDCP state
```

```ts
import { CsgClient } from '../src/protection/csg-client.ts';

const csg = new CsgClient({ baseUrl: 'http://127.0.0.1:8010' });
const sello = await csg.seal(content, { label: 'tdcp-integrity', proyecto_id: 'tdcp' });
const report = await csg.verify(content, sello); // report.todo_valido === true
```

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
