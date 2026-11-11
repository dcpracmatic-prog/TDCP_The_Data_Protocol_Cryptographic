# CSG + Smart Token bridge (free / self-hosted)

**Status (2026-11-11): FUNCIONANDO de extremo a extremo, verificado en local.** Smart Token API (`api/` en Smart-Token-Prod) habla el contrato exacto del cliente TDCP (`sdk/typescript/src/smart-token-client.ts`): protect → open → friction con roundtrip byte-idéntico. El sidecar CSG existe: `sidecar/` en el repo CSG (binario Rust `csg-sidecar` sobre el crate `sello-integridad`, loopback 127.0.0.1:8010) y el cliente TDCP (`src/protection/csg-client.ts`) sella y verifica contra él. Ejemplos verificados: `examples/smart-token-bridge-example.ts` y `examples/csg-seal-verify-example.ts`.

**P2-5 (2026-11-11): sello CSG incrustado en el .pkg.** El puente ya no es solo atestación de operaciones: al proteger, el paquete completo se sella con el sidecar y el sello viaja DENTRO del `.pkg` (`csgSeal`); al abrir, el Gatekeeper verifica el sello ANTES de descifrar y falla cerrado si el contenido fue alterado. Detalle y reglas de fallo en la sección «P2-5: sello CSG incrustado en el .pkg» abajo. Smoke: `npm run smoke:csg-pkg`.

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

### 2. CSG / Sello (sidecar, verificado)

The public surface is the Rust crate `sello-integridad` (`Notario`, `NotarioProtegido`, `Firmante`, `verificar_sello`). Two HTTP sidecars implement the same contract (Ed25519 + SHA3-256, `csg.sello.v1`):

- **Upstream (Rust):** `sidecar/` in the CSG repo, binary `csg-sidecar` (thin wrapper over the crate — no crypto reimplemented).
- **In this repo (Python):** `server/csg-sidecar/main.py` — stdlib HTTP + `cryptography` only, same endpoints and field names, keys persisted under `CSG_DATA_DIR` (600). This is the sidecar the P2-5 package seal and the smoke test use; it is an implementation of the contract, not a second crypto design.

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd <CSG repo>/sidecar
cargo build --release --offline
CSG_PORT=8010 ./target/release/csg-sidecar   # http://127.0.0.1:8010
```

Or the in-repo Python sidecar:

```bash
pip install cryptography   # only dependency beyond stdlib
CSG_PORT=8010 CSG_DATA_DIR=./data/csg-sidecar python3 server/csg-sidecar/main.py
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

## P2-5: sello CSG incrustado en el .pkg

El sello CSG ya no vive solo en un archivo aparte (`.csg.json`, que sigue existiendo para la atestación del *plaintext* en los paneles): desde P2-5 el paquete `.pkg` lleva su propio sello dentro, en el campo `csgSeal`. Implementación: `src/core/package/csg-package-seal.ts` (sellar/verificar), `src/core/package/package-format.ts` (campo + bytes canónicos), `src/core/package/tdcp-factory.ts` (proteger), `src/gatekeeper/gatekeeper.ts` (abrir).

### Formato

```jsonc
{
  "magicHeader": "TDCP_SECURE_PKG",
  "version": "2.5-SEC",
  // ... envelope TDCP sin cambios ...
  "integrityHash": "<sha-256 del sobre, como siempre>",
  "csgSeal": {
    "schema": "csg.sello.v1",
    "evento_id": "TDCP-PKG-PKG-<id>",
    "aceptado": true,
    "hash_contenido": "<SHA3-256 del sobre canónico>",
    "cuerpo_hash": "<SHA3-256 del cuerpo>",
    "firma_notario": "<Ed25519 del Notario>",
    "notario_pub": "<clave pública del Notario>",
    "label": "tdcp-pkg"
    // ... resto de campos del sello, ver src/protection/csg-client.ts
  }
}
```

### Qué cubre exactamente

El sello cubre los **bytes canónicos del sobre** (`canonicalPackageEnvelopeString` / `canonicalPackageEnvelopeBytes` en `package-format.ts`): la misma representación que calcula `integrityHash` — cabecera, versión, algoritmo, `documentId`/`packageId`, salt, IV, **ciphertext completo**, AAD, **metadata completa**, CEK envuelta, epoch y fragmentos ultra-críticos. Es decir: estructura + contenido completo del paquete.

El campo `csgSeal` queda **fuera** de esos bytes a propósito: el sello se calcula sobre el sobre, así que incluirlo sería circular. Por eso `integrityHash` no cambia al añadir el sello y los paquetes viejos siguen siendo válidos.

### Relación con las otras capas (no sustituye nada)

| Capa | Qué garantiza | Qué pasa si falla |
|------|---------------|-------------------|
| Sello CSG (`csgSeal`) | Integridad del sobre completo, atestada por el Notario (tercero) | Apertura denegada ANTES de descifrar, sin consumir grant |
| AES-256-GCM del .pkg | Autenticidad del ciphertext (tag) + AAD ligado a la política | Descifrado rechazado (`DECRYPTION_AUTH_TAG_FAILED`) |
| Grant del Gatekeeper (un solo uso, época, anti-replay) | Autorización para ESTA operación, en ESTE dispositivo | Sin grant no hay CEK: no se descifra nada |

El sello detecta lo que el `integrityHash` no puede: ese hash es SHA-256 **sin clave** — cualquiera puede alter el ciphertext y recalcularlo. El sello, en cambio, solo lo puede emitir el Notario (firma Ed25519). Por eso el Gatekeeper lo verifica antes de pedir challenge/grant: un paquete alterado no debe quemar un grant de un solo uso.

### Reglas de fallo (decisión de seguridad, documentada)

- **Proteger, modo `required`** (lo que pide el panel cuando el operador elige un modo con CSG): si el sidecar no está configurado o no responde, **no se crea el paquete** — error `CSG_SIDECAR_UNAVAILABLE` / `CSG_SEAL_FAILED`. Nunca se finge un sello.
- **Proteger, modo `optional`** (por defecto en el resto de modos): si el sidecar no responde, el paquete se crea **sin sello** (forma legacy) y se informa. Nunca se sustituye por el sello local de desarrollo (`tdcp.csg-local.v1`): ese sello se genera en el proceso con clave efímera y no es una atestación del Notario; usarlo como sello de paquete sería fingir una garantía CSG.
- **Abrir, sello presente pero inválido/corrupto/esquema desconocido** → `CSG_PACKAGE_SEAL_FAILED`, sin descifrar nada.
- **Abrir, sello presente pero sidecar caído (no se puede verificar)** → `CSG_PACKAGE_SEAL_FAILED` (no verificable). Falla cerrado: no se abre por "no poder comprobar".
- **Abrir, sin sello (paquete legacy)** → abre por el camino actual (`csgSealStatus: 'absent'`). Compatible hacia atrás por diseño, documentado como **sin garantía CSG**. El panel de descifrado lo avisa al cargar el archivo.

Modos en código: `createTDCPPackage({ csgSeal: 'required' | 'optional' | 'off' })` (por defecto `'optional'`); el runtime lo pasa desde `tdcpRuntime.createPackage({ csgSeal })`; el panel de cifrado pide `'required'` en modos con CSG y `'optional'` en el resto.

### Verificación

- Tests unitarios + Gatekeeper: `src/core/package/csg-package-seal.test.ts` (13 tests; sidecar simulado con el mismo contrato, SHA3-256 + cuerpo hash).
- Smoke end-to-end con el sidecar real: `npm run smoke:csg-pkg` (`scripts/csg-pkg-smoke.mjs` + `scripts/csg-pkg-smoke-run.ts`). Levanta el sidecar Python en un directorio temporal, protege → abre OK; altera 1 byte del ciphertext (recalculando `integrityHash`) → denegado; apaga el sidecar → el paquete sellado sigue denegado; el legacy sin sello abre. Requiere `python3` + paquete `cryptography`; si falta, el smoke aborta con exit 2 y mensaje claro en vez de fingir un aprobado.

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
