# CSG Sello sidecar (TDCP)

Thin HTTP service that exposes the **Notario + Firmante** flow for TDCP integrity seals.

- Upstream design / Rust crate: https://github.com/dcpracmatic-prog/CSG
- Crypto: Ed25519 + SHA3-256 (field names aligned with `sello_integridad::Sello`)
- Stdlib HTTP server + `cryptography` only (no FastAPI required)

## Run

```bash
# from TDCP repo root
export CSG_PORT=8010
export CSG_DATA_DIR=./data/csg-sidecar
python3 server/csg-sidecar/main.py
```

Point TDCP at it:

```bash
export CSG_SEAL_URL=http://127.0.0.1:8010
export VITE_CSG_SEAL_URL=http://127.0.0.1:8010
```

## Endpoints

| Method | Path | Body |
|--------|------|------|
| GET | `/healthz` | — |
| GET | `/v1/status` | — |
| POST | `/v1/seal` | `{ content_base64, label?, attributes?, proyecto_id?, evento_id? }` |
| POST | `/v1/verify` | `{ content_base64, sello }` |

## TDCP wiring

- `src/protection/csg-client.ts` — HTTP client
- `src/protection/csg-seal.ts` — prefers remote sidecar, falls back to local ECDSA seal
- EncryptPanel / DecryptPanel use `createCsgSeal` / `verifyCsgSeal`

When `VITE_CSG_SEAL_URL` is unset, TDCP uses the local development seal (`tdcp.csg-local.v1`).
