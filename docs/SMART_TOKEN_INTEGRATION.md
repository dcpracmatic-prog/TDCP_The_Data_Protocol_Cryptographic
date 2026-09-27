# Integración Smart Token → TDCP (pre-prod)

## Arquitectura

```
[ UI Vercel ] --Bearer+Master--> [ Smart-Token-Prod API ] --SDK--> crypto ML-KEM
       |                                  |
       +---- .stok.json (artifact_id) ----+
       |
       +---- Gatekeeper path (solo .pkg TDCP) ----> Authority Render
```

- **Aislamiento:** Smart Token es un producto/repo aparte. TDCP solo guarda `artifact_id` en un envelope JSON (`tdcp.stp-remote-ref.v1`).
- **Confianza:** la UI solo llama a `VITE_SMART_TOKEN_API_URL` (no URLs embebidas en el JSON).
- **Master:** header `X-Smart-Token-Master` por operación; nunca en localStorage/Authority.

## Flujo crear

1. Usuario elige modo Smart Token / STP+CSG.
2. `requireSmartTokenClient()` valida env.
3. `healthz` → `protect(file, master)`.
4. Se descarga `STP_*.stok.json` con `artifact_id`.
5. Si CSG: sello sobre **bytes originales** del archivo (no sobre el JSON).

## Flujo abrir

1. Usuario carga `.stok.json`.
2. `requireSmartTokenClient().open(artifact_id, master)`.
3. Plaintext en RAM / visor; opcional `verifyCsgSeal`.

## Despliegue API

```bash
# desde clone Smart-Token-Prod
export SMART_TOKEN_API_KEY=$(openssl rand -hex 32)
uvicorn api.main:app --host 0.0.0.0 --port 8000
# o scripts/start-sidecars.sh desde TDCP
```

Copiar la misma key a Vercel como `VITE_SMART_TOKEN_API_KEY`.
