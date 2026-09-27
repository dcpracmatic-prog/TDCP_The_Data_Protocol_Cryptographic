# Modos de protección (pre-producción)

| Modo | Cifrado | TDCP Gatekeeper | Smart Token API | CSG |
|------|---------|-----------------|-----------------|-----|
| `tdcp` | AES-256-GCM | Sí | No | No |
| `tdcp_csg` | AES-256-GCM | Sí | No | Sí |
| `smart_token` | Smart-Token-Prod | No | **Obligatorio** | No |
| `smart_token_csg` | Smart-Token-Prod | No | **Obligatorio** | Sí |
| `csg_only` | No | No | No | Solo integridad |

## Smart Token (repo aislado)

Upstream: https://github.com/dcpracmatic-prog/Smart-Token-Prod

TDCP **no** embebe el crypto core. Solo habla HTTP:

- `POST /v1/artifacts` + `Authorization: Bearer` + `X-Smart-Token-Master`
- `POST /v1/artifacts/{id}/open` (respuesta binaria; 403 = DENIED opaco)
- `GET /healthz`

Variables Vite (UI):

```bash
VITE_SMART_TOKEN_API_URL=https://your-stp.example
VITE_SMART_TOKEN_API_KEY=<same as SMART_TOKEN_API_KEY on API>
```

**No hay soft/demo local.** Sin URL/key los modos STP fallan cerrado.

CORS: el API debe permitir el origen de la UI (p. ej. `https://tdcp.vercel.app`).

## CSG

`createCsgSeal` / `verifyCsgSeal`: sidecar `VITE_CSG_SEAL_URL` o sello local de desarrollo.
