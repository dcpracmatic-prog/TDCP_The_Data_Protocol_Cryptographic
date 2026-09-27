# Modos de protección opcionales

| Modo | Cifrado | TDCP Gatekeeper | Smart Token | CSG |
|------|---------|-----------------|-------------|-----|
| `tdcp` | AES-256-GCM | Sí | No | No |
| `tdcp_csg` | AES-256-GCM | Sí | No | Sello local |
| `smart_token` | STP API o soft AES | No | Sí | No |
| `smart_token_csg` | STP + sello | No | Sí | Sello local |
| `csg_only` | No | No | No | Solo integridad |

## Smart Token remoto

```bash
VITE_SMART_TOKEN_API_URL=https://your-stp.example
VITE_SMART_TOKEN_API_KEY=...
```

Sin URL se usa **soft Smart Token** (AES-GCM + master, `developmentOnly`).

## CSG

Sello local ECDSA-P256 (`tdcp.csg-local.v1`). Producción: sidecar NotarioProtegido (`CSG_SEAL_URL`).

CSG **no cifra**: solo atestigua que el contenido no fue alterado.
