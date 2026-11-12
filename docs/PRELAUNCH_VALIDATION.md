# Validación pre-lanzamiento TDCP

> Soberanía: este documento no contiene hosts reales. Las URLs del
> despliegue propio del operador se pasan por variables de entorno
> (`$TDCP_SITE_URL`, `$TDCP_AUTHORITY_URL`, `$SMART_TOKEN_API_URL`).
> La validación que corre en el repo es siempre contra dobles locales o
> loopback, nunca contra un servicio externo (ver
> `docs/SOVEREIGN_ARCHITECTURE.md`). Antes de validar, exporta las tres
> variables con las URLs de tu propio despliegue:
>
> ```bash
> export TDCP_SITE_URL="https://<tu-sitio>"
> export TDCP_AUTHORITY_URL="https://<tu-authority>"
> export SMART_TOKEN_API_URL="https://<tu-smart-token>"  # solo si anuncias Smart Token
> ```

## 0. Infra (antes de probar UI)

```bash
curl -sS "$TDCP_AUTHORITY_URL/healthz"
curl -sS "$TDCP_AUTHORITY_URL/v1/public-key"
curl -sS "$SMART_TOKEN_API_URL/healthz"  # solo si anuncias Smart Token
```

- Authority debe responder `ok` (arranque en frío del despliegue: esperar 30–60 s y repetir).
- Smart Token: `smart_token_available: true` y, tras el parche CORS, peticiones desde el origen del navegador no deben fallar por CORS.

## 1. Auth (obligatorio)

1. Abrir `$TDCP_SITE_URL`
2. Confirmar que **no** hay “Continuar en modo demo”
3. Crear cuenta → cerrar sesión → iniciar sesión de nuevo

## 2. Encrypt / Decrypt TDCP (obligatorio)

1. Modo protección **TDCP** (no Smart Token)
2. Cifrar un archivo de prueba → descargar `.pkg`
3. Abrir el mismo `.pkg` con la contraseña correcta → OK
4. Contraseña incorrecta → denegación (sin filtrar detalles internos)
5. (Si aplica) View-once: segunda apertura denegada

## 3. Invariante

- Solo el archivo `.pkg` sin registro/autorización en Authority **no** concede uso.

## 4. Smart Token (solo si lo anuncias)

1. Modo Smart Token en UI
2. Proteger → obtener `artifact_id`
3. Abrir con master correcto
4. Si el navegador reporta error CORS → el API aún no tiene middleware o falta redeploy del despliegue propio del operador

## 5. CSG (opcional)

- Sello local en un encrypt: no requiere sidecar
- CSG remoto: solo con sidecar desplegado (sidecar local en-repo, `server/csg-sidecar/main.py`, en `127.0.0.1:8019`)

## Go / No-go

| Resultado | Decisión |
|-----------|----------|
| Bloques 0–3 OK | Beta / pre-lanzamiento cerrado |
| + Bloque 4 OK | Se puede mencionar Smart Token |
| Falla 1–2 | No lanzar |
