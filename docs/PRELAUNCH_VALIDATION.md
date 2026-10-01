# Validación pre-lanzamiento TDCP

Sitio: https://tdcp.vercel.app  
Authority: https://tdcp.onrender.com  
Smart Token (opcional): https://smart-token-prod.onrender.com  

## 0. Infra (antes de probar UI)

```bash
curl -sS https://tdcp.onrender.com/healthz
curl -sS https://tdcp.onrender.com/v1/public-key
curl -sS https://smart-token-prod.onrender.com/healthz
```

- Authority debe responder `ok` (cold start free: esperar 30–60 s y repetir).
- Smart Token: `smart_token_available: true` y, tras el parche CORS, peticiones desde el origen del navegador no deben fallar por CORS.

## 1. Auth (obligatorio)

1. Abrir https://tdcp.vercel.app
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
4. Si el navegador reporta error CORS → el API aún no tiene middleware o falta redeploy en Render

## 5. CSG (opcional)

- Sello local en un encrypt: no requiere sidecar
- CSG remoto: solo con sidecar desplegado

## Go / No-go

| Resultado | Decisión |
|-----------|----------|
| Bloques 0–3 OK | Beta / pre-lanzamiento cerrado |
| + Bloque 4 OK | Se puede mencionar Smart Token |
| Falla 1–2 | No lanzar |

