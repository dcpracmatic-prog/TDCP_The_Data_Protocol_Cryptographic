# Deploying TDCP Web

## Security notice (read first)

The default Authorization Oracle runs **in the browser / same process** as the UI. That is a **reference control plane**, not a production security boundary.

- A compromised browser/JS environment can inspect or alter Oracle state.
- Do **not** treat local or static hosting of this demo as “sovereign” authorization.
- Production requires a **remote Authorization Authority** with durable state and HSM/KMS-backed keys (see `docs/AUTHORITY.md`, `ARCHITECTURE.md`).
- The file-backed Authority MVP in `server/authority/` is durable across restart but is **still not HSM**.

## Vercel — despliegue de producción (tdcp.vercel.app)

> **Lo que pasó el 11 nov 2026:** el despliegue funcionaba con login y, a la vez,
> Supabase seguía con 0 usuarios. La causa: el despliegue servía la base en
> memoria (PGLite) porque las variables no habían tomado efecto en Production.
> Desde la P0-3 eso ya no puede pasar en silencio: **en producción la app no
> arranca sin `DATABASE_URL`** (falla al arrancar con un error claro) y el log
> de arranque dice qué backend está activo.

### 1. Variables en Vercel (Project Settings → Environment Variables)

Pega estas 4 en el entorno **Production** (marca solo Production; Preview y
Development siguen usando PGLite sin variables):

| Variable | Valor |
|---|---|
| `DATABASE_URL` | La cadena del **Session pooler** de Supabase (Connect → Session pooler, puerto 5432). Empieza por `postgresql://postgres.<ref>:<contraseña>@aws-0-<región>.pooler.supabase.com:5432/postgres`. Codifica caracteres especiales de la contraseña (`@` → `%40`). |
| `BETTER_AUTH_SECRET` | Un secreto largo, por ejemplo `openssl rand -hex 32`. Nunca lo pegues en el repo ni en un chat. |
| `BETTER_AUTH_URL` | `https://tdcp.vercel.app` |
| `VITE_AUTH_ENABLED` | `true` |

Opcional, si usas correo real: `RESEND_API_KEY` y `EMAIL_FROM`. Sin ellas, en
producción sale una advertencia en el log y no se envían correos de
verificación ni de restablecimiento.

### 2. Redeploy

Después de pegar o cambiar una variable, Vercel **no** la aplica al despliegue
que ya está en vivo. Hay que redesplegar:

Deployments → el despliegue de Production (el de la rama `main`) → **⋯ → Redeploy**
(o empuja un commit nuevo a `main`, que despliega solo).

### 3. Qué verificar tras el redeploy (Arturo)

1. **Log de arranque:** en Vercel → Deployments → el despliegue → Runtime Logs,
   busca la línea `[db] backend=postgres (DATABASE_URL configurada; cuentas en
   Postgres/Supabase)`. Si dice `backend=pglite`, el redeploy no tomó las
   variables (revisa que estén en Production, no solo en Preview).
2. **Endpoint:** abre `https://tdcp.vercel.app/api/db-status`. Debe devolver
   `{"backend":"postgres","databaseConfigured":true,"production":true,"ready":true}`.
   No muestra secretos, solo el nombre del backend.
3. **Crea una cuenta** en la app y comprueba en Supabase (Table Editor → tabla
   `user`) que aparece **1 usuario**. Si sigue en 0, el despliegue sigue en
   PGLite: repite los pasos 1 y 2.
4. Si el despliegue **falla al arrancar** con `[db] FALTA DATABASE_URL en
   producción…`, es la guardia funcionando: falta `DATABASE_URL` en Production
   (paso 1), no es un fallo del código.

> Nota: el `npm run preview` local sigue usando PGLite aunque sirva el build
> de producción. La guardia solo actúa en el despliegue de Vercel
> (`VERCEL_ENV=production`); un `NODE_ENV=production` local sin marcas de
> Vercel no la dispara.

## Local development (web only)

```bash
# from repo root
cp .env.example .env   # optional
./scripts/start.sh
# → http://127.0.0.1:8080/
```

Equivalent:

```bash
npm install
npm run dev
```

Useful checks:

```bash
npm test
npm run typecheck
npm run lint
npm run build
```

`npm run build` also runs DB migrate; without `DATABASE_URL` the migrate step skips (PGLite path).

## Local prod-stack (Authority + web)

One command:

```bash
./scripts/start-prod-stack.sh
# Prefer: docker compose up --build
# Authority → http://127.0.0.1:8787/health
# Web       → http://127.0.0.1:8080/
```

Set clients to:

```bash
export TDCP_AUTHORITY_URL=http://127.0.0.1:8787
# browser builds may use:
export VITE_TDCP_AUTHORITY_URL=http://127.0.0.1:8787
```

Authority-only:

```bash
npm run authority
# or: node --experimental-strip-types server/authority/index.ts
```

## Docker Compose

```bash
docker compose up --build
# services: authority (:8787) + web (:8080)
# volume: authority-data → /data/authority
```

Healthchecks are defined for both services. This stack exercises the remote Authority path; it does **not** provide HSM.

## Static / preview build

```bash
npm install
npm run build
npm run preview
```

Preview defaults follow the App Builder scripts (see `scripts/preview.mjs`; preview port is typically **8081**). The primary **dev** URL remains **http://127.0.0.1:8080/**.

Hosting `dist/` alone does not create a remote authorization boundary unless clients point at a live Authority.

## Environment

See `.env.example`. Never commit secrets (`BETTER_AUTH_SECRET`, real `DATABASE_URL` credentials, Authority signing JWKs under `data/authority/`).

## Demo vs production UI

- **Reference / Demo — Oracle in-browser** when `TDCP_AUTHORITY_URL` is unset
- **Production path — set TDCP_AUTHORITY_URL** when pointing at remote Authority
- Create a local demo account via AuthScreen “Crear Cuenta” (localStorage shell — not production IdP). See AuthScreen evaluator hints when `VITE_TDCP_DEMO_MODE=1`.

## Firebase / Gemini

This product tree must **not** include Firebase, Gemini, or AI Studio `server.ts` as the protocol control plane. Keep Google Drive UI/storage adapters separate from Oracle/Gatekeeper crypto paths.

## CI workflow file

GitHub Actions YAML lives at `.github/workflows/ci.yml`. Includes Authority tests via `npm test`.
