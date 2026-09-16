# Deploying TDCP Web

## Security notice (read first)

The default Authorization Oracle runs **in the browser / same process** as the UI. That is a **reference control plane**, not a production security boundary.

- A compromised browser/JS environment can inspect or alter Oracle state.
- Do **not** treat local or static hosting of this demo as “sovereign” authorization.
- Production requires a **remote Authorization Authority** with durable state and HSM/KMS-backed keys (see `docs/AUTHORITY.md`, `ARCHITECTURE.md`).
- The file-backed Authority MVP in `server/authority/` is durable across restart but is **still not HSM**.

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

GitHub Actions YAML lives at `docs/ci.github.yml` (copy into `.github/workflows/ci.yml` with a token that has the `workflow` scope). Includes Authority tests via `npm test`.
