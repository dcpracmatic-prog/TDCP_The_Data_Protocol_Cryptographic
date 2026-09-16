# Deploying TDCP Web

## Security notice (read first)

The Authorization Oracle in this build runs **in the browser / same process** as the UI. That is a **reference control plane**, not a production security boundary.

- A compromised browser/JS environment can inspect or alter Oracle state.
- Do **not** treat local or static hosting of this demo as “sovereign” authorization.
- Production requires a remote Authorization Authority with durable state and HSM/KMS-backed keys (see `ARCHITECTURE.md`).

## Local development

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

## Docker (dev-oriented)

A simple container that serves the Vite app on port 8080:

```bash
docker compose up --build
# → http://127.0.0.1:8080/
```

Or:

```bash
docker build -t tdcp-web .
docker run --rm -p 8080:8080 tdcp-web
```

This is for local/demo convenience. It does **not** harden the Oracle.

## Static / preview build

```bash
npm install
npm run build
npm run preview
```

Preview defaults follow the App Builder scripts (see `scripts/preview.mjs`; preview port is typically **8081**). The primary **dev** URL remains **http://127.0.0.1:8080/**.

For a pure static host, you still must understand that auth/Oracle semantics in this reference build are client-side; hosting `dist/` alone does not create a remote authorization boundary.

## Environment

See `.env.example`. Never commit secrets (`BETTER_AUTH_SECRET`, real `DATABASE_URL` credentials, provider keys). Auth is off by default (`VITE_AUTH_ENABLED=false`) for local preview.

## Firebase / Gemini

This product tree must **not** include Firebase, Gemini, or AI Studio `server.ts` as the protocol control plane. Keep Google Drive UI/storage adapters separate from Oracle/Gatekeeper crypto paths.

## CI workflow file

GitHub Actions YAML lives at `docs/ci.github.yml` (copy into `.github/workflows/ci.yml` with a token that has the `workflow` scope). The OAuth app used for this seed push could not create workflow files directly.

