# Local demo account (evaluators)

**Does not weaken crypto.** Demo entry only unlocks the App Builder shell so evaluators can reach Encrypt / Decrypt / Gatekeeper panels.

## Preferred — MVP demo gate

1. `./scripts/start-mvp.sh`
2. Open `http://127.0.0.1:8080/`
3. Click **Continuar en modo demo (MVP)**
4. Use Encrypt / Decrypt / Monitor — banner shows Authority Connected/Offline

## Optional — localStorage account shell

1. Open the Web UI
2. Choose **Crear Cuenta** on AuthScreen
3. Register with any email + password + security question (stored locally in the browser)
4. Sign in → use Gatekeeper / Encrypt panels

`VITE_TDCP_DEMO_MODE=1` is set by `start-mvp.sh` for evaluator-oriented copy.

## What this is not

- Not a production IdP / SSO
- Not HSM
- Not a bypass of Gatekeeper, grants, or package crypto
- Not Firebase / Gemini

## Production path

Set `TDCP_AUTHORITY_URL` / `VITE_TDCP_AUTHORITY_URL` and run `./scripts/start-mvp.sh` (or `./scripts/start-prod-stack.sh` / `docker compose up`). UI badge reflects remote Authority when connected.
