# Local demo account (evaluators)

**Does not weaken crypto.** This only documents the App Builder / localStorage account shell so evaluators can reach Encrypt / Decrypt / Gatekeeper panels.

## Flow

1. Open `http://127.0.0.1:8080/`
2. Choose **Crear Cuenta** on AuthScreen
3. Register with any email + password + security question (stored locally in the browser)
4. Sign in → use Gatekeeper / Encrypt panels

Optional: set `VITE_TDCP_DEMO_MODE=1` for evaluator-oriented copy (badges already show Reference/Demo by default when Authority URL is unset).

## What this is not

- Not a production IdP / SSO
- Not HSM
- Not a bypass of Gatekeeper, grants, or package crypto

## Production path

Set `TDCP_AUTHORITY_URL` / `VITE_TDCP_AUTHORITY_URL` and run `./scripts/start-prod-stack.sh` (or `docker compose up`). UI badge switches toward the remote Authority path.
