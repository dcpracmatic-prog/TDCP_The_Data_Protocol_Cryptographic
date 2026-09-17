# TDCP Operational MVP — what works / what doesn’t

This document is the honesty contract for the **operational MVP** shipped via `./scripts/start-mvp.sh`.

## What works

| Capability | Status |
|------------|--------|
| One-command stack (Authority `:8787` + Web `:8080`) | Yes — `./scripts/start-mvp.sh` |
| Demo entry to Encrypt / Decrypt / Monitor | Yes — **Continuar en modo demo (MVP)** (local session) |
| Remote Authority when `VITE_TDCP_AUTHORITY_URL` set | Yes — `HttpAuthorityClient` + CORS for browser |
| Authority `/health`, `/ready`, `/metrics` | Yes |
| Admin Bearer register / revoke (token mode) | Yes — local token in `.mvp/admin-token` |
| Gatekeeper challenge → authorize → wrap-secret path | Yes against Authority (see smoke) |
| Durable revoke/replay (file store) | Yes — MVP file-backed, not HA |
| Smoke script | Yes — `npm run smoke:mvp` |
| In-process Oracle fallback | Yes when Authority URL unset; UI copy stays honest |

## What does **not** work (yet) — not claimed

| Item | Notes |
|------|-------|
| Real HSM / cloud KMS signing | `TDCP_SIGNING_BACKEND=file` (default) or `kms-stub` only |
| Multi-tenant isolation / billing | Out of scope for this wedge |
| Production IdP / SSO for the demo UI | Local demo session + optional localStorage accounts |
| Firebase / Gemini control plane | Explicitly excluded |
| Full IRM SaaS (Office plugins, CASB, DLP suite) | Not this product |
| Formal certification / security proof | See `AUDIT_2.5.1.md` |
| Encrypted backups / HA Authority | Single-node file store |

## Paid production gaps (next)

1. Real KMS/HSM key custody + non-extractable signing
2. Independent security review
3. Multi-tenant Authority + ToS/DPA
4. Production admin auth (OIDC/mTLS as documented in `docs/ADMIN_AUTH.md`) operated properly
5. SLOs, encrypted durable store, backup/restore drills

## Commands

```bash
./scripts/start-mvp.sh    # start
./scripts/stop-mvp.sh     # stop
npm run smoke:mvp         # health + admin register + authorize
npm test                  # suite (must stay green)
```
