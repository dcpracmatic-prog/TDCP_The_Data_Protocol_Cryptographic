# Authority admin authentication

**Honest scope:** Production-hardening of the Authority **admin** surface (register / revoke / restore / admin lists). This is **not** a full enterprise IdP product, SSO portal, or multi-tenant IAM suite. Public Gatekeeper paths stay as they are.

See also: `docs/AUTHORITY.md`, `docs/OPS.md`.

## Modes

| `TDCP_AUTHORITY_ADMIN_AUTH` | Use when | What admin routes accept |
|----------------------------|----------|---------------------------|
| `token` (default) | Local / CI / quick demos | `Authorization: Bearer <TDCP_AUTHORITY_ADMIN_TOKEN>` |
| `oidc` | Hosted / IdP-backed | Valid OIDC/OAuth2 JWT with admin claim |
| `mtls` | Self-host / high assurance | TLS client certificate verified against CA |
| `oidc+mtls` | Highest bar in this MVP | **Both** valid JWT **and** client cert |

When mode is `oidc`, `mtls`, or `oidc+mtls`, the static Bearer `TDCP_AUTHORITY_ADMIN_TOKEN` is **disabled** (not accepted even if set).

Admin paths (unchanged):

- `POST /v1/documents/register`
- `GET /v1/documents`
- `POST /v1/revoke`
- `POST /v1/restore`
- `GET /v1/revoked`

Public Gatekeeper paths (challenge / authorize / wrap-secret / public-key / per-document policy get) do **not** use this auth.

## 1. Token mode (dev/local fallback)

```bash
export TDCP_AUTHORITY_ADMIN_AUTH=token   # or omit — default
export TDCP_AUTHORITY_ADMIN_TOKEN="$(openssl rand -hex 32)"
```

- Missing env token → **503** `ADMIN_TOKEN_NOT_CONFIGURED`
- Wrong/missing Bearer → **401** `UNAUTHORIZED`

Do **not** ship `VITE_TDCP_AUTHORITY_ADMIN_TOKEN` in production browser builds.

## 2. OIDC / OAuth2 JWT (preferred for hosted)

```bash
export TDCP_AUTHORITY_ADMIN_AUTH=oidc
export TDCP_OIDC_ISSUER=https://your-idp.example/realms/tdcp
export TDCP_OIDC_AUDIENCE=tdcp-authority
# Optional if not discoverable from issuer:
# export TDCP_OIDC_JWKS_URL=https://your-idp.example/.../protocol/openid-connect/certs
export TDCP_OIDC_ADMIN_CLAIM=tdcp_admin
# Optional: require exact string value instead of boolean/role-name match
# export TDCP_OIDC_ADMIN_CLAIM_VALUE=true
```

Issuer tooling sends:

```http
Authorization: Bearer <access_token>
```

Verification uses [`jose`](https://github.com/panva/jose) against JWKS (remote keys cached). Admin claim acceptance:

- `payload[TDCP_OIDC_ADMIN_CLAIM] === true` / `'true'`
- claim string / array contains the claim name (or `TDCP_OIDC_ADMIN_CLAIM_VALUE`)
- `roles` / `role` / `permissions` / `groups` contain the claim
- OAuth `scope` / `scp` contains the claim

Errors: **401** `OIDC_TOKEN_REQUIRED` / `OIDC_TOKEN_INVALID`, **403** `OIDC_ADMIN_CLAIM_MISSING`, **503** `OIDC_NOT_CONFIGURED` (or discovery failure).

## 3. mTLS (preferred for self-host / high assurance)

Generate local demo certs:

```bash
./scripts/gen-dev-mtls.sh
# writes data/mtls-dev/{ca,server,client}.{crt,key} + env.snippet
```

Run Authority with HTTPS + client CA:

```bash
export TDCP_AUTHORITY_ADMIN_AUTH=mtls
export TDCP_AUTHORITY_TLS_CERT_FILE=./data/mtls-dev/server.crt
export TDCP_AUTHORITY_TLS_KEY_FILE=./data/mtls-dev/server.key
export TDCP_MTLS_CA_FILE=./data/mtls-dev/ca.crt
export TDCP_MTLS_ALLOWED_CNS=tdcp-admin-dev   # optional allowlist; omit to allow any CA-signed client
npm run authority
```

Call admin APIs with a client certificate:

```bash
curl --cacert ./data/mtls-dev/ca.crt \
  --cert ./data/mtls-dev/client.crt --key ./data/mtls-dev/client.key \
  https://127.0.0.1:8787/v1/documents
```

Node HTTPS options used: `requestCert: true`, `rejectUnauthorized: true`, `ca: <TDCP_MTLS_CA_FILE>`.

Errors: **401** `MTLS_CLIENT_CERT_REQUIRED` / `MTLS_UNAUTHORIZED…`, **403** `MTLS_CN_NOT_ALLOWED`.

On plain HTTP (no TLS), mTLS mode always fails admin routes with `MTLS_CLIENT_CERT_REQUIRED` — expected.

## 4. oidc+mtls

Requires **both** a valid admin JWT **and** a verified client cert. Configure all OIDC and mTLS/TLS env vars above; set `TDCP_AUTHORITY_ADMIN_AUTH=oidc+mtls`.

## Docker Compose notes

Default `docker-compose.yml` stays on **token** mode so `./scripts/start-prod-stack.sh` keeps working. For mTLS, prefer mounting certs and setting env (see comments in compose), or run Authority outside Compose with the env snippet from `gen-dev-mtls.sh`. Optional profile sketch:

```bash
# Example only — not required for default stack
TDCP_AUTHORITY_ADMIN_AUTH=mtls \
TDCP_AUTHORITY_TLS_CERT_FILE=/certs/server.crt \
TDCP_AUTHORITY_TLS_KEY_FILE=/certs/server.key \
TDCP_MTLS_CA_FILE=/certs/ca.crt \
docker compose up authority
```

Expose HTTPS on the Authority port when TLS files are set (same `8787` mapping).

## Limitations

- Not a hosted IdP, user directory, or RBAC product — claim/CN checks only
- JWKS discovery needs network reachability to the issuer (or set `TDCP_OIDC_JWKS_URL`)
- mTLS needs process-level HTTPS; reverse-proxy client cert forwarding is out of scope for this MVP
- Static token remains the default for local demos; turn it off for shared/prod by switching mode
- Signing keys / wrap secrets custody is separate (`TDCP_SIGNING_BACKEND`) — see `docs/AUTHORITY.md`
