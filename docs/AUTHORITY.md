# Authorization Authority (design)

**Status:** Design + durable MVP stub shipped (file-backed). **Not** HSM/KMS. Browser Oracle remains reference/demo.

Canonical product: `PRODUCT.md`. Roadmap: `ROADMAP.md` P0–P1.

## Responsibilities

| Responsibility | Owner |
|----------------|--------|
| Policy evaluation | Authority |
| Challenge issue / freshness | Authority |
| One-time grant issuance (ECDSA P-256) | Authority |
| Wrap-secret release after verified grant | Authority |
| Revoke / epoch rotation | Authority (durable) |
| Replay / consumed operation registry | Authority (durable) |
| Document policy registration at encrypt time | Authority |
| Envelope integrity + unlock orchestration | **Gatekeeper** (client) |
| Ciphertext storage | Neutral (Drive / disk / blob) |

The Authority **never** receives plaintext or the content encryption key (CEK). It holds per-document **wrap secrets** used as an HKDF factor so that password + package copy is insufficient.

## Trust model

```
[Client / Gatekeeper]  --min material-->  [Authorization Authority]
        |                                         |
   verifies grant                          signs grants
   unlocks via Gatekeeper only             owns revoke/replay
                                           owns wrap secrets
                                           (prod: HSM/KMS signing)
```

**Assumptions**

1. **Durable state** for revoke, replay, challenges, policies, and wrap secrets survives Authority process restart.
2. **Production signing keys** live in HSM / KMS / platform Secure Key Store (stubs exist in `src/oracle/oracle-key-store.ts`). The MVP file store uses an extractable JWK on disk — **development only**.
3. **Client receives minimum material:** public key (verify), short-lived challenges, one-time grants, and wrap-secret bytes only after grant verification/consumption — never the Authority private key.
4. A compromised browser is **not** a production security boundary when using the in-process Oracle. Remote Authority moves the control plane off the client.

## Durable state (MVP)

Persisted under `data/authority/` (gitignored), default file `authority-state.json`:

- Registered document policies
- Per-document wrap secrets (base64)
- Revocation / epoch state
- Consumed operations + grant IDs
- Active challenges (TTL still enforced in memory logic)
- Development signing JWK pair (honest: not HSM)

## HTTP API sketch

Base URL: `TDCP_AUTHORITY_URL` (e.g. `http://127.0.0.1:8787`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/v1/public-key` | Key id + SPKI (verify grants) |
| POST | `/v1/challenge` | Issue fresh challenge |
| POST | `/v1/challenge/validate` | `{ challenge }` → `{ valid }` |
| POST | `/v1/documents/register` | Register policy; returns wrap secret once |
| GET | `/v1/documents` | List policies |
| GET | `/v1/documents/:id/policy` | Get policy |
| GET | `/v1/documents/:id/revocation` | Epoch / revoke state |
| POST | `/v1/authorize` | Process `AuthorizationRequest` → grant or deny |
| POST | `/v1/wrap-secret/release` | `{ grant }` → wrap secret or null (one-time) |
| POST | `/v1/view-once/commit` | Commit view-once after successful decrypt |
| POST | `/v1/revoke` | Rotate epoch / revoke |
| POST | `/v1/restore` | Clear revoke flag (new epoch) |
| GET | `/v1/revoked` | List revoked |

## Client wiring

- Env `TDCP_AUTHORITY_URL` (or `VITE_TDCP_AUTHORITY_URL`) → `HttpAuthorityClient`
- Else → `InProcessAuthority` wrapping the browser/in-process Oracle (current demo behavior)

Gatekeeper accepts optional `authority`; existing `oracle` option remains for backward compatibility.

## What is still required for production

- Real HSM/KMS-backed signing (no extractable JWK on disk)
- Broader IdP product features (SSO UI, multi-tenant RBAC) beyond admin JWT/mTLS hardening — see `docs/ADMIN_AUTH.md`
- Independent security review
- Multi-tenant isolation, backups, monitoring, SLOs
- Formal threat model update in `AUDIT_2.5.1.md`

## Admin authentication

Admin endpoints (register / revoke / restore / admin lists) support stronger modes via `TDCP_AUTHORITY_ADMIN_AUTH`:

| Mode | Summary |
|------|---------|
| `token` (default) | Bearer `TDCP_AUTHORITY_ADMIN_TOKEN` — **local/dev fallback** |
| `oidc` | OAuth2/OIDC JWT + admin claim — preferred for hosted |
| `mtls` | Client certificate against CA — preferred for self-host / high assurance |
| `oidc+mtls` | Both JWT and client cert required |

Full configuration, error codes, and mTLS cert generation: **`docs/ADMIN_AUTH.md`**.

Token-mode quick start:

```bash
export TDCP_AUTHORITY_ADMIN_AUTH=token   # default
export TDCP_AUTHORITY_ADMIN_TOKEN="$(openssl rand -hex 32)"
curl -s -X POST "$TDCP_AUTHORITY_URL/v1/documents/register" \
  -H "authorization: Bearer $TDCP_AUTHORITY_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"documentId":"DOC-1","packageId":"PKG-1","policyLevel":"STANDARD","allowExtraction":false,"createdAt":0}'
```

When mode is `oidc|mtls|oidc+mtls`, the static Bearer token is **disabled**. Issuer tooling may still use `TDCP_AUTHORITY_ADMIN_TOKEN` with `HttpAuthorityClient` for local token mode only. `VITE_TDCP_AUTHORITY_ADMIN_TOKEN` is **local demo only** (leaks into the browser bundle).

Gatekeeper public path (challenge / authorize / wrap-secret release / public-key / per-document policy get) stays unauthenticated, with in-memory rate limits on challenge/authorize.

**Honesty:** this hardens the admin surface; it is not a full enterprise IdP.

## Ops endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/ready` | Ready = store writable + signing key loaded |
| GET | `/metrics` | Prometheus counters |

See `docs/OPS.md`.

## Signing backend

| `TDCP_SIGNING_BACKEND` | Behavior |
|------------------------|----------|
| `file` (default) | Extractable JWK on disk via `DurableFileOracleKeyStore`. **NOT production-grade.** |
| `kms-stub` | `KmsOracleKeyStore` stub — local key + `signCanonical` hook documenting AWS KMS Sign. **No AWS credentials. NOT production-grade.** |

Production: implement real KMS Sign behind `OracleKeyStore.signCanonical` (see `src/oracle/oracle-key-store.ts`). Clear README note: file JWK is not production-grade.

## Commercial hardening docs

- Ops / backups / SLO sketch: `docs/OPS.md`
- Security review pack (not a certification): `docs/SECURITY_REVIEW_PACK.md`
- SKUs / legal placeholders: `docs/COMMERCIAL.md`
- Landing copy EN/ES: `docs/LANDING_COPY.md`
