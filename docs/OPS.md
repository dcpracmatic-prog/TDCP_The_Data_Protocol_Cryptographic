# Authority operations (MVP)

**Honest scope:** File-backed durable Authority under `data/authority/`. This is **not** HA multi-region infra. Use this runbook for design-partner / hosted Starter drills.

See also: `docs/AUTHORITY.md`, `LAUNCH.md`, `docs/SECURITY_REVIEW_PACK.md`.

## Health & readiness

| Endpoint | Meaning |
|----------|---------|
| `GET /health` | Process up (liveness) |
| `GET /ready` | Store writable **and** signing key loaded |
| `GET /metrics` | Prometheus text counters (`grants_issued`, `grants_denied`, `revokes`, …) |

Compose / k8s should gate traffic on `/ready`, not only `/health`.

## Structured logs

Authority emits one JSON object per request (`service=tdcp-authority`). Fields: `method`, `path`, `status`, `durationMs`, `client`, optional `errorCode`.

**Never logged:** `Authorization` header, admin tokens, wrap secrets, JWKs, grant signature bodies beyond status codes.

## Backups (`data/authority/`)

Critical files (default layout):

- `authority-state.json` — policies, wrap secrets (base64), revocation, replay, challenges, **development signing JWK** (if `TDCP_SIGNING_BACKEND=file`)

### Backup procedure (sketch)

1. Stop or quiesce writers if possible (single-node MVP: brief pause).
2. Copy the entire `TDCP_AUTHORITY_DATA_DIR` (default `./data/authority`) to encrypted offline storage.
3. Record backup time, host, and Authority `keyId` from `GET /v1/public-key`.
4. Verify copy checksums.

Treat backups as **secret material** (wrap secrets + signing JWK when using file backend).

### Restore drill

1. Provision empty host / volume.
2. Restore `data/authority/` from backup.
3. Set `TDCP_AUTHORITY_ADMIN_TOKEN`, `TDCP_SIGNING_BACKEND`, `TDCP_AUTHORITY_DATA_DIR`.
4. Start Authority; confirm `GET /ready` → `ready: true`.
5. Confirm `GET /v1/public-key` `keyId` matches pre-backup.
6. Issue challenge + authorize against a known registered document (or re-register via admin API).
7. Confirm revoke state for a previously revoked document still denies grants.

Schedule a restore drill at least once before any paid Starter launch.

## SLO sketch (non-contractual)

| Signal | Target sketch |
|--------|----------------|
| Availability (`/ready` success from probe) | 99.5% monthly (Starter) |
| Grant `POST /v1/authorize` p95 | < 300 ms (single region, unloaded) |
| Durable revoke effectiveness | Revoke visible to new grants within 1 process (immediate on node) |
| Backup RPO | ≤ 24 h (Starter); tighter for Growth |
| Backup RTO | ≤ 4 h manual restore (Starter) |

Publish customer-facing SLOs only after ops ownership is assigned.

## Alert suggestions

| Alert | Condition |
|-------|-----------|
| Authority down | `/health` failing > 2 min |
| Not ready | `/ready` ≠ 200 > 1 min |
| Grant deny spike | `grants_denied` rate ≫ baseline (replay attacks / misconfig) |
| Admin auth failures | `admin_unauthorized` rising (token leak / brute force) |
| Rate limit | `rate_limited` sustained (abuse or undersized limit) |
| Disk / backup | Backup job failed; data dir disk > 80% |

Wire Prometheus scrape to `/metrics` or equivalent.

## Admin token

```bash
export TDCP_AUTHORITY_ADMIN_TOKEN="$(openssl rand -hex 32)"
# Clients / issuer tooling:
# Authorization: Bearer $TDCP_AUTHORITY_ADMIN_TOKEN
```

Required for: `POST /v1/documents/register`, `POST /v1/revoke`, `POST /v1/restore`, `GET /v1/documents`, `GET /v1/revoked`.

Gatekeeper public path (challenge / authorize / wrap-secret release) does **not** use this token.

## Signing backend

- `TDCP_SIGNING_BACKEND=file` (default) — extractable JWK on disk. **Not production-grade.**
- `TDCP_SIGNING_BACKEND=kms-stub` — documents KMS Sign hook; still local keys; **not** AWS KMS.

Paid launch blocker: real KMS/HSM signing + reviewed key custody.
