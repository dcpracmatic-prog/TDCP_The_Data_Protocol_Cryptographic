# Security review pack (TDCP Authority + Gatekeeper)

**Status:** Materials for an independent reviewer. **This document is not a certification, attestation, or formal proof.**

Canonical honesty: `AUDIT_2.5.1.md`. Product: `PRODUCT.md`. Authority design: `docs/AUTHORITY.md`.

## Scope

**In scope for review**

1. Remote Authorization Authority HTTP service (`server/authority/`)
2. Durable revoke / replay / wrap-secret custody (file MVP)
3. Gatekeeper unlock path (client must not bypass Oracle/Authority)
4. Grant verify + one-time wrap-secret release semantics
5. Admin Bearer auth for register/revoke; public grant path rate-limit readiness
6. Signing backend interface (`OracleKeyStore`, `signCanonical`, file vs kms-stub)

**Out of scope / deferred**

- Full IRM SaaS (plugins, email gateway, CASB)
- Firebase / Gemini control plane (explicitly disallowed)
- Formal cryptographic proofs
- Claiming production HSM/KMS while using `file` or `kms-stub`
- Browser in-process Oracle as a production trust boundary

## Threat model summary

| Threat | Mitigation (current) | Residual |
|--------|----------------------|----------|
| Ciphertext copy grants access | Package ≠ auth; wrap secret at Authority | Compromised Authority releases wrap secrets |
| Replay of challenge/operation | Anti-replay registry (durable MVP) | Single-node file store integrity |
| Stale grant after revoke | Epoch revocation at Authority | Propagation = that Authority node |
| Admin API abuse | Bearer `TDCP_AUTHORITY_ADMIN_TOKEN` | Shared secret ≠ mTLS/OAuth yet |
| Grant flooding | In-memory rate limit on challenge/authorize | Per-process; needs edge limits |
| Signing key theft (file JWK) | Documented non-claim; kms-stub hook | **File backend is not production-grade** |
| Browser fully compromised | Expected for in-process demo | Use remote Authority for production path |
| Log leakage of secrets | Structured logs omit Authorization | Operator misconfiguration |

## Trust boundaries

```
[ Untrusted client / Gatekeeper ]
        |  public: challenge, authorize, wrap-secret release (post-grant)
        |  verify grants with Authority public key
        v
[ Authorization Authority ]  <-- admin Bearer for register/revoke
        |  durable state + signing key material
        v
[ Storage (Drive/disk/blob) ]  <-- ciphertext only; neutral
```

- Authority never receives plaintext or CEK.
- Clients never receive Authority private keys.
- Admin token must not be embedded in public web bundles for production.

## Known non-claims

Do **not** assert:

- Formal security proofs or Common Criteria / FIPS certification from this repo
- HSM/KMS production custody while using `TDCP_SIGNING_BACKEND=file` or `kms-stub`
- Browser Oracle as remote sovereign authority / TPM / HSM
- Feature parity with Virtru / Seclore / Digify
- That in-memory rate limits replace edge WAF / API gateway controls

## Test map

| Area | Location |
|------|----------|
| Integration / Gatekeeper / tamper / replay | `src/test/tdcp-integration.test.ts` |
| Durable revoke / replay / one-time wrap | `src/authority/authority.test.ts` |
| Admin 401 / Bearer success / health/ready/metrics | `src/authority/authority.test.ts` |
| KMS stub `signCanonical` | `src/authority/authority.test.ts` |
| Auth invariant script | `npm run check:auth` |

## How to run the suite

```bash
npm install
npm test
npm run typecheck
npm run lint
npm run build
```

Optional Authority process:

```bash
export TDCP_AUTHORITY_ADMIN_TOKEN="$(openssl rand -hex 32)"
export TDCP_SIGNING_BACKEND=file   # or kms-stub
npm run authority
curl -s localhost:8787/ready
```

## Open questions for reviewer

1. Is Bearer admin token acceptable for Starter, or is mTLS / OAuth required before any paid tier?
2. Wrap-secret storage: encrypt-at-rest / envelope with KMS before Starter GA?
3. Multi-tenant isolation model for hosted Authority (namespace vs process vs cluster)?
4. Acceptable RPO/RTO and backup encryption standards for customer wrap secrets?
5. Should `GET /v1/documents/:id/policy` remain public, or move behind grant/auth?
6. Rate-limit / abuse controls: which belong in Authority vs API gateway?
7. Signing: prefer AWS KMS asymmetric Sign vs CloudHSM for first production backend?
8. Any Gatekeeper client assumptions that weaken remote-Authority trust?

## Contact / process

Assign reviewer, share this pack + `AUDIT_2.5.1.md` + PR diff for commercial hardening. Track findings in `LAUNCH.md` security checklist. **Do not** market "certified" based on this pack alone.
