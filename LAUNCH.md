# Production launch checklist

Use this before any commercial “hosted Authority” claim. The browser Oracle is **not** production.

## Security review

- [ ] Independent review of Authority design (`docs/AUTHORITY.md`) and Gatekeeper path
- [ ] Threat model updated; `AUDIT_2.5.1.md` non-claims still true
- [ ] No Firebase/Gemini in control plane
- [ ] Crypto/Gatekeeper semantics unchanged without explicit review

## Authority deploy

- [ ] Remote Authority deployed (not in-browser)
- [ ] Durable revoke/replay verified across restart
- [ ] **HSM/KMS** (or Secure Key Store) wired — replace file JWK signing
- [x] Admin register/revoke APIs authenticated (Bearer `TDCP_AUTHORITY_ADMIN_TOKEN`; mTLS/OAuth still preferred for Growth+)
- [ ] `TDCP_AUTHORITY_URL` configured for clients
- [ ] Backups + restore drill for Authority state (procedure in `docs/OPS.md`)

## Secrets & config

- [ ] No secrets in git; `.env` from `.env.example` only
- [ ] Signing keys never shipped to browsers
- [ ] TLS everywhere (Authority + web)

## Monitoring & support

- [x] Healthchecks (`/health`, `/ready`, `/metrics` on Authority)
- [ ] Metrics: grant issue rate, revoke events, replay rejects, error codes
- [ ] On-call / support path for design partners
- [ ] Incident runbook (key compromise → rotate + revoke epochs)

## Legal / GTM

- [ ] Honest marketing (no fake HSM / formal proof claims)
- [ ] License + customer terms for hosted Authority
- [ ] Pricing sketch reviewed (`docs/GTM.md`) — not published as final until approved
- [ ] Privacy / data-processing addendum if hosting wrap secrets / policies

## Exit for “launch readiness”

Green: remote Authority with durable revoke/replay, Gatekeeper SDK docs, launch checklist owners assigned, security review scheduled or complete.

Still demo until HSM/KMS + review: in-process Oracle UI, mock NFC/device/bio, local account shell.
