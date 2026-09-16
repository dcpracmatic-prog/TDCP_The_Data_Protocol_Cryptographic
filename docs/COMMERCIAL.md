# Commercial offer sketch (TDCP)

**Not published pricing.** Sketches for founder / sales conversations. Align with `docs/GTM.md`, `LAUNCH.md`, `MARKET.md`.

## SKUs

| SKU | What customer gets | What is included | Requires sales / legal |
|-----|--------------------|------------------|------------------------|
| **Self-host protocol** | This repo: Gatekeeper + reference Oracle/Authority | Protocol, TS SDK docs, self-run Authority MVP | No (open/reference). Support optional |
| **Hosted Authority — Starter** | Managed remote Authority URL, durable revoke/replay, admin token issuance | Grant quota sketch, `/health`+`/ready`+`/metrics`, backup policy sketch | Yes: ToS, DPA if holding wrap secrets/policies, billing |
| **Hosted Authority — Growth** | Starter + higher quota, HA sketch, audit export sketch, support SLA sketch | Ops runbooks (`docs/OPS.md`), restore drills | Yes: MSA/SLA, security questionnaire |
| **Enterprise** | Dedicated Authority, real KMS/HSM, review support | Custom networking, key custody design | Yes: always |

**Non-SKU (near term):** Office plugins, email gateway, CASB listing, Firebase/Gemini control plane, "full Virtru replacement."

## What Starter does **not** include (honesty)

- Certified HSM/KMS until wired and reviewed
- Formal security certification
- Multi-region active-active (unless explicitly sold later)
- Browser in-process Oracle as the hosted product

## Legal placeholders (links TBD)

| Document | Purpose | Status |
|----------|---------|--------|
| Terms of Service (hosted) | Use of Hosted Authority | Placeholder — link TBD |
| Privacy Policy | Personal data in admin/billing | Placeholder — link TBD |
| DPA / Data Processing Addendum | Policies, wrap secrets, logs as customer data | Placeholder — link TBD |
| Acceptable Use | Abuse / illegal content | Placeholder — link TBD |
| Security overview | Point to `docs/SECURITY_REVIEW_PACK.md` + AUDIT non-claims | Draft in-repo |
| SLA (Growth+) | Availability / support | Sketch only in `docs/OPS.md` |

Do not collect payment until ToS/DPA placeholders are replaced with counsel-approved links.

## Launch checklist cross-link

Before charging cards, complete **`LAUNCH.md`** (security review, KMS path, admin auth, backups, honest marketing). Commercial copy: `docs/LANDING_COPY.md`.

## Billing sketch

- Starter: monthly subscription + included grant quota; overage sketch
- Growth: higher base + SLA
- Meter: `grants_issued` (and optionally `revokes`) from `/metrics` or billing logs — **do not** log secrets

Exact numbers: finance/legal sign-off required (`docs/GTM.md`).
