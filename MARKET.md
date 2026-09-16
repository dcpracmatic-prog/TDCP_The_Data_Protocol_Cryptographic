# Market positioning (short)

TDCP Web is a **protocol-first reference**: ciphertext is storage; authorization is a separate control plane (Oracle + Gatekeeper). Competitors below are useful orientation — not a claim that TDCP is production-ready IRM.

## Differentiation

| Theme | TDCP stance |
|-------|-------------|
| Copy ≠ auth | Explicit invariant: possessing the `.pkg` does not grant use |
| Storage neutrality | Package format aims to sit on Drive/local/any blob store |
| Operation-scoped grants | One-time signed grants for READ / RENDER_RAM / EXTRACT / AUDIT_EXPORT |
| Open reference | Inspectable crypto/policy path in-repo (browser Oracle today) |

## Competitive sketch

| Product / pattern | Overlap | Gap vs TDCP narrative | TDCP gap vs them |
|-------------------|---------|------------------------|------------------|
| **Box IRM / Box Shield** | Enterprise file protection, access controls | Strong SaaS IRM, compliance integrations, admin UX | Mature multi-tenant ops, certifications, support |
| **Microsoft Purview / AIP** | Label-based protection, Office/Exchange ecosystem | Deep M365 integration, DLP, classification | Platform lock-in; TDCP aims storage-neutral packages |
| **Virtru** | Email/file encryption with persistent control | Polished collaboration + policy UX | Production trust, enterprise connectors |
| **Digify** | Secure document sharing, watermarks, expiry | Sales-ready data-room features | Hardened remote control plane, SLA |
| **age** | Modern file encryption CLI | Simple, auditable crypto tool | No authorization Oracle / grant lifecycle |
| **Bitwarden Send** | Ephemeral secure share links | Excellent UX for short-lived secrets | Not a full IRM/protocol with Gatekeeper ops |

## Honest gaps (this repo)

- Browser Oracle is **not** an HSM/KMS boundary
- Not formally verified; not a compliance product
- UI/auth shell still carries App Builder scaffolding
- Python SDK under `sdk/python` is a **demo sketch**, not protocol parity

Next product step that matters commercially: remote Authorization Authority + durable revocation/replay + independent security review.
