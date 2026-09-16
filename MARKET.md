# Market positioning

TDCP is a **protocol-first wedge**: ciphertext is storage; authorization is a separate control plane (Authority/Oracle + Gatekeeper). This document orients against adjacent products — it is **not** a claim that TDCP is production-ready IRM SaaS.

Canonical product decisions: **`PRODUCT.md`**. Roadmap: **`ROADMAP.md`**.

## Wedge strategy

| We build | We do not chase (next ~2 quarters) |
|----------|-------------------------------------|
| Protocol + Gatekeeper reference | Full IRM feature parity vs Virtru/Seclore/Digify |
| Remote Authorization Authority | Office plugins, email gateway, CASB listing |
| TS SDK / integrator API | Firebase/Gemini control plane |
| Operation-scoped unlocks + revoke/replay | Claiming HSM parity for the browser Oracle |

**ICP (primary):** secure data rooms, regulated file exchange, agent pipelines needing READ/RENDER/EXTRACT with revoke/replay.  
**ICP (secondary):** security engineers evaluating open data-centric protocols (OpenTDF-adjacent).

**Viability:** real need for persistent post-share control; adoption path is protocol/SDK + remote Authority — not IRM marketplace feature race.

## Differentiation (TDCP stance)

| Theme | TDCP stance |
|-------|-------------|
| Copy ≠ auth | Explicit invariant: possessing the `.pkg` does not grant use |
| Storage neutrality | Package format aims to sit on Drive/local/any blob store |
| Operation-scoped grants | One-time signed grants for READ / RENDER_RAM / EXTRACT / AUDIT_EXPORT |
| Open reference | Inspectable crypto/policy path in-repo (browser Oracle today) |
| Control plane roadmap | Remote Authority is the commercial credibility milestone |

## Competitive table

| Product / pattern | Overlap | Gap vs TDCP narrative | TDCP gap vs them |
|-------------------|---------|------------------------|------------------|
| **Seclore** | Persistent file protection, usage control after share | Mature IRM, enterprise connectors, admin UX | Production Trust, scale, certifications, plugin ecosystem |
| **Virtru** | Email/file encryption with persistent control; OpenTDF-adjacent ecosystem | Polished collaboration + policy UX; enterprise trust | Hardened remote control plane, connectors, SLA |
| **OpenTDF** (ecosystem) | Open data-centric / attribute-based packaging niche | Spec traction, vendor implementations, community | Spec maturity, interoperability, Authority production story |
| **Digify** | Secure document sharing, watermarks, expiry, data rooms | Sales-ready data-room features | Hardened remote control plane, enterprise ops |
| **Microsoft Purview / AIP** | Label-based protection, Office/Exchange ecosystem | Deep M365 integration, DLP, classification | Platform lock-in; TDCP aims storage-neutral packages |
| **Box IRM / Box Shield** | Enterprise file protection, access controls | Strong SaaS IRM, compliance integrations, admin UX | Mature multi-tenant ops, certifications, support |
| **age** | Modern file encryption CLI | Simple, auditable crypto tool | No authorization Oracle / grant lifecycle |
| **Bitwarden Send** | Ephemeral secure share links | Excellent UX for short-lived secrets | Not a full IRM/protocol with Gatekeeper ops |

## Honest gaps (this repo)

- Browser Oracle is **not** an HSM/KMS boundary (see `AUDIT_2.5.1.md`)
- Not formally verified; not a compliance product
- Not competing as full IRM SaaS (Office plugins, email gateway, CASB listing are non-goals)
- UI/auth shell still carries App Builder scaffolding; local demo auth ≠ production IdP
- Python SDK under `sdk/python` is a **demo sketch**, not protocol parity
- No ATL Edge implementation here (future bridge only; agents must unlock via Gatekeeper)

## What matters commercially next

1. Remote **Authorization Authority** design + stub interface  
2. Durable **revocation / replay** state  
3. **Gatekeeper API** for integrators + TS SDK surface  
4. Independent security review of the Authority design  

See `ROADMAP.md` for sequenced priorities.
