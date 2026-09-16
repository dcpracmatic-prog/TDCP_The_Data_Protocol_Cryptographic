# TDCP — Product definition

**Resumen (ES):** TDCP es un protocolo que separa paquetes cifrados de la autorización para operar sobre ellos. Copiar el ciphertext no copia la autorización. Vendemos protocolo + Gatekeeper de referencia, luego Authority remota y SDK; no competimos como IRM SaaS completo.

---

## Definition

**Product name:** TDCP (The Data Cryptographic Protocol)

**One-liner:** Protocol that separates encrypted packages from authorization to operate on them — copying ciphertext does not copy authorization.

A `.pkg` is storage. The Authorization Authority (Oracle in the reference build) is the control plane. The **Gatekeeper** is the only application path that may unlock a package for a scoped operation (e.g. READ / RENDER / EXTRACT).

## Problem

Once a file is shared, traditional encryption and share-link models lose persistent control: copies of the blob can be reused without fresh authorization, revocation is weak or absent, and agent/automation pipelines need operation-scoped unlocks rather than “give me the whole key.” Regulated data rooms and secure exchange still need post-share control without forcing every consumer into a single vendor IRM suite.

## Solution

TDCP encodes a clear split:

| Plane | Role |
|-------|------|
| **Data** | Authenticated ciphertext package (storage-neutral) |
| **Control** | Policy, revoke/replay, one-time grants for a named operation |
| **Gatekeeper** | Sole unlock path; verifies envelope + grant before releasing material |

What we sell / build toward (in order):

1. **Protocol + Gatekeeper reference** (canonical — this repo)
2. **Remote Authorization Authority** (next critical milestone)
3. **Developer / SDK surface** (TypeScript first; Python under `sdk/python` stays a demo sketch)
4. **Optional bridge to ATL Edge later** — agents unlock only via Gatekeeper (design/docs only; no ATL implementation in this repo)

## ICP

**Primary:** Teams building secure data rooms, regulated file exchange, or agent pipelines that need operation-scoped unlocks (READ / RENDER / EXTRACT) with revoke and replay protection.

**Secondary:** Security engineers evaluating open data-centric protocols (OpenTDF-adjacent niche).

## Non-goals (next ~2 quarters)

- Competing head-on with Virtru / Seclore / Digify as a full IRM SaaS
- Firebase / Gemini in the control plane
- Claiming HSM or browser-Oracle parity with hardware-backed production boundaries
- Office plugin suite, email gateway, or CASB marketplace listing

## Differentiation

- **Copy ≠ authorization** — explicit protocol invariant, not only an app feature
- **Storage neutrality** — package can live on Drive, local disk, or any blob store
- **Operation-scoped grants** — one-time signed grants for specific operations
- **Open reference** — inspectable crypto/policy path; honest about browser Oracle limits
- **Adoption path** — protocol/SDK wedge + remote Authority, not IRM feature parity

See `MARKET.md` for the competitive table and honest gaps.

## Viability

There is real market demand for **persistent post-share control**. TDCP’s viable path is not to out-feature enterprise IRM suites in the next two quarters. It is:

1. Make the protocol and Gatekeeper reference clear and credible
2. Ship a **remote Authorization Authority** with durable revoke/replay
3. Grow via **TS SDK / integrator API** into data-room, regulated exchange, and agent-pipeline builders

Viability depends on control-plane credibility (remote Authority + review), not on browser-demo polish alone.

## Relationship to ATL Edge (future)

ATL Edge (or similar agent runtimes) may later unlock TDCP packages **only through the Gatekeeper**, never by holding long-lived content keys in the agent. That bridge is a **future design note** (see `ROADMAP.md` P3). This repository does **not** implement ATL Edge code.

## Success metrics (next milestone)

Next milestone = **Remote Authorization Authority design + stub interface** (ROADMAP P0), then durable revoke/replay (P1).

| Metric | Signal |
|--------|--------|
| Authority interface published | Stable types/API for remote grant issue, revoke, replay, challenge |
| Integrator clarity | Gatekeeper remains the only unlock path; docs point to PRODUCT + ROADMAP |
| Honesty preserved | No HSM/production claims for browser Oracle; AUDIT non-claims intact |
| SDK direction | TS surface is the product SDK path; Python remains labeled demo |
| Review readiness | Architecture ready for independent security review of Authority design |

Further detail: `ROADMAP.md`, `ARCHITECTURE.md`, `AUDIT_2.5.1.md`.
