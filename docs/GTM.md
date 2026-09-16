# Go-to-market (commercialization sketch)

**Honest framing:** TDCP is a protocol + Gatekeeper wedge, not full IRM SaaS. Pricing and channels below are **sketches**, not published offers.

See `PRODUCT.md`, `MARKET.md`, `LAUNCH.md`.

## ICP

**Primary:** Teams building secure data rooms, regulated file exchange, or agent pipelines that need operation-scoped unlocks (READ / RENDER / EXTRACT) with revoke and replay protection.

**Secondary:** Security engineers evaluating open data-centric protocols (OpenTDF-adjacent niche).

## Offer

1. **Protocol + Gatekeeper reference** (open / self-host) — this repo  
2. **Hosted Authorization Authority MVP** — durable revoke/replay, remote grants (roadmap commercial credibility)  
3. **TypeScript SDK / integrator API** — Gatekeeper-only unlock surface  

Non-offer (near term): Office plugins, email gateway, CASB listing, Firebase/Gemini control plane, “full Virtru/Seclore replacement.”

## Pricing sketch (NOT final)

| Tier | Sketch |
|------|--------|
| Self-host protocol + Gatekeeper | Free / open reference |
| Hosted Authority — Starter | Low monthly + grant quota (sketch) |
| Hosted Authority — Regulated | Higher tier: HA, audit export, support SLA (sketch) |
| Enterprise | Custom: dedicated Authority, HSM/KMS, review, MSA |

Clearly marked as sketch — do not publish as committed pricing without legal/finance sign-off.

## Launch channels

1. Open-source / protocol community (GitHub, OpenTDF-adjacent discussions)  
2. Developer content: “copy ≠ auth” demos + TS SDK examples  
3. Design-partner outreach to data-room / regulated exchange builders  
4. Security review publication once Authority + HSM path is real  

## Competitive pitch (wedge vs Virtru / Seclore)

| Them | TDCP wedge |
|------|------------|
| Full IRM suite, connectors, polish | Protocol invariant: package ≠ authorization |
| Vendor control plane + plugins | Storage-neutral `.pkg` + Gatekeeper unlock API |
| Enterprise trust / certs today | Honest roadmap: remote Authority first, then trust |

**Pitch line:** “Don’t buy another IRM UI — integrate a protocol where copying the file never copies the right to use it.”

**Do not claim:** production HSM parity for browser Oracle; formal proofs; feature parity with Seclore/Virtru.
