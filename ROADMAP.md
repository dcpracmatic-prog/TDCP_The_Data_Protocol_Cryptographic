# TDCP roadmap

Product north star: **`PRODUCT.md`**. Architecture: **`ARCHITECTURE.md`**. Security honesty: **`AUDIT_2.5.1.md`**.

Do **not** change crypto primitives or Gatekeeper security semantics under these items without an explicit security review. Do **not** add Firebase/Gemini to the control plane. Do **not** claim formal security proofs.

## P0 — Remote Authorization Authority (design + stub interface)

**Goal:** Define the remote control-plane boundary that replaces the in-process browser Oracle for production.

- Publish Authority responsibilities: policy eval, challenge issue, one-time grant issue, wrap-secret release path, revoke/replay ownership
- Stub interface (types / API sketch) for remote grant issuance and verification that Gatekeeper can target later
- Document trust assumptions: durable state + HSM/KMS (or platform Secure Key Store); browser receives minimum material only
- Keep current browser Oracle as **reference/demo** only — no production Authority claims

**Exit criteria:** Reviewed design note + stub interface in-repo; PRODUCT/ARCHITECTURE/AUDIT language remain aligned.

## P1 — Durable revoke / replay

**Goal:** Revocation epochs and replay protection survive process restart and are owned by the Authority, not only in-memory browser state.

- Persist revoke/replay/challenge state on the Authority side of the interface
- Clarify client vs Authority responsibilities for View-Once and one-time grants
- Tests against the stub/fake Authority for revoke after share and replay rejection

**Exit criteria:** Durable semantics specified and testable against a non-browser Authority stub.

## P2 — Gatekeeper API for integrators

**Goal:** External apps integrate through a clear Gatekeeper surface (TS first).

- Document operation-scoped unlock API (READ / RENDER / EXTRACT / …)
- Stable error/audit hooks for integrators
- Position TypeScript as the product SDK path; keep `sdk/python` labeled demo

**Exit criteria:** Integrator-facing API doc + minimal TS usage examples without bypassing Gatekeeper.

## P3 — ATL Edge bridge (design note only)

**Goal:** Describe how agent runtimes (e.g. ATL Edge) unlock TDCP packages **only via Gatekeeper** — never by holding long-lived content keys in the agent.

- Design note only: trust model, grant scope for agents, revoke implications
- **Do not implement ATL Edge code in this repository**

**Exit criteria:** Short design note linked from PRODUCT.md; no ATL runtime dependency.

## P4 — UI polish / local demo auth

**Goal:** Improve local demo UX and auth shell without claiming production identity or IRM SaaS readiness.

- Clarify demo vs production auth in UI copy
- Polish reference flows (encrypt / authorize / unlock) for demos
- Explicitly avoid production IdP / HSM / compliance claims

**Exit criteria:** Demo path is clearer for evaluators; AUDIT non-claims unchanged.

## Explicitly deferred

- Full IRM SaaS parity (Seclore / Virtru / Digify feature race)
- Office plugin suite, email gateway, CASB marketplace listing
- Firebase / Gemini in the control plane
- Formal cryptographic proofs
