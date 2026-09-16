# TDCP roadmap

Product north star: **`PRODUCT.md`**. Architecture: **`ARCHITECTURE.md`**. Security honesty: **`AUDIT_2.5.1.md`**.

Do **not** change crypto primitives or Gatekeeper security semantics under these items without an explicit security review. Do **not** add Firebase/Gemini to the control plane. Do **not** claim formal security proofs.

## P0 — Remote Authorization Authority (design + stub interface) — **DONE (MVP)**

**Goal:** Define the remote control-plane boundary that replaces the in-process browser Oracle for production.

- [x] Publish Authority responsibilities: policy eval, challenge issue, one-time grant issue, wrap-secret release path, revoke/replay ownership (`docs/AUTHORITY.md`)
- [x] Stub interface (types / API) for remote grant issuance (`src/authority/`) that Gatekeeper can target
- [x] Document trust assumptions: durable state + HSM/KMS (or platform Secure Key Store); browser receives minimum material only
- [x] Keep current browser Oracle as **reference/demo** only — no production Authority claims for in-browser path
- [x] HTTP Authority service + `HttpAuthorityClient` + `TDCP_AUTHORITY_URL` wiring

**Exit criteria:** Reviewed design note + stub interface in-repo; PRODUCT/ARCHITECTURE/AUDIT language remain aligned.  
**Remaining:** Real HSM/KMS, authenticated admin APIs, independent security review.

## P1 — Durable revoke / replay — **DONE (file-backed MVP)**

**Goal:** Revocation epochs and replay protection survive process restart and are owned by the Authority, not only in-memory browser state.

- [x] Persist revoke/replay/challenge state on the Authority side (`server/authority/durable-store.ts`)
- [x] Clarify client vs Authority responsibilities for View-Once and one-time grants (`docs/AUTHORITY.md`)
- [x] Tests against durable Authority stub: revoke after restart, replay rejection, one-time wrap-secret release

**Exit criteria:** Durable semantics specified and testable against a non-browser Authority stub.  
**Remaining:** Production-grade storage (not gitignored JSON file), HA, backup SLOs.

## P2 — Gatekeeper API for integrators — **DONE (docs + SDK folder)**

**Goal:** External apps integrate through a clear Gatekeeper surface (TS first).

- [x] Document operation-scoped unlock API (`docs/INTEGRATOR_API.md`)
- [x] Stable error/audit hooks documented for integrators
- [x] TypeScript SDK path (`sdk/typescript/`) + `examples/unlock-via-gatekeeper.ts`; `sdk/python` remains labeled demo

**Exit criteria:** Integrator-facing API doc + minimal TS usage examples without bypassing Gatekeeper.

## P3 — ATL Edge bridge (design note only) — **DONE**

**Goal:** Describe how agent runtimes (e.g. ATL Edge) unlock TDCP packages **only via Gatekeeper** — never by holding long-lived content keys in the agent.

- [x] Design note: `docs/ATL_EDGE_BRIDGE.md`
- [x] **Do not implement ATL Edge code in this repository**

**Exit criteria:** Short design note linked from PRODUCT.md; no ATL runtime dependency.

## P4 — UI polish / local demo auth — **DONE (copy + badges)**

**Goal:** Improve local demo UX and auth shell without claiming production identity or IRM SaaS readiness.

- [x] Clarify demo vs production auth in UI copy / badges
- [x] Documented local account flow for evaluators (no crypto bypass)
- [x] Explicitly avoid production IdP / HSM / compliance claims

**Exit criteria:** Demo path is clearer for evaluators; AUDIT non-claims unchanged.

## Launch packaging (this foundation PR)

- [x] `docker-compose.yml` authority + web, healthchecks, volume
- [x] `scripts/start-prod-stack.sh`, updated `DEPLOY.md` / `.env.example`
- [x] `LAUNCH.md`, `docs/GTM.md`
- [x] CI template includes Authority tests (`docs/ci.github.yml`)

## Explicitly deferred

- Full IRM SaaS parity (Seclore / Virtru / Digify feature race)
- Office plugin suite, email gateway, CASB marketplace listing
- Firebase / Gemini in the control plane
- Formal cryptographic proofs
- Real HSM/KMS-backed Authority signing (stubs only today)
