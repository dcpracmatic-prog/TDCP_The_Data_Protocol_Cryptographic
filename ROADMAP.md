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

## P5 — Commercial hardening (this PR) — **DONE (honest MVP)**

**Goal:** Production-leaning Authority ops without fake HSM claims.

- [x] Admin Bearer auth for register/revoke (`TDCP_AUTHORITY_ADMIN_TOKEN`)
- [x] `/health`, `/ready`, `/metrics` + structured request logs (no secrets)
- [x] Ops runbook (`docs/OPS.md`), security review pack, commercial + landing docs
- [x] `TDCP_SIGNING_BACKEND=file|kms-stub` interface path (`signCanonical` hook)
- [x] Tests: 401 without token, success with token, KMS stub signing

**Exit criteria:** Admin auth + ops endpoints tested; docs honest about non-production file/kms-stub signing.  
**Remaining true blockers for paid launch:** real KMS/HSM, independent review, ToS/DPA, multi-tenant isolation, encrypted backups.


## P6 — Operational MVP (one-command stack + demo UX) — **DONE**

**Goal:** A stranger can start Authority + Web with one command, enter Encrypt/Decrypt/Monitor via demo gate, see Authority health, and run smoke.

- [x] `./scripts/start-mvp.sh` / `./scripts/stop-mvp.sh` + `.mvp/` pids/logs
- [x] Demo button «Continuar en modo demo (MVP)» (local session; no Firebase/Gemini)
- [x] Authority status banner + Connected/Offline chip; Monitor Ops strip (`/metrics`)
- [x] CORS on Authority for browser Gatekeeper path
- [x] `npm run smoke:mvp` — health/ready/register/authorize
- [x] README MVP Quickstart (EN+ES) + `MVP.md`

**Exit criteria:** Operational feel without false HSM claims.  
**Remaining for paid production:** real KMS/HSM, multi-tenant, ToS/DPA, independent review (see `MVP.md`).

## P7 — CSG + Smart Token free bridge (docs + client stub) — **DONE (MVP)**

**Goal:** Document and stub optional, self-hosted integration with Smart-Token-Prod (long-lived PQ + friction files) and CSG/Sello (integrity seals), without vendoring their trees or bypassing Gatekeeper.

- [x] Design note: `docs/CSG_SMART_TOKEN_BRIDGE.md` (trust planes, free deploy, patterns A/B, non-goals)
- [x] Minimal TypeScript client: `sdk/typescript/src/smart-token-client.ts` (fetch-only; master request-scoped)
- [x] Example: `examples/smart-token-bridge-example.ts`
- [x] PRODUCT / ARCHITECTURE / `.env.example` pointers; optional `SMART_TOKEN_API_URL` / `SMART_TOKEN_API_KEY`
- [x] **Do not** embed CSG Rust in Node; **do not** change Gatekeeper unlock semantics

**Exit criteria:** Integrators can self-host Smart Token API and call it after Gatekeeper authorization; CSG remains design-time / sidecar attestation.  
**Remaining:** Formal threat-model cross-reference.
**P2-5 (2026-11-11, DONE):** CSG seal wired into the `.pkg` itself — seal at protect (stored in `csgSeal`, covers the canonical envelope: structure + full content), verify in the Gatekeeper before decrypt/grant with fail-closed `CSG_PACKAGE_SEAL_FAILED`, legacy seal-less packages still open (no CSG guarantee), unit + Gatekeeper tests (`src/core/package/csg-package-seal.test.ts`, 13 tests) and real-sidecar smoke (`npm run smoke:csg-pkg`). See `docs/CSG_SMART_TOKEN_BRIDGE.md` § P2-5.

## P0-2 — External signing backend (KMS/HSM sidecar) — **DONE**

**Goal:** The Authority can sign grants with a real KMS/HSM without the key
ever entering its process, and without an AWS SDK dependency in the repo.

- [x] `OracleKeyStore` contract documented as the extension point (`src/oracle/oracle-key-store.ts`): what it promises, what it does not promise; non-exportable stores throw from `getOrCreateSigningKey()` instead of faking a private key
- [x] `TDCP_SIGNING_BACKEND=external` (`server/authority/external-signing-backend.ts`): HTTP sidecar (`TDCP_SIGNING_EXTERNAL_URL`) and/or local command (`TDCP_SIGNING_EXTERNAL_CMD`); fail closed on any signer failure, no silent fallback to `file`; unknown backend values refuse to start
- [x] Example AWS KMS sidecar (`examples/kms-signing-sidecar/`, fake mode + real KMS mode with DER→raw conversion, minimum IAM `kms:Sign` + `kms:GetPublicKey`) + local-command fake signer + deployment docs (`docs/AUTHORITY.md`, `.env.example`)
- [x] USB-HSM (`server/authority/usb-hsm.ts`) documented as user identity, not grant signing; two honest plug-in paths noted, none faked
- [x] Tests: fake sidecar end-to-end (sign + verify), fail-closed on dead signer, local-command signer, config validation

**Exit criteria:** `npm test` + `npm run typecheck` green; no AWS SDK in repo dependencies; no credential in the repo.  
**Remaining:** a real KMS/HSM deployment by the operator (key + IAM + sidecar host); key rotation is manual (no multi-key support yet); independent security review.

## P2-6 — Smart Token como custodio de la CEK — **DONE (con doble local)**

**Goal:** La CEK del documento queda custodiada por Smart Token (ML-KEM + contraseña maestra del emisor) y el descifrado controlado ocurre vía Gatekeeper sin exponer la CEK nunca en servidores externos.

- [x] Modo explícito `smart-token-custody` (`cekCustodyMode: 'smart-token'` en `createTDCPPackage`; default `oracle` sin cambios)
- [x] En este modo la CEK se entrega a Smart Token y el paquete NO contiene CEK envuelta por el Oracle (*en vez de*, no *además de*: documentado en `docs/CSG_SMART_TOKEN_BRIDGE.md` §C)
- [x] Gatekeeper sigue siendo el único camino: valida y consume el grant de un solo uso y solo entonces Smart Token libera la CEK para descifrar en local; sin grant, Smart Token ni se contacta
- [x] Falla cerrado: sin custodio, sin master, DENIED o servicio caído → denegado, sin fallback al Oracle
- [x] Cliente Smart Token existente reutilizado sin reescribir (`HttpSmartTokenCekCustodian` adaptador fino; sin endpoints inventados)
- [x] Tests: `src/protection/smart-token-cek-custody.test.ts` (11 tests: roundtrip, smoke, sin grant, master incorrecto, servicio caído, sin custodio/master, formato tamperado, regresión oracle, adaptador HTTP con fetch falso) + ejemplo smoke `examples/smart-token-cek-custody-example.ts`
- [x] Sin variables de entorno nuevas (`SMART_TOKEN_API_URL` / `SMART_TOKEN_API_KEY` ya existen; el master es por operación, nunca se guarda)

**Exit criteria:** Roundtrip proteger/abrir con custodia y denegación sin grant / con servicio caído, todo verificado en tests.  
**Remaining:** Smoke contra el servicio Smart Token REAL (requiere `api/` levantado; el contrato es el mismo ya verificado por el puente en 2026-11-11). Sin pruebas formales (deferred, como el resto del repo).

## Explicitly deferred

- Full IRM SaaS parity (Seclore / Virtru / Digify feature race)
- Office plugin suite, email gateway, CASB marketplace listing
- Firebase / Gemini in the control plane
- Formal cryptographic proofs
- Real HSM/KMS deployment in production (backend + KMS sidecar example shipped in P0-2; the operator still has to deploy a real key and pass independent review)
- Vendoring Smart-Token-Prod or CSG source into this repository
