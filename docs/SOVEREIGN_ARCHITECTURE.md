# Arquitectura soberana — directiva

Directiva inquebrantable de Arturo: **este repo no depende de ningún
servicio real, externo o de otro despliegue, ni de ninguna credencial
real, para probar, validar o arrancar en local.** Todo lo que el repo
necesita para sus tests vive en el repo (dobles locales, loopback y
valores efímeros generados al vuelo). Lo que pertenece al operador —
sus despliegues, sus llaves — llega solo por entorno y, si falta, el
sistema falla cerrado. Esta directiva se cumple, no se discute.

## Las dos reglas

### Regla 1 — Ningún test, smoke o validación en-repo depende de un servicio real ni de credenciales reales

- Los tests y smokes corren solo contra dobles locales (la fake Smart
  Token en `test/fake-smart-token/`, el sidecar CSG Python en-repo en
  `127.0.0.1:8019`, PGLite embebido) o contra servicios levantados en
  loopback por el propio test, con llaves y contraseñas efímeras
  generadas al vuelo dentro del proceso de test.
- Nunca se lee en un test una variable de credenciales reales para
  contactar un despliegue externo. Un test que borra la variable para
  probar el camino fail-closed (p. ej. `smart-token-cek-custody.test.ts`,
  que hace `delete process.env.SMART_TOKEN_API_URL/KEY`) sí es legítimo:
  no usa la credencial, prueba su ausencia.
- No existe ningún smoke contra un servicio externo. El smoke canónico
  de punta a punta es `npm run smoke:viewer-e2e` (visor offline contra
  la fake local, también dentro de `npm test`).

### Regla 2 — Ningún secreto fijo ni default de credencial en el repo

- No hay tokens, llaves ni contraseñas hardcodeadas, ni siquiera como
  "default solo para dev". Un default conocido es un secreto fijo.
- Los tokens de arranque local se generan por corrida
  (`openssl rand -hex 32`, patrón ya usado en `scripts/start-mvp.sh`)
  o los exporta el operador. Nunca se imprimen.
- Sin configuración, el sistema falla cerrado y con un error claro:
  la Authority responde `503 ADMIN_TOKEN_NOT_CONFIGURED` sin token
  (`server/authority/admin-auth.ts`), la app no arranca en producción
  sin `DATABASE_URL` (`src/lib/db.ts`), y el CLI del visor no genera
  nada sin custodio (`src/viewer/offline-viewer-cli.ts`).
- Los secretos del operador (GitHub secrets, llaves de Vercel, etc.)
  son del operador: el repo no los inyecta en CI ni los lee en tests.

## Qué está prohibido (ejemplos reales, corregidos en esta auditoría)

| # | Lo prohibido | Dónde estaba | Corrección |
|---|---|---|---|
| H1 | "Smoke contra el servicio Smart Token REAL" como trabajo pendiente | `ROADMAP.md:161` | Línea borrada; el smoke canónico es `npm run smoke:viewer-e2e` contra la fake |
| H2 | "Pendiente: smoke contra el servicio Smart Token REAL" | `docs/CSG_SMART_TOKEN_BRIDGE.md:164` | Sustituido por la referencia al smoke e2e contra la fake (`docs/OFFLINE_VIEWER.md`) |
| H3 | Hosts reales de servicios en la validación (`https://tdcp.onrender.com`, `https://smart-token-prod.onrender.com`) | `docs/PRELAUNCH_VALIDATION.md:3-5, 10-12, 20` | Reescrito con variables `$TDCP_SITE_URL`, `$TDCP_AUTHORITY_URL`, `$SMART_TOKEN_API_URL` del despliegue propio del operador; la validación en-repo es contra fake/local |
| H4 | Default hardcodeado para `TDCP_AUTHORITY_ADMIN_TOKEN` (y su espejo `VITE_TDCP_AUTHORITY_ADMIN_TOKEN`) | `docker-compose.yml:18, 69, 70`, `scripts/start-prod-stack.sh:13` | Generación por corrida (`openssl rand -hex 32`, con fallback a `node:crypto`); compose exige la variable con fail-closed (`${VAR:?…}`) si no viene del script |
| H4-extra | El mismo default como fallback silencioso del smoke | `scripts/smoke-mvp.mjs:25` (hallazgo extra al aplicar H4) | Sin token (ni env ni `.mvp/admin-token`) el smoke falla cerrado con mensaje claro, exit 1 |
| H5 | `MASTER_KEY_HEX: ${{ secrets.MASTER_KEY_HEX }}` inyectado como env en el paso `npm test` de CI, sin que ningún archivo del repo lo lea | `.github/workflows/ci.yml:38` | Inyección eliminada del workflow. El secreto en GitHub no se tocó (es del operador); la suite completa pasa sin él |
| H6 | "Copiar la misma key a Vercel como `VITE_SMART_TOKEN_API_KEY`" (ambiguo: ¿qué key?) | `docs/SMART_TOKEN_INTEGRATION.md:40` | Aclarado: la key del despliegue propio autoalojado del operador, nunca una key personal o de producción de otro despliegue |
| H7 | "Smoke manual contra el sidecar real" (el sidecar es el Python en-repo en loopback, no un servicio de producción) | `docs/OFFLINE_VIEWER.md:147` | Renombrado a "sidecar local"; misma aclaración en `docs/CSG_SMART_TOKEN_BRIDGE.md:228` y `docs/SECURITY_REVIEW_PACK.md:150` |
| Menor | `docs/ci.github.yml`, copia vieja de `ci.yml` solo como documentación, divergente del workflow real | `docs/ci.github.yml` | Borrada; las dos referencias (`DEPLOY.md`, `ROADMAP.md`) apuntan ahora a `.github/workflows/ci.yml` |

## Qué es configuración desacoplada legítima (no se toca)

Esto ya estaba bien y se queda como está:

- `src/viewer/offline-viewer-cli.ts` y `src/viewer/offline-viewer.ts`:
  custodio solo por entorno, fail-closed sin él.
- `src/protection/smart-token-cek-custody.ts`:
  `smartTokenCekCustodianFromEnv`, doble en memoria solo para tests.
- `sdk/typescript/src/smart-token-client.ts`:
  `smartTokenClientFromEnv`, `null` sin URL.
- `src/lib/db.ts` y `scripts/migrate.mjs`: fail-fast en producción sin
  `DATABASE_URL` (PGLite solo en local/dev).
- `scripts/start-sidecars.sh` y `scripts/start-mvp.sh`: generación de
  token por corrida (patrón que ahora sigue `start-prod-stack.sh`).
- `test/fake-smart-token/*`: la fake es el doble local canónico; sus
  llaves y masters son valores de test que solo existen dentro del
  proceso de test.
- `examples/kms-signing-sidecar/`: modo default `fake`; el modo KMS
  exige `AWS_KMS_KEY_ID` por entorno.
- `docs/DEPLOY.md` y `docs/CUENTAS_SUPABASE.md`: documentan el
  despliegue propio del operador (sus URLs, sus variables); eso es
  configuración del operador, no un acoplamiento de los tests.

La línea es simple: **configurar el despliegue propio por entorno es
legítimo; que un test, un smoke o un default del repo necesite algo
externo o real, no.**

## Cómo se prueba

1. **Guarda contra regresiones** — `scripts/check-sovereign-architecture.mjs`,
   sin dependencias nuevas. Corre al inicio de `npm test` (y con
   `npm run check:sovereign`). Falla (exit 1) si encuentra en el árbol:
   hosts reales de servicios (`onrender.com`), el default hardcodeado,
   `MASTER_KEY_HEX`, referencias a un smoke contra el servicio real,
   "sidecar real", o tests que lean variables de credenciales reales
   (`SMART_TOKEN_API_URL/KEY`, `MASTER_KEY_HEX`) sin el patrón
   fail-closed (`delete process.env.…`). Excluye este documento (que
   cita los patrones prohibidos como ejemplos), la propia guarda, y
   líneas marcadas explícitamente como sintéticas con
   `SOVEREIGN-GUARD-ALLOW: <motivo>`. Sus pruebas están en
   `scripts/check-sovereign-architecture.test.mjs` (corren con
   `npm run test:scripts`): verifican que detecta cada patrón plantado
   en un árbol temporal y que no dispara sobre el árbol limpio.
2. **Suite completa en entorno limpio** — `npm test` y
   `npm run smoke:viewer-e2e` deben pasar sin `SMART_TOKEN_API_URL/KEY`
   reales, sin `DATABASE_URL` real y sin `MASTER_KEY_HEX` configuradas.
   Si un test necesita algo de eso para pasar, el test está mal, no el
   entorno.
3. **Grep final** — tras cada cambio de este tipo, `grep -rn` de los
   patrones prohibidos sobre todo el árbol debe dar vacío (salvo este
   documento y la guarda).
