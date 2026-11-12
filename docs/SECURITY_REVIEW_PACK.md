# Paquete de revisión de seguridad (TDCP Authority + Gatekeeper)

**Estado:** materiales para un revisor independiente. **Este documento NO es
una certificación, ni una atestación, ni una prueba formal. PREPARA la
auditoría; no la sustituye. Un auditor humano externo sigue siendo
necesario.**

**Foto de la arquitectura:** 2026-11-11, `main` tras P0-1 (PR #59), P0-2
(PR #54), P0-3 (PR #57), P2-5 (PR #58) y P2-6 (PR #55).
**Modelo de amenazas completo:** `docs/THREAT_MODEL.md`.
**Honestidad canónica:** `AUDIT_2.5.1.md`.
**Producto:** `PRODUCT.md`. **Diseño de la Authority:** `docs/AUTHORITY.md`.
**Puente CSG + Smart Token:** `docs/CSG_SMART_TOKEN_BRIDGE.md`.

> En simple: esto es la carpeta que se le entrega a un auditor externo para
> que revise TDCP por su cuenta. Dice qué hay, qué se revisa, qué no se
> afirma y cómo se comprueba. Si el auditor encuentra algo, eso es un éxito
> del paquete, no un fracaso.

## 1. Arquitectura que se revisa (verificada en este repo)

| Pieza | Qué es | Dónde vive en el repo |
|-------|--------|----------------------|
| Store Postgres de la Authority (P0-1) | El estado durable (políticas, wrap secrets, revocación, anti-replay, challenges) vive en Postgres en vez de un JSON; `TDCP_AUTHORITY_STORE=postgres\|file`; `/ready` incluye `storeKind` | `server/authority/postgres-store.ts`, `migrations/0005_authority_store.sql` (9 tablas `authority_*`, RLS sin políticas) |
| Firma externa KMS/HSM (P0-2) | Interfaz `OracleKeyStore` + backend `external` (sidecar HTTP y/o comando local); falla cerrado sin fallback a `file`; ejemplo de sidecar AWS KMS | `server/authority/external-signing-backend.ts`, `src/oracle/oracle-key-store.ts`, `examples/kms-signing-sidecar/` |
| Guardia fail-fast (P0-3) | En producción la app falla al arrancar sin `DATABASE_URL` en vez de caer en silencio a PGLite; `GET /api/db-status` dice qué base sirve, sin secretos | `src/lib/db.ts`, `server/routes/api/db-status.get.ts` |
| Sello CSG en el `.pkg` (P2-5) | El paquete lleva su sello dentro (`csgSeal`); el Gatekeeper lo verifica antes de descifrar y antes de gastar el grant; falla cerrado si el contenido cambió | `src/core/package/csg-package-seal.ts`, `src/core/package/package-format.ts` |
| Custodia Smart Token de la CEK (P2-6) | Modo `smart-token-custody`: la CEK la custodia Smart Token (ML-KEM + contraseña maestra del emisor) y solo se libera tras un grant válido; el paquete NO contiene CEK envuelta por el Oracle | `src/protection/smart-token-cek-custody.ts`, `docs/CSG_SMART_TOKEN_BRIDGE.md` §C |
| Cuentas y sesiones | Better Auth sobre Supabase (proyecto `tdcp`; 7 tablas, RLS sin políticas, rol `tdcp_app` dueño) | `migrations/0001–0004`, `docs/CUENTAS_SUPABASE.md` |
| Servicio Authority HTTP | Endpoints de challenge, authorize, grant de un solo uso, liberación de wrap-secret, revocación, `/health`, `/ready`, `/metrics` | `server/authority/` |

## 2. Activos: qué se protege

- **Paquetes `.pkg`** (ciphertext AES-256-GCM + metadata + política). Copiarlos
  no da acceso: la autorización vive en la Authority, no en el archivo.
- **CEK** (llave de contenido, 32 bytes). Solo en memoria del proceso que
  descifra; en modo `smart-token` no vive en el paquete ni en ningún servidor
  TDCP.
- **Secreto de wrap del Oracle** (factor HKDF por documento). Sin él, la
  contraseña sola no reconstruye la CEK en modo `oracle`.
- **Llaves de firma de grants** (ECDSA P-256). Quien las tiene firma grants
  falsos: es el activo más sensible de la Authority.
- **Cuentas y sesiones** (Better Auth / Supabase). Una sesión robada actúa
  como ese usuario en la app, pero no abre paquetes sin grant válido.
- **Ledger de auditoría** (revocaciones, grants consumidos, operaciones).
  Las claves primarias hacen colisionar el re-uso en la capa de
  almacenamiento.
- **Sellos CSG** (`csgSeal`): atestación de integridad del paquete por un
  tercero (Notario). No sustituyen al tag AES-GCM ni al grant.

Detalle por activo, amenaza y riesgo residual: `docs/THREAT_MODEL.md` §1 y §4.

## 3. Fronteras de confianza

```
[ Navegador / cliente / Gatekeeper ]   <-- NO es frontera: un navegador
        |  pide challenge, grant y wrap-secret;     comprometido puede ver
        |  verifica grants con la llave PÚBLICA      lo que el usuario ve
        v
[ Authority remota ]  <-- frontera principal: decide, firma, guarda
        +-- [ Postgres (Supabase) ]  estado durable; la Data API no lee nada
        +-- [ Backend de firma ]     file (dev) | external (KMS/HSM real)
        +-- [ Sidecar CSG ]          sella / verifica; no cifra ni autoriza
        +-- [ Smart Token ]          custodia la CEK (modo smart-token)
[ Vercel ]  sirve la app; NO guarda secretos de la Authority
[ Supabase Auth ]  cuentas/sesiones; NO autoriza paquetes
```

**Qué NO debe confiar en qué:**

- El navegador comprometido no es frontera; el camino de producción es la
  Authority remota, no el Oracle en proceso (que es solo referencia/demo).
- La Data API de Supabase no lee nada por RLS sin políticas; solo la
  conexión del servidor (dueño de las tablas) lee y escribe.
- El sidecar CSG no sustituye a AES-GCM ni al grant: solo atesta integridad.
- Smart Token no sustituye a la Authority: sin grant válido ni se lo contacta.
- El backend `file` no es HSM: una firma con JWK extraíble no es custodia
  de producción.

Modelo completo con tabla de confianzas: `docs/THREAT_MODEL.md` §3.

## 4. Alcance de la revisión

### Dentro de alcance (incluye)

1. Servicio HTTP de la Authority (`server/authority/`) y su cliente
   (`src/authority/`).
2. Store durable Postgres (P0-1): esquema, transacciones, RLS, secretos en
   reposo, `save()` de snapshot completo, topes de retención.
3. Interfaz `OracleKeyStore` y backend `external` (P0-2): contrato, fallo
   cerrado, ejemplo de sidecar KMS, freno honesto `ATTESTED`.
4. Guardia fail-fast y `GET /api/db-status` (P0-3).
5. Sello CSG en el `.pkg` (P2-5): bytes canónicos cubiertos, modos
   required/optional/off, reglas de fallo, paquetes legacy sin sello.
6. Custodia Smart Token de la CEK (P2-6): "en vez de, no además de",
   liberación solo tras grant, fallo cerrado, master por operación.
7. Camino de desbloqueo del Gatekeeper (el cliente no debe poder saltarse
   el Oracle / la Authority).
8. Verificación de grants de un solo uso, anti-replay, revocación por épocas,
   view-once.
9. Auth de admin (Bearer, OIDC, mTLS) y rate limits públicos.
10. Logs: que no filtren secretos ni en los caminos de error.

### Fuera de alcance (excluye)

- El SDK de AWS y el servicio KMS en sí; los servicios Smart Token y CSG en
  sí (su criptografía interna): solo su contrato con TDCP.
- La infraestructura de Vercel y Supabase como tal.
- El IRM SaaS completo (plugins, email gateway, CASB), multi-tenant
  alojado, backups cifrados y SLO.
- Firebase / Gemini en el plano de control (explícitamente prohibido).
- Pruebas formales de los protocolos y certificaciones de cumplimiento.
- El Oracle en el navegador como frontera de producción.

## 5. Qué NO se afirma

No afirmar, ni en este paquete ni en material comercial:

- Pruebas formales de seguridad ni certificación Common Criteria / FIPS /
  SOC 2 a partir de este repo.
- Custodia HSM/KMS de producción con `TDCP_SIGNING_BACKEND=file` o con un
  firmador `fake`: solo es apto con `external` +
  `TDCP_SIGNING_EXTERNAL_ATTESTED=true` y un KMS/HSM real detrás.
- Que el Oracle en el navegador sea una autoridad remota, un TPM o un HSM.
- Paridad de funciones con Virtru / Seclore / Digify.
- Que el rate limit en memoria sustituya un WAF / gateway en el borde.
- Que el sello CSG o la custodia Smart Token sustituyan a la Authority: son
  planos aditivos, no un segundo plano de control.

## 6. Estado honesto del despliegue (a 2026-11-11)

El despliegue de Vercel **todavía no usa Supabase en Production**: tras un
login exitoso, Supabase sigue con 0 usuarios/perfiles/sesiones; las cuentas
viven en el PGLite temporal del despliegue viejo y se pierden al reciclarse.
No es un fallo del repo: falta el redeploy con las variables en Production
(pendiente de Arturo). La guardia P0-3 impide que un despliegue nuevo caiga
en el mismo silencio, y `GET /api/db-status` debe decir
`backend: "postgres", ready: true` tras ese redeploy. El auditor debe
verificarlo en vivo, no darlo por hecho.

## 7. Evidencia de tests (medida en este clon, 2026-11-11)

| Comprobación | Resultado medido | Cómo reproducir |
|--------------|------------------|-----------------|
| Suite completa | **192 tests, 46 suites, 192 pass, 0 fail** | `npm install && npm test` |
| Typecheck | **limpio, exit 0** | `npm run typecheck` |
| CSG sello en paquete | 13 tests (`src/core/package/csg-package-seal.test.ts`) | `npm test` (incluidos) |
| Custodia Smart Token | 11 tests (`src/protection/smart-token-cek-custody.test.ts`) | `npm test` (incluidos) |
| Store Postgres | `src/authority/postgres-store.test.ts` contra PGLite embebido (mismo SQL); Supabase real verificado por la API de Management, no por conexión directa (el sandbox bloquea el puerto 5432) | `npm test`; ver `docs/OPS.md` |
| Smoke sello CSG (sidecar local) | `npm run smoke:csg-pkg` (sidecar local en-repo; altera 1 byte → denegado) | Requiere `python3` + paquete `cryptography` |
| Análisis estático | Workflows Bearer, CodeQL y Codacy en `.github/workflows/` + CI en `ci.yml` | Ver runs de CI del PR en GitHub |

> Los números de arriba son los medidos en el clon de trabajo de P0-4
> antes de abrir el PR. El CI del PR debe volver a darlos en verde; si un
> número cambia, el cambio se explica en el PR, no se edita el número.

## 8. Alcance concreto para el auditor externo

### Qué revisar (archivo por archivo / componente por componente)

| # | Componente | Archivos | Pregunta principal |
|---|-----------|----------|-------------------|
| 1 | Store Postgres | `server/authority/postgres-store.ts`, `migrations/0005_authority_store.sql`, `server/authority/durable-store.ts` | ¿El estado durable impide re-uso y pérdida de revocación? ¿RLS de verdad bloquea la Data API? |
| 2 | Servicio Authority | `server/authority/service.ts`, `http-server.ts`, `index.ts` | ¿Grant de un solo uso, anti-replay, épocas y view-once se cumplen en todos los caminos, incluidos los de error? |
| 3 | Firma externa | `server/authority/external-signing-backend.ts`, `signing-backend.ts`, `src/oracle/oracle-key-store.ts`, `examples/kms-signing-sidecar/` | ¿Sin firmador no hay firma? ¿Sin `ATTESTED=true` no se presenta como producción? ¿IAM mínimo real? |
| 4 | Guardia fail-fast | `src/lib/db.ts`, `server/routes/api/db-status.get.ts` | ¿Producción sin `DATABASE_URL` falla al arrancar? ¿`/api/db-status` filtra algún secreto? |
| 5 | Sello CSG | `src/core/package/csg-package-seal.ts`, `package-format.ts`, `src/protection/csg-client.ts`, `server/csg-sidecar/main.py` | ¿El sello cubre sobre + contenido completo? ¿Alterar 1 byte deniega antes de gastar el grant? |
| 6 | Custodia Smart Token | `src/protection/smart-token-cek-custody.ts`, `src/core/package/tdcp-factory.ts`, `src/gatekeeper/gatekeeper.ts` | ¿El paquete en este modo no contiene CEK del Oracle? ¿Sin grant no hay llamada al custodio? |
| 7 | Gatekeeper | `src/gatekeeper/gatekeeper.ts`, `src/runtime/tdcp-runtime.ts` | ¿Hay algún camino que descifre sin pasar por el Gatekeeper? |
| 8 | Cuentas y admin | `server/authority/admin-auth.ts`, `user-auth.ts`, `docs/ADMIN_AUTH.md`, `migrations/0001–0004` | ¿Bearer desactivado en modos OIDC/mTLS? ¿Token admin fuera del bundle web en producción? |
| 9 | Logs y secretos | `server/authority/request-log.ts`, `metrics.ts`, `rate-limit.ts` | ¿Algún log, error o métrica filtra secretos? |
| 10 | Formato `.pkg` | `src/core/package/package-format.ts`, `tdcp-factory.ts` | ¿La validación rechaza versiones, algoritmos, KDF e IV/salt fuera de rango? |

### Artefactos que se entregan al auditor

- Este paquete + `docs/THREAT_MODEL.md` + `AUDIT_2.5.1.md` + `ROADMAP.md`
  (P0-1, P0-2, P0-3, P2-5, P2-6).
- `docs/AUTHORITY.md`, `docs/CSG_SMART_TOKEN_BRIDGE.md`, `docs/OPS.md`,
  `docs/ADMIN_AUTH.md`, `docs/CUENTAS_SUPABASE.md`.
- El diff del PR de esta pieza contra `main`.
- Salida de `npm test` (192 tests) y `npm run typecheck` (limpio), y el run
  de CI en verde del PR.
- Acceso de lectura al repo y, si lo pide, un despliegue de prueba con
  `GET /api/db-status` y `GET /ready` visibles.
- Los sidecars de ejemplo (`examples/kms-signing-sidecar/`,
  `server/csg-sidecar/main.py`) para reproducir los smokes.

### Criterios de aceptación (la revisión se da por pasada cuando…)

1. Cada fila de la tabla de arriba tiene un veredicto escrito (pasa / pasa
   con observaciones / falla) con la evidencia (archivo, línea, prueba o
   comando reproducido).
2. Los 7 supuestos de `docs/THREAT_MODEL.md` §6 están verificados o rotos
   por escrito; un supuesto roto es un hallazgo, no un silencio.
3. No queda ninguna afirmación de la §5 sin tachar o confirmar.
4. Los hallazgos tienen severidad (crítico / alto / medio / bajo) y se
   registran en el checklist de seguridad de `LAUNCH.md`.
5. El despliegue de Vercel se verifica en vivo (`/api/db-status` dice
   `postgres` y `ready: true`) o queda como hallazgo abierto con dueño y
   fecha, no como supuesto.
6. Ningún hallazgo crítico o alto queda sin plan de corrección antes de
   cualquier tier de pago.

## 9. Preguntas abiertas para el revisor

1. ¿El Bearer de admin es aceptable para Starter, o se exige mTLS / OAuth
   antes de cualquier tier de pago?
2. ¿El wrap-secret debe cifrarse en reposo con envelope KMS antes de la GA
   de Starter?
3. ¿Modelo de aislamiento multi-tenant para una Authority alojada
   (namespace vs proceso vs clúster)?
4. ¿RPO/RTO y estándar de cifrado de backups aceptables para los wrap
   secrets de clientes?
5. ¿Debe `GET /v1/documents/:id/policy` seguir siendo público o pasar
   detrás de grant/auth?
6. ¿Qué controles de rate limit / abuso van en la Authority y cuáles en el
   gateway?
7. Firma: ¿AWS KMS con Sign asimétrico o CloudHSM para el primer backend
   de producción?
8. ¿Alguna suposición del cliente Gatekeeper debilita la confianza en la
   Authority remota?

## 10. Contacto / proceso

Asignar revisor, compartir este paquete + `AUDIT_2.5.1.md` +
`docs/THREAT_MODEL.md` + el diff del PR. Registrar hallazgos en el
checklist de seguridad de `LAUNCH.md`. **No** vender "certificado" con
este paquete solo.
