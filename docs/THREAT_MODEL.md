# Modelo de amenazas — TDCP (Authority + Gatekeeper)

**Estado:** documento de trabajo para la revisión de seguridad independiente
(P0-4). **No es una certificación, ni una prueba formal, ni una garantía de
que no existan fallos.** Prepara la auditoría; no la sustituye. Un auditor
humano externo sigue siendo necesario.

**Fecha de la foto:** 2026-11-11, sobre `main` tras fusionar P0-1 (PR #59),
P0-2 (PR #54), P0-3 (PR #57), P2-5 (PR #58) y P2-6 (PR #55).
**Paquete de revisión:** `docs/SECURITY_REVIEW_PACK.md` (este documento es su
anexo técnico). **Honestidad canónica:** `AUDIT_2.5.1.md`.
**Diseño de la Authority:** `docs/AUTHORITY.md`.
**Puente CSG + Smart Token:** `docs/CSG_SMART_TOKEN_BRIDGE.md`.

> En simple: este documento dice qué se protege, de quién, con qué piezas, y
> qué queda sin proteger. Si algo de aquí no es verdad, la revisión debe
> encontrarlo antes que un atacante.

## 1. Qué se protege (activos)

| Activo | Dónde vive | Qué pasa si se pierde o se roba |
|--------|-----------|---------------------------------|
| Paquetes `.pkg` (ciphertext AES-256-GCM + metadata + política) | Almacén neutro (Drive / disco / blob) | El ciphertext solo no abre nada: copiarlo no copia la autorización. Pero un paquete robado puede intentarse abrir para siempre; la defensa es la Authority, no el secreto del archivo |
| CEK (llave de contenido, 32 bytes) | Solo en memoria del proceso que descifra; nunca en el paquete en modo `smart-token-custody` | Quien la tiene descifra el documento. En modo `oracle` vive envuelta por el Oracle dentro del paquete; en modo `smart-token` vive custodiada por Smart Token |
| Secreto de wrap del Oracle (factor HKDF por documento) | Authority (Postgres `authority_wrap_secrets` o archivo `data/authority/`) | Con el secreto de wrap + la contraseña del usuario se reconstruye la CEK en modo `oracle`. Robarlo no basta solo, pero es la mitad del secreto |
| Llaves de firma de grants (ECDSA P-256) | Backend de firma: archivo JWK (`file`), o KMS/HSM real detrás del backend `external` | Quien firma grants falsos autoriza aperturas. Es el activo más sensible de la Authority |
| Cuentas y sesiones (Better Auth sobre Supabase) | Supabase proyecto `tdcp` (7 tablas, RLS sin políticas, rol `tdcp_app` dueño) | Una sesión robada actúa como ese usuario en la app web; no da acceso a paquetes sin grant válido |
| Ledger de auditoría (revocaciones, grants consumidos, operaciones) | Authority (Postgres `authority_*` o archivo) + logs estructurados | Si se altera, una revocación podría "desaparecer" o un grant consumido podría reutilizarse. Por eso las claves primarias hacen colisionar el re-uso en la capa de almacenamiento |
| Sellos CSG (`csgSeal` dentro del `.pkg`) | Dentro del paquete + Notario CSG (sidecar) | Un sello falso o ausente no abre el paquete por sí solo; pero sin sello no hay garantía de integridad de terceros: solo quedan `integrityHash` (SHA-256 sin clave, recalculable por cualquiera) y el tag AES-GCM |
| Contraseña maestra del emisor (modo `smart-token-custody`) | Solo en la cabeza / gestor del emisor; se entrega por operación, nunca se guarda | Si se pierde, el documento NO se recupera. Si se roba + hay grant válido, abre |
| Token admin de la Authority (`TDCP_AUTHORITY_ADMIN_TOKEN`) | Entorno del operador | Quien lo tiene registra políticas y revoca/restaura documentos |

## 2. De quién nos defendemos (modelo de atacante)

Se asume que el atacante **puede**:

- Copiar cualquier `.pkg` (el almacén es neutro y no se confía en él).
- Leer el tráfico y reenviar mensajes viejos (replay).
- Intentar abrir un paquete revocado, con un grant ya usado o con un
  challenge viejo.
- Alterar bytes del paquete y recalcular `integrityHash` (es SHA-256 sin
  clave: cualquiera puede recalcularlo).
- Inundar los endpoints públicos de la Authority (challenge / authorize).
- Robar una sesión web o engañar a un usuario para que abra un paquete.

Se asume que el atacante **no puede** (supuestos que el auditor debe
cuestionar):

- Leer la memoria del proceso que descifra en local (si lo logra, ve la CEK
  en claro en ambos modos de custodia).
- Romper AES-256-GCM, ECDSA P-256, SHA-256/SHA3-256, Ed25519, ML-KEM-768 o
  PBKDF2-HMAC-SHA-256 con 600.000 iteraciones.
- Leer las tablas de Supabase por la Data API: RLS está activado **sin
  políticas**, así que la Data API no ve nada; solo la conexión del servidor
  (dueño de las tablas) lee y escribe.
- Sacar la llave privada de un KMS/HSM real (las llaves no exportables no
  salen del KMS; el sidecar solo pide firmas).

**No se defiende contra:** un navegador totalmente comprometido en el camino
del Oracle en proceso (ese camino es solo referencia/demo); un operador
malicioso con acceso total al servidor de la Authority; la pérdida de la
contraseña maestra del emisor; ni contra fallos dentro de los servicios
Smart Token / CSG / AWS KMS en sí (solo se revisa su contrato con TDCP).

## 3. Fronteras de confianza

```
[ Navegador / cliente / Gatekeeper ]   <-- NO es frontera de confianza:
        |  pide challenge, grant y wrap-secret;      un navegador comprometido
        |  verifica grants con la llave PÚBLICA       puede ver lo que el
        v  nunca recibe llaves privadas               usuario ve
[ Authority remota ]  <-- frontera principal:
        |  decide política, firma grants (un solo uso),
        |  guarda wrap secrets, revocación y anti-replay
        +-- [ Postgres (Supabase) ]  estado durable; Data API no lee nada
        +-- [ Backend de firma ]     file (dev) | external (KMS/HSM real)
        |  -- [ Sidecar CSG ]        sella / verifica integridad (no cifra)
        |  -- [ Smart Token ]        custodia la CEK (modo smart-token)
        v
[ Vercel (app web) ]  sirve la app; NO guarda secretos de la Authority
[ Supabase Auth ]     cuentas/sesiones; NO autoriza paquetes
```

**Qué confía en qué (y qué NO debe confiar):**

| Relación | Confianza |
|----------|-----------|
| Gatekeeper → Authority | Confía en su llave pública para verificar grants; NO confía en el almacén de paquetes ni en el navegador |
| Authority → Postgres | Confía en que las filas durables no se duplican (claves primarias) y en que solo el servidor las lee (RLS sin políticas); NO confía en la Data API de Supabase |
| Authority → backend `external` | Confía en que el firmador firma solo lo que se le pide y no filtra la llave; si el firmador no responde, NO se firma nada (falla cerrada, sin fallback a `file`) |
| Gatekeeper → sidecar CSG | Confía en el sello solo como atestación de integridad de un tercero; el sello NO sustituye al tag AES-GCM ni al grant |
| Gatekeeper → Smart Token | Confía en que libera la CEK solo con master correcto; NO lo contacta sin un grant válido previo |
| App web → Supabase | Confía en Better Auth para cuentas/sesiones; las cuentas NO autorizan paquetes por sí solas |
| Nadie → navegador comprometido | No es frontera: si el navegador está comprometido, el camino del Oracle en proceso no protege nada; el camino de producción es la Authority remota |

## 4. Amenazas por componente

### 4.1 Paquete `.pkg` y Gatekeeper

| Amenaza | Defensa actual | Riesgo que queda |
|---------|---------------|------------------|
| Copiar el `.pkg` y abrirlo en otro lado | Copia ≠ autorización: sin grant de la Authority no hay CEK | Ninguno por copia sola |
| Alterar el ciphertext y recalcular `integrityHash` | Tag AES-GCM (falla `DECRYPTION_AUTH_TAG_FAILED`); sello CSG verificado ANTES de descifrar y ANTES de gastar el grant | Paquetes legacy sin sello: solo los protege el tag GCM, no hay atestación de terceros |
| Reusar un grant de un solo uso | Registro de grants consumidos (durable; colisión por clave primaria en Postgres) | Ventana de carrera si dos Authority escriben a la vez sin la misma base (un solo nodo por diseño) |
| Reusar un challenge para minar varios grants | El challenge se consume al emitir el grant (`operationId + challenge`) | Ninguno conocido en el diseño actual |
| Abrir un documento revocado | Épocas de revocación en la Authority; el Gatekeeper consulta la época | La revocación solo vale dentro de esa Authority (un nodo) |
| Saltarse el Gatekeeper e ir directo al descifrado | La CEK solo se reconstruye con wrap-secret (Authority) o custodia (Smart Token) tras grant | En modo `oracle`, quien tenga contraseña + wrap-secret robado no necesita grant: por eso el wrap-secret es activo protegido |
| Ver la CEK en memoria | Se borra el buffer tras importarla como clave AES-GCM | Un proceso descifrador comprometido la ve igual (supuesto del §2) |

### 4.2 Authority remota y store Postgres (P0-1)

| Amenaza | Defensa actual | Riesgo que queda |
|---------|---------------|------------------|
| Perder revocación/replay al reiniciar | Estado durable en Postgres (9 tablas `authority_*`) o archivo atómico | El archivo es un solo nodo sin HA ni backup cifrado definido |
| Caer en silencio al store de archivo en producción | `TDCP_AUTHORITY_STORE=postgres` sin `DATABASE_URL` falla al arrancar; valores inválidos también | Ninguno en el arranque; el operador debe poner `postgres` en producción |
| Leer el estado por la Data API de Supabase | RLS activado sin políticas en las 9 tablas | Si alguien crea una política por error, la Data API podría leer; revisar en auditoría |
| Llave de firma en claro en la base | Igual que el archivo: en claro solo en dev; blob AES-256-GCM con `TDCP_AUTHORITY_KEY_PASSPHRASE` | Sigue sin ser HSM: la passphrase vive en el entorno del servidor |
| Abuso de endpoints públicos | Rate limit en memoria en challenge/authorize | Por proceso: no sustituye WAF / gateway en el borde |

### 4.3 Firma externa / KMS (P0-2)

| Amenaza | Defensa actual | Riesgo que queda |
|---------|---------------|------------------|
| Robo de la llave de firma del archivo JWK | Backend `file` documentado como NO producción; `external` no mete la llave en el proceso | `file` sigue siendo el default: un despliegue sin configurar `external` firma con JWK extraíble |
| Firmador caído o malicioso | Falla cerrada: sin firma no hay grant; sin fallback silencioso a `file` | Disponibilidad: si el KMS cae, nadie abre nada (es el precio del fallo cerrado) |
| Creer que hay KMS real cuando hay un firmador falso | `TDCP_SIGNING_EXTERNAL_ATTESTED=true` solo lo pone el operador con un KMS real; sin él `/ready` y `/v1/public-key` reportan `developmentOnly: true` | El freno es una variable de entorno: un operador puede mentir poniéndola en `true` con un firmador falso |
| Permisos de más en IAM | Mínimo documentado: solo `kms:Sign` + `kms:GetPublicKey` sobre esa llave | El auditor debe verificar la política IAM real del despliegue |

### 4.4 Guardia fail-fast y despliegue Vercel (P0-3)

| Amenaza | Defensa actual | Riesgo que queda |
|---------|---------------|------------------|
| Producción en silencio con PGLite (cuentas que se pierden al reciclar) | En producción (`VERCEL_ENV=production`, o `NODE_ENV=production` con `VERCEL=1`) la app falla al arrancar sin `DATABASE_URL` | La guardia solo cubre el arranque: no arregla despliegues viejos |
| No saber qué base sirve un despliegue | `GET /api/db-status` devuelve backend (`postgres` / `pglite`), `production` y `ready`, sin secretos | El endpoint es público por diseño: solo dice qué base hay, no datos |

**Estado honesto a 2026-11-11:** el despliegue de Vercel todavía NO usa
Supabase en Production (login exitoso, pero 0 usuarios/perfiles/sesiones en
Supabase tras el login: las cuentas viven en el PGLite temporal del
despliegue viejo y se pierden al reciclarse). No es un fallo del repo: falta
el redeploy de Arturo con las variables en Production. Hasta ese redeploy,
la guardia P0-3 impide que un despliegue nuevo caiga en el mismo silencio.

### 4.5 Sello CSG en el `.pkg` (P2-5)

| Amenaza | Defensa actual | Riesgo que queda |
|---------|---------------|------------------|
| Alterar el paquete sin que nadie lo note | Sello Ed25519 del Notario sobre el sobre canónico (estructura + contenido completo); verificado antes de descifrar y antes de gastar el grant | El sello no cubre nada fuera del sobre; un sello válido no dice que el contenido sea "bueno", solo que no cambió desde que se selló |
| Fingir un sello sin Notario | Modo `required` sin sidecar: no se crea el paquete; nunca se usa el sello local de desarrollo como sello de paquete | Un paquete legacy sin sello abre igual (compatibilidad): el panel lo avisa como "sin garantía CSG" |
| Sidecar caído al abrir un paquete sellado | Falla cerrada (`CSG_PACKAGE_SEAL_FAILED`): no verificable = no se abre | Disponibilidad del sidecar en el camino de apertura |

### 4.6 Custodia Smart Token de la CEK (P2-6)

| Amenaza | Defensa actual | Riesgo que queda |
|---------|---------------|------------------|
| Robar el `.pkg` y sacar la CEK de él | En este modo el paquete NO contiene CEK envuelta por el Oracle (en vez de, no además de) | Si el paquete contuviera ambas, la custodia no serviría: el auditor debe verificar que sigue siendo "en vez de" |
| Abrir sin grant válido | Smart Token ni se contacta sin grant; revocación, épocas y un solo uso intactos | Ninguno en el diseño; la CEK solo se libera tras grant |
| Robo del master del emisor | Master por operación, nunca guardado en TDCP (ni paquete, ni logs, ni estado) | Quien tenga grant válido + master abre: el master ES el factor de conocimiento en este modo |
| Servicio Smart Token caído o que niega | Falla cerrada (`SMART_TOKEN_UNAVAILABLE` / `SMART_TOKEN_DENIED` opaco); un intento fallido consume el grant igual que una contraseña incorrecta | Disponibilidad y recuperación: sin master no hay recuperación del documento |
| CEK en claro en tránsito/memoria | Llega por HTTPS al proceso que descifra, se importa y se borra el buffer | Un proceso descifrador comprometido la ve (supuesto del §2) |

### 4.7 Cuentas, sesiones y admin

| Amenaza | Defensa actual | Riesgo que queda |
|---------|---------------|------------------|
| Admin API sin autenticar | Bearer `TDCP_AUTHORITY_ADMIN_TOKEN`; modos `oidc` / `mtls` / `oidc+mtls` disponibles (`docs/ADMIN_AUTH.md`); en esos modos el Bearer queda desactivado | El modo `token` es un secreto compartido, no mTLS/OAuth: aceptable para Starter, a revisar antes de un tier de pago |
| Token admin en el bundle web | `VITE_TDCP_AUTHORITY_ADMIN_TOKEN` solo para demo local; nunca en producción | Un descuido en el build lo filtraría al navegador |
| Sesión web robada | Better Auth sobre Supabase; sesiones separadas de los grants de paquetes | Una sesión robada no abre paquetes sin grant, pero sí actúa como el usuario en la app |
| Secretos en logs | Logs estructurados omiten `Authorization` y no registran secretos | Un operador puede activar logs de depuración que filtren material sensible |

## 5. Fuera de alcance (lo que este modelo NO cubre)

- El SDK de AWS y el servicio KMS en sí (solo se revisa el sidecar de
  ejemplo y su contrato HTTP con TDCP).
- Los servicios Smart Token y CSG en sí (su criptografía interna, su
  fricción, su almacenamiento): solo su contrato con TDCP.
- La infraestructura de Vercel y de Supabase como tal (red, aislamiento
  entre proyectos, parches): solo cómo TDCP las usa.
- El IRM SaaS completo (plugins, email gateway, CASB), el multi-tenant
  alojado, los backups cifrados y los SLO: pendientes, no diseñados.
- Pruebas formales de los protocolos y certificaciones de cumplimiento
  (Common Criteria / FIPS / SOC 2): no existen en este repo.
- El Oracle en el navegador como frontera de producción: es solo referencia.

## 6. Supuestos que el auditor debe verificar o romper

1. La Data API de Supabase no lee las tablas `authority_*` ni las de
   cuentas (RLS sin políticas) — comprobarlo con una llamada real, no solo
   leyendo la migración.
2. `TDCP_AUTHORITY_STORE=postgres` sin `DATABASE_URL` de verdad impide el
   arranque en producción, y `GET /api/db-status` dice `postgres` tras el
   redeploy pendiente.
3. El backend `external` de verdad no cae a `file` cuando el firmador
   muere, y `developmentOnly: true` aparece sin `ATTESTED=true`.
4. Un paquete alterado con `integrityHash` recalculado es rechazado por el
   sello CSG antes de gastar el grant; un paquete legacy sin sello abre con
   el aviso de "sin garantía CSG".
5. En modo `smart-token-custody` el paquete no contiene CEK envuelta por el
   Oracle y sin grant no hay ninguna llamada a Smart Token.
6. Los logs no contienen secretos (`Authorization`, wrap secrets, CEK,
   masters, tokens) ni siquiera en los caminos de error.
7. El rate limit en memoria no se presenta como sustituto de un WAF /
   gateway en el borde.

## 7. Historial de cambios de este modelo

- **2026-11-11 (P0-4):** primera versión completa sobre la arquitectura
  final: store Postgres (P0-1), firma externa (P0-2), guardia fail-fast
  (P0-3), sello CSG (P2-5), custodia Smart Token (P2-6). Antes solo existía
  el resumen de amenazas en `docs/SECURITY_REVIEW_PACK.md` y el modelo del
  Channel Guardian (`packages/channel-guardian/docs/THREAT_MODEL.md`,
  que cubre solo ese paquete, no la Authority).
- **Antes:** `AUDIT_2.5.1.md` documentaba la limitación del Oracle en
  proceso y los no-reclamos; `ROADMAP.md` P0–P7 registraba cada pieza al
  fusionarse.
