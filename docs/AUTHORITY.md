# Authorization Authority (design)

**Status:** Design + durable MVP stub shipped (file-backed). **Not** HSM/KMS by itself — the `external` signing backend delegates to a KMS/HSM sidecar (see "Firma externa (KMS/HSM)" below); only an attested real KMS/HSM signer is production-grade. Browser Oracle remains reference/demo.

Canonical product: `PRODUCT.md`. Roadmap: `ROADMAP.md` P0–P1.

## Responsibilities

| Responsibility | Owner |
|----------------|--------|
| Policy evaluation | Authority |
| Challenge issue / freshness | Authority |
| One-time grant issuance (ECDSA P-256) | Authority |
| Wrap-secret release after verified grant | Authority |
| Revoke / epoch rotation | Authority (durable) |
| Replay / consumed operation registry | Authority (durable) |
| Document policy registration at encrypt time | Authority |
| Envelope integrity + unlock orchestration | **Gatekeeper** (client) |
| Ciphertext storage | Neutral (Drive / disk / blob) |

The Authority **never** receives plaintext or the content encryption key (CEK). It holds per-document **wrap secrets** used as an HKDF factor so that password + package copy is insufficient.

## Trust model

```
[Client / Gatekeeper]  --min material-->  [Authorization Authority]
        |                                         |
   verifies grant                          signs grants
   unlocks via Gatekeeper only             owns revoke/replay
                                           owns wrap secrets
                                           (prod: HSM/KMS signing)
```

**Assumptions**

1. **Durable state** for revoke, replay, challenges, policies, and wrap secrets survives Authority process restart.
2. **Production signing keys** live in HSM / KMS / platform Secure Key Store, reached through the `external` signing backend (`TDCP_SIGNING_BACKEND=external`, sidecar example in `examples/kms-signing-sidecar/`). The MVP file store uses an extractable JWK on disk — **development only**.
3. **Client receives minimum material:** public key (verify), short-lived challenges, one-time grants, and wrap-secret bytes only after grant verification/consumption — never the Authority private key.
4. A compromised browser is **not** a production security boundary when using the in-process Oracle. Remote Authority moves the control plane off the client.

## Durable state (MVP)

Persisted under `data/authority/` (gitignored), default file `authority-state.json`:

- Registered document policies
- Per-document wrap secrets (base64)
- Revocation / epoch state
- Consumed operations + grant IDs
- Active challenges (TTL still enforced in memory logic)
- Development signing JWK pair (honest: not HSM)

## HTTP API sketch

Base URL: `TDCP_AUTHORITY_URL` (e.g. `http://127.0.0.1:8787`)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/v1/public-key` | Key id + SPKI (verify grants) |
| POST | `/v1/challenge` | Issue fresh challenge |
| POST | `/v1/challenge/validate` | `{ challenge }` → `{ valid }` |
| POST | `/v1/documents/register` | Register policy; returns wrap secret once |
| GET | `/v1/documents` | List policies |
| GET | `/v1/documents/:id/policy` | Get policy |
| GET | `/v1/documents/:id/revocation` | Epoch / revoke state |
| POST | `/v1/authorize` | Process `AuthorizationRequest` → grant or deny |
| POST | `/v1/wrap-secret/release` | `{ grant }` → wrap secret or null (one-time) |
| POST | `/v1/view-once/commit` | Commit view-once after successful decrypt |
| POST | `/v1/revoke` | Rotate epoch / revoke |
| POST | `/v1/restore` | Clear revoke flag (new epoch) |
| GET | `/v1/revoked` | List revoked |

## Client wiring

- Env `TDCP_AUTHORITY_URL` (or `VITE_TDCP_AUTHORITY_URL`) → `HttpAuthorityClient`
- Else → `InProcessAuthority` wrapping the browser/in-process Oracle (current demo behavior)

Gatekeeper accepts optional `authority`; existing `oracle` option remains for backward compatibility.

## What is still required for production

- Real HSM/KMS-backed signing (no extractable JWK on disk)
- Broader IdP product features (SSO UI, multi-tenant RBAC) beyond admin JWT/mTLS hardening — see `docs/ADMIN_AUTH.md`
- Independent security review
- Multi-tenant isolation, backups, monitoring, SLOs
- Formal threat model update in `AUDIT_2.5.1.md`

## Admin authentication

Admin endpoints (register / revoke / restore / admin lists) support stronger modes via `TDCP_AUTHORITY_ADMIN_AUTH`:

| Mode | Summary |
|------|---------|
| `token` (default) | Bearer `TDCP_AUTHORITY_ADMIN_TOKEN` — **local/dev fallback** |
| `oidc` | OAuth2/OIDC JWT + admin claim — preferred for hosted |
| `mtls` | Client certificate against CA — preferred for self-host / high assurance |
| `oidc+mtls` | Both JWT and client cert required |

Full configuration, error codes, and mTLS cert generation: **`docs/ADMIN_AUTH.md`**.

Token-mode quick start:

```bash
export TDCP_AUTHORITY_ADMIN_AUTH=token   # default
export TDCP_AUTHORITY_ADMIN_TOKEN="$(openssl rand -hex 32)"
curl -s -X POST "$TDCP_AUTHORITY_URL/v1/documents/register" \
  -H "authorization: Bearer $TDCP_AUTHORITY_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"documentId":"DOC-1","packageId":"PKG-1","policyLevel":"STANDARD","allowExtraction":false,"createdAt":0}'
```

When mode is `oidc|mtls|oidc+mtls`, the static Bearer token is **disabled**. Issuer tooling may still use `TDCP_AUTHORITY_ADMIN_TOKEN` with `HttpAuthorityClient` for local token mode only. `VITE_TDCP_AUTHORITY_ADMIN_TOKEN` is **local demo only** (leaks into the browser bundle).

Gatekeeper public path (challenge / authorize / wrap-secret release / public-key / per-document policy get) stays unauthenticated, with in-memory rate limits on challenge/authorize.

**Honesty:** this hardens the admin surface; it is not a full enterprise IdP.

## Ops endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/ready` | Ready = store writable + signing key loaded |
| GET | `/metrics` | Prometheus counters |

See `docs/OPS.md`.

## Signing backend

| `TDCP_SIGNING_BACKEND` | Behavior |
|------------------------|----------|
| `file` (default) | Extractable JWK on disk via `DurableFileOracleKeyStore`. **NOT production-grade.** |
| `external` | The private key never enters the Authority process. Every signature is delegated to an external signer (HTTP sidecar or local command) implementing `OracleKeyStore.signCanonical`. **Fail closed:** if the signer is unreachable or misbehaves, the grant is not issued and there is no silent fallback to `file`. |
| `kms-stub` (legacy) | Deprecated alias → `file`. Kept only so old deployments keep booting. |

## Firma externa (KMS/HSM)

**Idea en simple:** la Authority no guarda la llave de firma. Cuando tiene
que firmar un permiso, le pide la firma a otro programa (el *firmador*),
que es el único que toca la llave. La Authority solo conoce la llave
pública, para publicarla y verificar. Si el firmador no responde, **no se
firma nada** (falla cerrada): nunca se usa la llave de archivo en silencio.

**Punto de extensión:** `OracleKeyStore` (`src/oracle/oracle-key-store.ts`)
documenta el contrato — qué métodos, qué promete y qué no promete. El
backend listo para usar es `ExternalOracleKeyStore`
(`server/authority/external-signing-backend.ts`); enchufar otro KMS/HSM es
implementar esa interfaz o apuntar este backend a otro firmador. El resto
del código (Gatekeeper, revocación, anti-replay, view-once) no cambia.

### Configuración

```bash
export TDCP_SIGNING_BACKEND=external
# Una de las dos (no las dos):
export TDCP_SIGNING_EXTERNAL_URL=http://127.0.0.1:8011   # sidecar HTTP
# export TDCP_SIGNING_EXTERNAL_CMD="/usr/local/bin/kms-signer"  # comando local
export TDCP_SIGNING_EXTERNAL_KEY_ID="arn:aws:kms:...:key/..."  # opcional; si no, lo adopta del sidecar
export TDCP_SIGNING_EXTERNAL_TIMEOUT_MS=5000              # opcional
export TDCP_SIGNING_EXTERNAL_TOKEN="<redacted>"  # opcional, Bearer hacia el sidecar; nunca se registra en logs
# Solo cuando el firmador es un KMS/HSM real con llave no exportable:
export TDCP_SIGNING_EXTERNAL_ATTESTED=true
# Solo para el transporte por comando (el sidecar HTTP publica su llave):
# export TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_B64="<SPKI DER en base64>"
# export TDCP_SIGNING_EXTERNAL_PUBLIC_KEY_FILE=./data/authority/signer-pub.b64
```

Sin `TDCP_SIGNING_EXTERNAL_ATTESTED=true`, la Authority reporta el backend
como no apto para producción (`developmentOnly: true` en `/ready` y en
`/v1/public-key`), aunque el firmador funcione. Es un freno honesto: el
código no puede saber si detrás hay un KMS real o un firmador falso local.

### Protocolo del sidecar HTTP

| Método | Ruta | Cuerpo / respuesta |
|--------|------|--------------------|
| GET | `/health` | `{ "ok": true }` |
| GET | `/v1/public-key` | `{ "keyId", "publicKeySpkiBase64" }` (SPKI DER en base64) |
| POST | `/v1/sign` | `{ "canonical": "<utf8>" }` → `{ "signatureBase64" }` (firma cruda ECDSA P-256, r\|\|s, 64 bytes — los mismos bytes que devuelve WebCrypto, así la verificación de permisos no cambia) |

El firmador recibe **solo** los bytes canónicos del permiso. Nunca recibe
el documento, el texto claro ni la llave de contenido.

### Ejemplo: sidecar AWS KMS

Código en `examples/kms-signing-sidecar/` (sidecar + README de despliegue).
Dos modos con el mismo contrato HTTP:

- `fake` (por defecto): llave P-256 efímera en memoria. **Para pruebas y
  demo local, sin credenciales reales.** No es KMS, no es producción.
- `kms`: AWS KMS real. El SDK de AWS se instala solo en el directorio del
  sidecar (`npm install @aws-sdk/client-kms`); **no** es dependencia del
  repo TDCP. Las credenciales salen de la cadena estándar de AWS (variables
  de entorno, `~/.aws`, rol IAM del host). KMS devuelve firmas DER; el
  sidecar las convierte a crudo r||s.

Permisos IAM mínimos (solo para esa llave KMS, nada más):

```json
{ "Effect": "Allow", "Action": ["kms:Sign", "kms:GetPublicKey"],
  "Resource": "arn:aws:kms:<region>:<cuenta>:key/<id>" }
```

Sin `kms:Decrypt`, `kms:Encrypt` ni `kms:*`. La llave debe ser
`ECC_NIST_P256` con uso `SIGN_VERIFY` (una llave simétrica de KMS no puede
firmar permisos TDCP). Despliegue: sidecar en la misma máquina/red privada
que la Authority (`127.0.0.1` por defecto); si sale de localhost, TLS +
proxy inverso y token compartido (`SIDECAR_TOKEN` /
`TDCP_SIGNING_EXTERNAL_TOKEN`). Rotación: crear otra llave KMS, apuntar
`AWS_KMS_KEY_ID` a ella y reiniciar sidecar + Authority (no hay soporte
multi-llave automático todavía).

### Transporte por comando local

Para un HSM local, una USB con herramienta de línea de comandos, o un
agente PKCS#11 con envoltorio: el comando se ejecuta **sin shell**, recibe
los bytes canónicos por stdin y escribe una línea en stdout con la firma
en base64. La llave pública se entrega por entorno o archivo (ver arriba).
Ejemplo de firmador falso para pruebas:
`examples/kms-signing-sidecar/fake-cmd-signer.mjs`.

### Cómo enchufar el USB-HSM ya existente

El registro USB-HSM (`server/authority/usb-hsm.ts`, WebAuthn) hoy es
**identidad de usuario**, no firma de permisos: registra llaves FIDO2 del
usuario, verifica sus respuestas (con PIN/biometría, contador anti-clon)
y decide si ese usuario puede pedir un permiso. No firma permisos de la
Authority y no debe fingir que lo hace.

Enchufarlo como backend de firma (`OracleKeyStore.signCanonical`) es
posible pero **no está implementado, a propósito**: cada firma exigiría
una ceremonia WebAuthn interactiva (el usuario toca su llave), y la
Authority firma permisos sin nadie delante. Las dos vías honestas son:

1. **Llave USB del operador para el sidecar:** la llave protege el
   arranque o el desbloqueo del sidecar (el operador la toca una vez al
   arrancar), y el sidecar firma sin intervención después. El sidecar es
   el que implementa el desbloqueo; la Authority no cambia.
2. **Firma por permiso con presencia del usuario:** solo para flujos donde
   el usuario está presente; sería un `OracleKeyStore` nuevo cuya
   `signCanonical` pide una aserción WebAuthn (`usbHsmChallenge`) y la
   verifica contra `UsbHsmRegistry` antes de firmar con la llave del
   dispositivo. Eso cambia el flujo (la Authority ya no firma sola) y
   exige diseño y revisión de seguridad propios; no se hace en esta pieza.

### Qué NO es esto

- El backend `file` sigue sin ser HSM; esta pieza no lo convierte en uno.
- El sidecar `fake` no es KMS/HSM real; decir lo contrario sería falso.
- No hay pruebas formales ni certificación: esto es una interfaz + un
  ejemplo funcional, con tests automatizados del camino feliz y del fallo
  cerrado.

Production: implement real KMS Sign behind `OracleKeyStore.signCanonical` (see `src/oracle/oracle-key-store.ts`). Clear README note: file JWK is not production-grade.

## Commercial hardening docs

- Ops / backups / SLO sketch: `docs/OPS.md`
- Security review pack (not a certification): `docs/SECURITY_REVIEW_PACK.md`
- SKUs / legal placeholders: `docs/COMMERCIAL.md`
- Landing copy EN/ES: `docs/LANDING_COPY.md`
