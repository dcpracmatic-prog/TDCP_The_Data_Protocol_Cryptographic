# Sesión de usuario en el Authority TDCP

Con `TDCP_USER_AUTH=required`, el Authority solo responde a usuarios con sesión iniciada en la app web. Cada challenge, cada grant y cada liberación del wrap secret quedan ligados a un usuario verificado. Cada documento tiene un dueño y una lista de acceso.

## Flujo

```
Navegador ──cookie de sesión──▶ App web (Better Auth)
    │                            GET /api/auth/token  → JWT EdDSA, 5 min, sub = user.id
    │                            GET /api/auth/jwks   → claves públicas
    │
    └──x-tdcp-user-token: <JWT>──▶ Authority
                                   verifica firma (JWKS), iss, aud, exp (≤ 1 h)
                                   subjectUserId = sub   (el cliente nunca lo elige)
```

| Paso | Qué exige el Authority |
|---|---|
| `POST /v1/challenge` | Token válido. El challenge queda ligado al usuario. |
| `POST /v1/authorize` | Token válido. El `subjectUserId` del body se descarta y se reemplaza por el `sub` verificado. El challenge debe pertenecer al mismo usuario. El usuario debe ser dueño o estar en `allowedUserIds`. El grant firmado incluye `SUBJECT:<id>`. |
| `POST /v1/wrap-secret/release` | Mismo usuario del grant. La ACL se vuelve a comprobar en ese momento. Si el documento es View-Once, se consume aquí mismo, de forma atómica. |
| `POST /v1/view-once/commit` | Mismo usuario del grant. |
| `POST /v1/documents` | Registro del documento. El dueño es el `sub` del token (se ignora el `ownerUserId` del body). Si el `documentId` ya existe, responde 409. |
| `POST /v1/documents/:id/acl` · `revoke` · `restore` | Solo el dueño. A cualquier otro usuario se le responde 404, para no revelar si el documento existe. |
| `GET /v1/me/documents` | Documentos propios y compartidos conmigo. |
| `GET /v1/documents/:id/policy` | La ACL solo es visible para el dueño. |

En modo `required` se deniegan los documentos sin dueño ni ACL (`DOCUMENT_HAS_NO_ACL`). Esto incluye los registrados por admin sin `ownerUserId`. El endpoint admin `/v1/documents/register` también rechaza sobrescribir un documento existente (409).

## Compartir

En "Crear paquete", el campo "Compartir con" acepta correos o IDs `DCP-USR-…`. La app los convierte en ids de usuario en el servidor (`resolveShareRecipients`, detrás de `authMiddleware`, máximo 25). Cada destinatario debe tener ya una cuenta. El dueño puede cambiar la lista después con `updateDocumentAcl`.

Mientras no exista verificación de email, compartir por ID `DCP-USR-…` es más seguro que por correo. Alguien podría registrar primero una cuenta con el correo de otra persona.

## Configuración

App web (`.env`):

```env
VITE_AUTH_ENABLED=true
VITE_TDCP_AUTHORITY_URL=https://authority.tu-dominio.com
BETTER_AUTH_URL=https://app.tu-dominio.com          # = issuer del JWT
BETTER_AUTH_SECRET=<openssl rand -hex 32>            # cifra la clave privada del JWKS
# TDCP_USER_AUDIENCE=tdcp-authority                  # opcional, debe coincidir
```

Authority:

```env
TDCP_USER_AUTH=required
TDCP_USER_JWKS_URL=https://app.tu-dominio.com/api/auth/jwks   # https fuera de localhost
TDCP_USER_ISSUER=https://app.tu-dominio.com                    # = BETTER_AUTH_URL
TDCP_USER_AUDIENCE=tdcp-authority
TDCP_CORS_ORIGINS=https://app.tu-dominio.com
```

Aplica `migrations/0004_jwks.sql` con `npm run db:migrate` (tabla `jwks`, con RLS). La clave de firma se genera sola en la primera petición a `/api/auth/token`, rota cada 90 días y la anterior sigue siendo válida 7 días más.

Si hay cuentas, el navegador no lee `VITE_TDCP_AUTHORITY_ADMIN_TOKEN`. Ese token queda solo para la demo anónima (`VITE_AUTH_ENABLED=false`, `TDCP_USER_AUTH=off`).

## Límites conocidos

- La credencial NFC y el dispositivo siguen siendo mocks. La sesión de usuario es hoy el único factor de identidad que verifica el servidor.
- El descifrado y el visor siguen ejecutándose en el navegador. Un usuario autorizado puede quedarse con el contenido que abrió.
- `allowedOperations` aún no se aplica en el Oracle.
- Un token robado sirve durante un máximo de 5 minutos. Cerrar sesión no invalida los tokens ya emitidos antes de que caduquen.

## USB-HSM y correo

- Credencial sin llave: el Authority fija `credentialId = ACCOUNT-<sub>`; ignora el valor del cliente.
- Documentos CRITICAL / ULTRA_CRITICAL o con `requireUsbHsm`: exigen firma del USB-HSM del usuario (`USB_HSM_REQUIRED` si falta). Ver [HSM_USB.md](./HSM_USB.md).
- El JWT incluye `email_verified`; con `TDCP_REQUIRE_VERIFIED_EMAIL=true` solo cuentas verificadas registran llaves. El correo lo envía Resend (`RESEND_API_KEY`, `EMAIL_FROM`).
