# USB-HSM: tu llave USB como ID físico

El USB-HSM reemplaza a la credencial NFC. Un usuario convierte una llave USB en su ID de
hardware para TDCP: la llave genera dentro de su chip un par de claves que **no se puede
exportar**. El Authority guarda solo la clave pública, ligada a la cuenta, con ciclo de vida
`ACTIVE → SUSPENDED → REVOKED → REPLACED`
(ver [PROPOSAL_SMART_TOKEN_CSG_PLATFORM.md](./PROPOSAL_SMART_TOKEN_CSG_PLATFORM.md)).

Es la evolución que ya recomendaba el repositorio: el binding por VID/PID/serial
(`src/device/usb-binding.ts`) usa descriptores observables que se pueden copiar; una clave
en elemento seguro no.

## Qué llave sirve

Sirve cualquier llave **FIDO2 / WebAuthn USB** con PIN o huella: YubiKey 5, Nitrokey 3,
SoloKey, Feitian, Token2, Google Titan, etc. Una memoria USB genérica **no sirve**, porque
no tiene elemento seguro.

El Authority rechaza al registrar:

| Caso | Código |
|------|--------|
| Passkey sincronizada (iCloud / Google Password Manager) | `USB_HSM_NOT_HARDWARE_BOUND` |
| Autenticador de plataforma (Windows Hello, Touch ID) | `USB_HSM_NOT_USB` |
| Llave sin verificación de usuario (PIN/huella) | `USB_HSM_REGISTRATION_INVALID` |
| Origen o rpId distinto al configurado | `USB_HSM_REGISTRATION_INVALID` |
| Más de `TDCP_USB_HSM_MAX_PER_USER` llaves vivas | `USB_HSM_LIMIT` |
| Correo sin verificar (si `TDCP_REQUIRE_VERIFIED_EMAIL=true`) | `EMAIL_NOT_VERIFIED` |

## Flujo

1. **Cuenta primero.** La USB no inicia sesión. El usuario entra con correo y contraseña
   (Better Auth) y el Authority lo identifica por el JWT (`docs/AUTHORITY_USER_AUTH.md`).
2. **Registro** ("Hardware & Identidad" → "Mi USB-HSM" → "Registrar USB como mi ID"):
   - `POST /v1/me/usb-hsm/registration-options`: el reto es de un solo uso, dura 5 min y
     queda ligado al usuario.
   - La llave crea la clave (se toca y se pide el PIN).
   - `POST /v1/me/usb-hsm/register`: el Authority verifica la attestation y guarda
     `USBHSM-<sha256(credentialId)[:16]>` + clave pública COSE + contador.
3. **Apertura.** Si el documento es CRITICAL / ULTRA_CRITICAL o se creó con "Exigir USB-HSM
   para abrir":
   - El Gatekeeper calcula
     `challenge = SHA-256("TDCP-USB-HSM-AUTHZ-v1" | reto Authority | DOC | PKG | OP_ID | OP)`.
   - La llave firma ese reto (con PIN) y la firma viaja en `/v1/authorize`.
   - El Authority verifica la firma, el origin/rpId, el flag de verificación de usuario y el
     contador, y que la llave pertenezca al usuario del JWT.
   - Si todo cuadra, fija `deviceId = credentialId = USBHSM-…` en el grant firmado.
   - En los niveles CRITICAL, `biometricVerified` sale del flag UV de la llave, no de lo que
     declare el cliente.
4. **Liberación.** `/v1/grants/release` rechaza grants de una llave que ya no esté ACTIVE, así
   que revocar la llave también invalida los grants pendientes.

Los documentos que no exigen USB-HSM se abren solo con la cuenta. El Authority fija
`credentialId = ACCOUNT-<userId>` y la sesión se trata como no biométrica.

## Ciclo de vida

| Acción | Endpoint | Nota |
|--------|----------|------|
| Listar | `GET /v1/me/usb-hsm` | Nunca devuelve claves |
| Suspender / reactivar | `POST /v1/me/usb-hsm/:id/suspend` \| `reactivate` | Pausa temporal |
| Revocar | `POST /v1/me/usb-hsm/:id/revoke` | Permanente |
| Reemplazar (recovery) | `registration-options` con `replaceDeviceId` | La anterior pasa a REPLACED |
| Clon sospechado | automático | Si el contador de firmas retrocede, la llave pasa a SUSPENDED (`CLONE_SUSPECTED`) y solo se puede reemplazar |

Cada usuario solo ve y gestiona sus propias llaves; para cualquier otro usuario, la llave
aparece como inexistente (404).

## Configuración (Authority)

```bash
TDCP_WEBAUTHN_RP_ID=app.tu-dominio.com         # dominio de la app, sin esquema ni puerto
TDCP_WEBAUTHN_ORIGINS=https://app.tu-dominio.com
TDCP_WEBAUTHN_RP_NAME=TDCP
TDCP_USB_HSM_MAX_PER_USER=5
TDCP_REQUIRE_VERIFIED_EMAIL=true               # recomendado en producción (con Resend)
```

Por defecto, rpId y origin salen de `TDCP_USER_ISSUER`. WebAuthn exige HTTPS salvo en
`localhost`. Si cambias el dominio (rpId), las llaves registradas dejan de funcionar y hay
que volver a registrarlas.

## Límites honestos

- La attestation se pide en modo `none`: se verifica que la clave está ligada a un solo
  dispositivo, pero no el fabricante. Para exigir modelos concretos se puede cambiar a
  `direct` y validar el AAGUID contra FIDO MDS.
- El contador de firmas detecta clones solo en llaves que lo incrementan. Algunas llaves
  reportan 0 siempre.
- La clave de firma del Authority sigue siendo de archivo (no HSM). Eso es independiente
  del USB-HSM del usuario (ver `docs/AUTHORITY.md`).

## Pruebas

- `src/authority/usb-hsm.test.ts` (12 casos): usa un autenticador FIDO2 por software
  (`src/test/soft-usb-hsm.ts`) que genera estructuras WebAuthn reales. Cubre registro,
  rechazo de passkeys sincronizadas/no USB/sin PIN/origen falso, reto de un solo uso,
  firma para otro documento, llave de otro usuario, clon por contador, revocación con
  grant pendiente, reemplazo, límite por usuario, correo sin verificar, apertura
  end-to-end por Gatekeeper y persistencia tras reinicio.
- Verificado también en Chromium con el autenticador virtual CDP (ctap2/usb): registro
  desde la UI, apertura con llave y rechazo `USB_HSM_REQUIRED` para quien no tiene llave.
