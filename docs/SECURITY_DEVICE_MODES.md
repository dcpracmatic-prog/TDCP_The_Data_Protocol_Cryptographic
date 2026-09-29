# TDCP Security Device Modes

**Principio:** soberanía de datos. El cliente elige e integra el plano de claves; TDCP no impone un proveedor externo ni trata la USB como secreto de autenticación.

## Defaults

| Función | Predeterminado |
|---|---|
| USB binding | activado |
| HSM | `none` |
| NFC | retirado (reemplazado por USB-HSM) |
| Validación colaborativa | desactivada |
| Validación USB | persistente |

## HSM (`none` | `usb` | `cloud`)

Estos valores son **preferencia de configuración del cliente**, no un requisito de TDCP ni un segundo plano de login.

| Modo | Significado |
|------|-------------|
| **`none`** | Sin dependencia artificial de un proveedor HSM. Criptografía de aplicación / Authority según despliegue. Predeterminado soberano. |
| **`usb`** | Adaptador para HSM/token criptográfico **conectado localmente** (el cliente lo integra). No equivale a “pendrive genérico = HSM”. |
| **`cloud`** | Adaptador para HSM/KMS **remoto** (AWS / Azure / GCP / Vault, etc.) cuando el cliente decide usarlo. |

- La clave maestra o privada **no** debe copiarse a la capa UI.
- Documentación de Authority/comercial que mencione HSM/KMS describe un **camino de producción opcional** que el cliente cablea; no contradice el default `none` ni la soberanía del despliegue self-hosted.
- Los adaptadores en código son interfaces; sin SDK real no se afirma custodia certificada.

## USB: dispositivo autorizado, no 2FA

La USB **no** es el segundo factor de inicio de sesión.

```text
Login de cuenta (independiente):
  identidad + contraseña + 2FA/passkey/TOTP

Después de la sesión:
  USB = almacenamiento autorizado + device binding
```

El `serial` observable **no** es secreto ni autenticador. Solo forma parte de una representación canónica `H` que se autentica junto con cuenta, device_id, autorización y sello CSG. Ver `docs/USB_DEVICE_BINDING_SMART_TOKEN_CSG.md`.

## USB colaborativa

Cuando `collaborativeUsbValidation=true`, la aplicación debe forzar `usbValidationPreference=ephemeral`.

Objetivo: comprobar si la USB está autorizada **sin** registrar binding permanente en la cuenta.

## NFC (retirado → USB-HSM)

La credencial NFC fue reemplazada por el **USB-HSM**: la credencial es la cuenta verificada
por el Authority (`ACCOUNT-<userId>`) y el factor físico es una llave USB FIDO2 con elemento
seguro registrada a la cuenta. Ver [HSM_USB.md](./HSM_USB.md). El interruptor NFC queda
deshabilitado en la UI.

## Separación de planos

| Plano | Rol |
|-------|-----|
| **TDCP Authority** | Cuenta, grants, revocación, dispositivos registrados |
| **Smart Token** | Credencial / artefacto de larga duración (self-hosted) |
| **CSG** | Sello de integridad de la relación (binding, contenido) |
| **USB** | Contexto físico observable + almacenamiento; fuera del contexto autorizado el binding falla |
| **HSM preferencia** | Dónde el *cliente* ancla claves adicionales (`none` / `usb` / `cloud`) |

## Artefacto portátil y dual path (USB | MFA)

El ciphertext puede almacenarse en cualquier medio. La apertura usa:

- **Ruta A:** USB autorizada (digest canónico H + CSG).
- **Ruta B:** step-up de identidad (contraseña + TOTP; WebAuthn recomendado).
- **Siempre:** verificación CSG previa; unwrap vía API Smart Token confiable (anti brute-force offline).

Detalle: `docs/PORTABLE_ARTIFACT_DUAL_PATH.md`.

### HSM none: funcional, no equivalente a HSM

Con `hsmProvider: none` el dual path **sigue siendo posible**. Lo que **no** es posible:

- aislar las claves de unwrap en un módulo HSM validable;
- afirmar el mismo nivel de resistencia ante compromiso del host/API que con HSM USB o Cloud HSM.

Ese riesgo debe valorarlo el operador al decidir integrar **HSM USB** o un **servicio Cloud HSM/KMS**. TDCP no impone el proveedor; expone la preferencia y el aviso de riesgo en la UI (`SecurityDevicesPanel`).
