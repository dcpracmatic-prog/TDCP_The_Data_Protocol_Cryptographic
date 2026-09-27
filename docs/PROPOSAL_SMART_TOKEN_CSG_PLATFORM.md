# Propuesta TDCP: Smart Token + CSG + USB Binding

## Objetivo

Convertir TDCP en una capa de autoridad que pueda vincular almacenamiento físico, credenciales de larga duración e integridad técnica sin convertir la USB en el segundo factor de inicio de sesión.

## Principio

**La cuenta autentica al usuario. La Authority autoriza el dispositivo. Smart Token aporta la credencial de autorización y recuperación. CSG sella la relación técnica.**

## Flujo de cuenta

1. Correo/identidad.
2. Contraseña.
3. Segundo factor mediante dispositivo autorizado, passkey o biometría respaldada por el sistema operativo.
4. Se crea la sesión TDCP.
5. Solo después se puede validar o vincular una USB.

La USB no sustituye el login.

## Enrolamiento USB

```text
Cuenta autenticada
    -> observar USB
    -> normalizar hardware observable
    -> calcular hardwareDigest
    -> crear Device Binding
    -> Smart Token autoriza
    -> CSG sella el input canónico
    -> Authority registra ACTIVE
```

## Validación

```text
USB observada
  + binding
  + Smart Token
  + CSG
       |
       +-- hardware mismatch -> INVALID
       +-- token mismatch    -> INVALID
       +-- CSG mismatch      -> INVALID
       +-- revoked/expired   -> INVALID
       +-- todo coincide     -> VALID
```

## Recuperación

```text
Login + 2FA
   -> Smart Token
   -> validar autorización de recuperación
   -> revocar USB anterior
   -> observar USB nueva
   -> crear nuevo binding
   -> CSG
   -> ACTIVE
```

## Validación colaborativa sin guardar

El usuario puede habilitar un modo efímero para comprobar una USB de un colaborador sin registrarla permanentemente.

```text
observe -> verify -> result -> discard binding context
```

El modo colaborativo debe forzar `ephemeral` y no crear un registro de dispositivo permanente.

## HSM

Configuración inicial:

`none`

Opciones:

- `none`: sin HSM adicional.
- `usb`: HSM conectado localmente.
- `cloud`: proveedor HSM remoto.

La UI solo selecciona el proveedor. Nunca debe recibir ni persistir una clave privada del HSM.

## NFC

NFC pasa a ser un proveedor opcional:

- desactivado por defecto;
- no requerido para login;
- no requerido para recuperación;
- no requerido para vinculación USB.

Esto reduce coste y complejidad de hardware en el camino principal.

## Modelo de confianza

VID/PID/serial y demás atributos USB son datos observables. No son secretos ni una raíz de confianza por sí mismos.

La propiedad de seguridad proviene de que el estado observado queda relacionado con una autorización Smart Token y un sello CSG que la Authority reconoce y puede revocar.

Para una resistencia física superior contra dispositivos capaces de falsificar descriptores USB, la evolución recomendada es una clave de dispositivo no exportable mediante secure element/HSM.

## Revocación

Estados recomendados:

`ACTIVE -> SUSPENDED -> REVOKED -> REPLACED`

No se recomienda destruir archivos como respuesta de seguridad. El control debe ser criptográfico y de estado: un binding inválido/revocado deja de ser aceptado y conserva evidencia auditable.

## Separación de responsabilidades

| Componente | Responsabilidad |
|---|---|
| TDCP Identity | autenticación de cuenta y sesión |
| TDCP Authority | autorización, revocación y estado de dispositivos |
| Smart Token | credencial de autorización/recuperación |
| CSG | integridad y attestation del binding/evento |
| USB | almacenamiento + identidad observable del dispositivo |
| HSM | protección opcional de claves de alto valor |
| NFC | integración opcional futura |

## Criterio de éxito

Antes de producción, la integración debe demostrar al menos:

- copia exacta de una USB a otra -> rechazo;
- cambio de serial/hardware observado -> rechazo;
- alteración del documento -> rechazo;
- alteración del sello CSG -> rechazo;
- token no autorizado -> rechazo;
- binding revocado -> rechazo;
- recuperación legítima -> nuevo binding ACTIVE;
- validación colaborativa -> resultado sin persistencia del binding.
