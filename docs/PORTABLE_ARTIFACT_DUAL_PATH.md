# Artefacto cifrado portátil — dual path (USB | MFA)

## Modelo

```text
Artefacto cifrado portátil (descargable, renombrable, nube/USB/NAS)
        │
        ▼
  CSG verify (previo a pedir secretos)
        │
   ┌────┴────────────────────┐
   ▼                         ▼
Ruta A: Anclaje físico     Ruta B: Step-up MFA
  USB autorizada (H)         Contraseña + TOTP
  + sello CSG binding        [+ WebAuthn / FIDO2]
        │                         │
        └──────────┬──────────────┘
                   ▼
         STP API unwrap (obligatorio anti brute-force offline)
                   ▼
              contenido
```

- **Portabilidad:** el ciphertext es agnóstico al almacenamiento (Drive, Dropbox, NAS, USB genérica).
- **Inutilidad sin autorización:** sin plano STP (y pruebas de ruta A o B) no hay content-key.
- **USB no es login:** la cuenta se autentica aparte; la USB es dispositivo de almacenamiento autorizado.

## Invariantes

1. Validar **CSG** antes de solicitar contraseña, TOTP o biometría.
2. **Unwrap** de la clave de contenido vía **API Smart Token confiable** (no URL embebida en el JSON).
3. Ruta A: reconstruir digest canónico \(H\) y contrastar con binding sellado.
4. Ruta B: identidad de cuenta (password + TOTP; WebAuthn recomendado) sin exigir USB.

## HSM `none` — lo que SÍ y lo que NO

| Con HSM = none | ¿Posible? |
|----------------|-----------|
| Dual path A/B (USB binding + MFA) | Sí |
| Artefacto portátil + STP obligatorio | Sí |
| Sello CSG + rechazo INVALID | Sí |
| Claves de unwrap aisladas en módulo HSM validable | **No** |
| Resistencia a compromiso del host/proceso STP como la de un HSM | **No** |
| Afirmación tipo FIPS 140-3 del módulo de claves TDCP | **No** (salvo componer un HSM ya certificado) |

**Riesgo que el operador debe valorar:**  
Con `hsmProvider: none` el sistema es **soberano y funcional**, pero el material criptográfico sensible vive en **software** (API STP, Authority file-backed, navegador). Un atacante que comprometa ese software no se enfrenta al aislamiento físico/lógico de un HSM.

**Decisión de producto recomendada al usuario:**

- Aceptar el riesgo de `none` en pre-producción / datos de bajo impacto, **o**
- Integrar **como mínimo HSM USB** (token/HSM real del cliente, no pendrive genérico = HSM), **o**
- Integrar **Cloud HSM/KMS** (AWS/Azure/GCP/Vault) bajo la soberanía y contrato del cliente.

La preferencia se configura en `SecurityDevicesPanel` (`none` | `usb` | `cloud`). Ver también `docs/SECURITY_DEVICE_MODES.md`.
