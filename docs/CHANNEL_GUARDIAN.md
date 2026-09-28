# Channel plane (workflow) — estado de implementación

Documentación **solo de hechos** implementados en código. Sin claims de producto futuros.

## Implementado

| Pieza | Ubicación | Estado |
|-------|-----------|--------|
| Presupuesto de canal cooperativo (Web Crypto, misma curva que grants) | `src/channel/channel-budget.ts` | Sí |
| Validación de esquema, edges duplicados, expiry en `send` | idem | Sí |
| Binding firmado al emitir grant (`grantId` + `expiresAt`) | `src/oracle/authorization-oracle.ts` → `channelPolicyBinding` | Sí |
| Tipo de respuesta Authority | `src/authority/types.ts` (`channelPolicyBinding?`) | Sí |
| Tests | `src/channel/channel-budget.test.ts` + `packages/channel-guardian/test/` | Sí |

## Rol (código)

- Protege el **canal del flujo de trabajo** tras un grant: aristas, presupuestos de bytes, cuarentena cooperativa.
- **No** cifra documentos, **no** emite grants, **no** guarda wrap secrets ni claves de Notario CSG.
- CSG / Smart Token / Gatekeeper siguen en sus planos; este binding es aditivo en la respuesta de authorize.

## Qué no está hecho (por eso no se documenta como producto cerrado)

- Proxy/sidecar como único camino de red (egress real).
- UI que enrute todas las tramas de sesión por `ChannelBudget.send`.
- Paridad criptográfica byte-a-byte con el paquete Node `@tdcp/channel-guardian` (referencia Node; TDCP usa Web Crypto en el camino de grants).

## Uso en código

```ts
// Tras authorize con granted + grant + channelPolicyBinding:
const budget = await ChannelBudget.fromBinding(
  result.channelPolicyBinding,
  authorityPublicKey,
  result.grant.grantId, // rechazo si no coincide
);
budget.send('GATEKEEPER->RUNTIME', frame, 0);
```
