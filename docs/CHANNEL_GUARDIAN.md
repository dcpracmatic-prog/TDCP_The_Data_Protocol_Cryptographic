# Channel Guardian — plano de canal / egress (aditivo)

## Rol

El **Channel Guardian** protege el **canal de datos en tiempo de ejecución** *después* de que el Gatekeeper haya autorizado una operación. No emite grants, no evalúa política de negocio y no posee wrap secrets.

| Plano | Responsabilidad | Componente |
|-------|-----------------|------------|
| Control | Grants, revocación, política | Authority + Gatekeeper |
| Datos | Cifrado autenticado del sobre | TDCPPackage |
| Integridad de eventos | Atestación de operaciones | CSG / Sello (opcional) |
| Protección PQ + fricción | Artefacto de larga duración | Smart Token (API aislada) |
| **Canal / egress** | **Bordes, presupuestos de bytes, cuarentena** | **`@tdcp/channel-guardian`** |

Invariante: **Gatekeeper sigue siendo la única vía de unlock** de paquetes TDCP.

## Ubicación en el monorepo

```text
packages/channel-guardian/   # @tdcp/channel-guardian
```

Documentación del paquete: `packages/channel-guardian/docs/INTEGRATION.md`, `THREAT_MODEL.md`.

## Flujo (Gatekeeper-first)

1. Cliente solicita operación vía Gatekeeper.
2. Authority emite grant de un solo uso y firma un `PolicyBinding` `{ documentId, grantId, expiry, edges[] }`.
3. Aplicación: `ChannelGuardian.fromBinding(binding, authorityPublicKey)`.
4. Tráfico de plano de datos: `guardian.send("A->B", frame, chunkIdx)`.
5. Fin de operación / expiry → descartar la instancia.
6. Opcional: `guardian.auditEvents()` → audit sink TDCP; evento → CSG/Sello.

## Qué no hacer

- Usar el Guardia como condición previa al grant.
- Meter claves del Notario CSG o wrap secrets en el proceso del Guardia.
- Exponer un mapa mutable de `edges` tras verificar el binding.

## Pruebas

```bash
node --test packages/channel-guardian/test/guardian.test.mjs
```

## Estado

Paquete integrado como **plano aditivo opcional** (pre-producción). La emisión de `PolicyBinding` desde Authority remoto es el siguiente cableado de producto; la biblioteca y el contrato ya están listos.
