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


## Claim de producto (honestidad)

La biblioteca **en proceso** solo aplica la política a tramas que la aplicación **elige** pasar por `guardian.send`. Eso **no** es un control de egress de red obligatorio:

| Capacidad real hoy | Nombre honesto |
|--------------------|----------------|
| Presupuestos de bytes y aristas firmados, cuarentena cooperativa | **Presupuesto de canal / política de canal cooperativa** |
| Único camino de red (proxy, sidecar, eBPF, allowlist de sockets) | **Protección de egress** (requiere componente de enforcement de red) |

Hasta que exista un proxy/sidecar como único camino de red, la documentación de producto debe preferir **presupuesto de canal**, no “egress protection” como garantía absoluta.

## Hardening (biblioteca)

- Validación de esquema de `ChannelPolicy` (documentId, grantId, edges, expectedBytes).
- Rechazo de aristas duplicadas.
- Comprobación de `expiry` en `fromBinding` **y** en cada `send`.
- Tests: `node --test packages/channel-guardian/test/guardian.test.mjs` (incluido en `npm test` / CI).

## Authority (siguiente cableado)

La emisión de `PolicyBinding` ligado al `grantId` consumido **aún no** está en el servidor Authority. Contrato listo en `src/channel/policy-binding.ts`. Cuando se cablee:

1. Al emitir el grant, construir `ChannelPolicy` con el mismo `grantId`.
2. `signPolicyBinding` con la clave de Authority.
3. Devolver binding junto al material del grant.
4. El cliente solo acepta binding cuyo `grantId` coincida con el grant verificado.
