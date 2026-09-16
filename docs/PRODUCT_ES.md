# TDCP — Definición de producto (resumen para fundador)

Documento canónico completo: `../PRODUCT.md`. Mercado: `../MARKET.md`. Hoja de ruta: `../ROADMAP.md`.

## Qué es

**TDCP (The Data Cryptographic Protocol)** — protocolo que separa paquetes cifrados de la autorización para operar sobre ellos. **Copiar el ciphertext no copia la autorización.**

- El `.pkg` es almacenamiento.
- La Authority/Oracle es el plano de control.
- El **Gatekeeper** es el único camino de la app que puede desbloquear un paquete (READ / RENDER / EXTRACT, etc.).

## Qué vendemos / hacia dónde construimos

1. Protocolo + Gatekeeper de referencia (canónico — este repo)
2. **Authorization Authority remota** (siguiente hito crítico)
3. Superficie developer / SDK (TypeScript primero; Python solo demo)
4. Puente opcional a ATL Edge más adelante (agentes solo vía Gatekeeper) — **solo diseño futuro, sin código ATL aquí**

## ICP

- **Primario:** equipos que construyen data rooms seguros, intercambio regulado de archivos, o pipelines de agentes con unlocks por operación y revoke/replay.
- **Secundario:** ingenieros de seguridad que evalúan protocolos data-centric abiertos (nicho OpenTDF-adjacent).

## No-goals (~2 trimestres)

- Competir de frente como IRM SaaS completo (Virtru / Seclore / Digify)
- Firebase / Gemini en el plano de control
- Afirmar paridad HSM o “Oracle de browser = producción”
- Suite de plugins Office, gateway de email, listing CASB

## Viabilidad

Hay necesidad real de **control persistente después de compartir**. La vía de adopción de TDCP es **cuña protocolo/SDK + Authority remota**, no paridad de features IRM.

## Hitos (orden)

| Prioridad | Hito |
|-----------|------|
| P0 | Diseño + interfaz stub de Authority remota |
| P1 | Revoke/replay durable |
| P2 | API Gatekeeper para integradores (TS) |
| P3 | Nota de diseño puente ATL Edge (sin implementar) |
| P4 | Pulido UI / auth demo local sin claims de producción |

## Honestidad de seguridad

Mantener lo de `AUDIT_2.5.1.md`: Oracle en browser no es frontera HSM; sin pruebas formales; A/B/C no es Shamir; no cambiar primitivas crypto ni semántica de seguridad del Gatekeeper en este trabajo de producto.
