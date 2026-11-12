# FAKE Smart Token — SOLO PARA PRUEBAS

**FAKE. NO ES PRODUCCIÓN. NO ES EL SERVICIO REAL.**

Este directorio contiene un doble en memoria del servicio HTTP Smart Token
Prod v0.10.5, solo para probar el visor offline de TDCP (y la CLI) sin el
servicio real y sin red externa. Nunca debe importarse desde código de
producción: vive bajo `test/` y ningún archivo bajo `src/` fuera de tests
lo importa (verificado con grep en el PR).

## Por qué `test/fake-smart-token/` y no `tools/fake-cli/`

El repo ya tiene `test/` como casa de los dobles y harness de pruebas
(`test/run-tdcp-tests.ts`, los `*.test.ts` bajo `src/`); la fake es un
doble de test del servicio externo, no una herramienta de operador. Quedarse
en `test/` deja claro que es infraestructura de pruebas y que `npm test`
la cubre.

## Qué hay aquí

| Archivo | Qué es |
|---|---|
| `fake-smart-token-server.mjs` | Servidor HTTP fake (node:http + node:crypto, sin deps). Exporta `createFakeSmartTokenServer()`. |
| `fake-smart-token-cli.ts` | CLI fake (`node --experimental-strip-types ...`). Espeja la CLI real. |
| `fake-smart-token.test.ts` | Tests del contrato del servidor + de la CLI (en `npm test`). |
| `viewer-e2e.test.ts` | Smoke e2e del visor offline real contra la fake (`npm run smoke:viewer-e2e`, también en `npm test`). |

## Contrato espejado (del real, leído en el repo Smart Token)

Fuente de verdad: `api/main.py` + `api/README.md` de
[Smart-Token-Prod](https://github.com/dcpracmatic-prog/Smart-Token-Prod)
(v0.10.5, commit 4423386, solo lectura) y
`sdk/typescript/src/smart-token-client.ts` de este repo.

| Endpoint real | Fake | Notas |
|---|---|---|
| `GET /healthz` (sin auth) → `{ok, storage_backend, smart_token_available}` | Igual, `storage_backend: "memory"` | Sin auth, como el real. Con `--down`, 503 `{ok:false,...}`. |
| `GET /v1/status` (Bearer) → `sdk_status()` | Igual + `fake:true` | `version 0.10.5`, `native_friction:false`, `available:true`. |
| `POST /v1/artifacts` (Bearer + `X-Smart-Token-Master`, multipart campo `file`) → `{artifact_id, filename, status:"PROTECTED"}` | Igual | `artifact_id` = 32 hex (mismo formato que el real, `token_hex(16)`). Sin master → 400; sin key → 503; key mala → 401; >50 MB → 413. |
| `POST /v1/artifacts/{id}/open` (Bearer + master) → 200 binario + `X-Smart-Token-Status: OPEN`, o 403 cuerpo `DENIED` | Igual, con 1 divergencia intencionada (abajo) | Sin master → 400. |
| `GET /v1/artifacts/{id}/friction` (Bearer) → `artifact_friction_status()` | Igual en forma | `{path, friction_snapshot{fail_count, recovery_tier, work_factor, cumulative_iters, stok_id, flag_fibonacci, flag_persistencia, tarpit_triggered}, public_label, target_coherence, has_embedded_sk, recovery_tier, work_factor, cumulative_iters}`. Desconocido → 404 como el real. Valores sintéticos (abajo). |

**Divergencia intencionada en `/open`:** artefacto desconocido → **403
`DENIED` opaco** (el real devuelve 404 "Artifact not found"). La fake no
distingue entre master incorrecto y artefacto desconocido, como pide la
tarea y como hace el doble en memoria de
`src/protection/smart-token-cek-custody.ts`.

## CLI espejada (de `smart_token_prod/cli.py`, prog `smart-token`)

| Comando real | Fake | Diferencia documentada |
|---|---|---|
| `serve` | **Extra fake** (no existe en el real) | Arranca el servidor: `--port` (0 = efímero), `--host` (default 127.0.0.1), `--api-key`, `--down`. Imprime `FAKE ready port=… url=…`. |
| `protect <archivo> [--master] [--out] [--key] [--backend] [--tarpit-mode] [--tarpit-seconds]` | Igual en flags/salida | Habla HTTP contra la fake (no crea `.stok` ni `.stok.key`); `--out` escribe un recibo JSON `{artifact_id, filename, status, fake:true}` (default `<archivo>.fake-stok.json`). `--backend`/`--tarpit-*`/`--key` se aceptan y se avisa que no tienen efecto. |
| `open <artifact-id\|recibo> [--master] [--key] [-o SALIDA] [--force-failure]` | Igual en flags/salida/códigos | 0 = OPEN, 1 = DENIED, 2 = sin master. Sin `-o` no vuelca el plaintext a stdout. `--force-failure` abre con un master forzado incorrecto. |
| `status <artifact-id>` | Igual en salida | Lee `GET /friction` y muestra los mismos campos que el real. |
| `demo [archivo]` | Igual en estructura (pasos 1–5) | Sin ladder ni hang: tras 3 fallos, 1 acierto correcto abre (el real exige 4). |
| `version` | Igual | Imprime `0.10.5 (FAKE — …)`. |
| `doctor` | Igual en estructura | Chequea PBKDF2/AES-GCM + `fetch` + `/healthz` si hay URL; no chequea pqcrypto/argon2/native. |
| `print-dep [--editable]` | Igual en forma | No hay paquete pip: solo avisa cómo correr la fake con Node. |
| `integrate <dir> [--bridge] [--editable] [--dry-run]` | Igual en flags | **Nunca escribe**: solo admite `--dry-run`; sin él, exit 2. |
| `repair-mac <artifact-id> [--key]` | Igual en salida | Solo lectura de fricción; no hay MAC real que reponer. Deuda preservada. |

Cada salida de la CLI lleva el prefijo `[FAKE]`; `--help` lleva el banner
FAKE. `--master` también se puede dar con `SMART_TOKEN_MASTER`;
`--api-url`/`--api-key` con `SMART_TOKEN_API_URL`/`SMART_TOKEN_API_KEY`.

## Cómo se guarda (y qué NO se guarda)

- Solo en memoria (`Map` en el proceso del servidor). Al parar el proceso,
  todo desaparece. Sin disco, sin persistencia.
- El blob se cifra antes de guardarse: PBKDF2-SHA256 (100.000 iteraciones,
  salt 16 B) + AES-256-GCM (iv 12 B), clave derivada del master. El cliente
  manda el blob en claro por HTTP local; la fake **no lo guarda en claro**.
- Del master solo se guarda su **SHA-256** (para verificar en `open`), nunca
  el valor, como el doble en memoria de `smart-token-cek-custody.ts`.
- La fricción es **sintética**: `fail_count` sube 1 por cada `open` con
  master incorrecto sobre un artefacto existente; `recovery_tier` =
  0/1/2/3 según `fail_count` 0/1/2/≥3; `work_factor` = 1/2/4/8;
  `cumulative_iters` = `fail_count × 1000`; resto de flags en `false`,
  `target_coherence: 1.0`, `has_embedded_sk: false`. Un `open` correcto
  resetea `fail_count` a 0.

## Suposiciones documentadas (donde el real no dejaba ver el formato)

1. **Fricción:** el cliente TDCP solo hace `res.json()` sin consumir
   campos, así que la forma se tomó de `friction_status()` en
   `smart_token_prod/stok.py` (campos listados arriba). Los valores son
   sintéticos (ver sección anterior), no medidos del real.
2. **`GET /v1/status`:** forma tomada de `sdk.status()` en
   `smart_token_prod/sdk.py` (`version`, `native_friction`,
   `import_error`, `role`, `available`); la fake añade `fake:true` y
   `storage_backend`.
3. **`/healthz` sin auth y `/v1/*` con 401/503:** leídos de `api/main.py`
   (`require_api_key`: sin key → 503, sin Bearer → 401).

## Qué NO imita la fake del servicio real

- **ML-KEM-768** (wrap post-cuántico): la fake usa PBKDF2 + AES-GCM
  derivado de la contraseña. No observable por HTTP, pero es la diferencia
  criptográfica principal.
- **Argon2id** en cada intento: la fake usa PBKDF2 (100k, ~decenas de ms).
- **Fricción persistente file-borne:** en el real el `friction_snapshot` +
  `friction_mac` viajan dentro del `.stok` y sobreviven a copias y
  reinicios; en la fake viven en un `Map` y se pierden al parar.
- **Validation ladder:** tras N fallos el real exige N+1 aciertos
  consecutivos de la misma clave correcta (tope 4); la fake abre al primer
  acierto y resetea.
- **Hang de fase 3:** con `fail_count ≥ 3` el real puede no retornar ante
  un master incorrecto; la fake siempre responde DENIED rápido.
- **Tarpit / trabajo de trampa** (cpu/mutate/block): no implementado.
- **`.stok` + `.stok.key` (sk fuera de banda), almacenamiento local/S3,
  núcleo C++ `libfriction.so`, `SMART_TOKEN_MAX_UPLOAD_BYTES` salvo el
  límite 50 MB, CORS, `/docs`:** no imitados (o solo el límite de tamaño).
- **404 en `/open` por artefacto desconocido:** la fake devuelve 403
  opaco por diseño (ver divergencia arriba).

## Simular caída (fail-closed del visor)

- Al arrancar: `serve --down` (todo el contrato responde 503).
- En caliente: `POST /__fake__/down` y `POST /__fake__/up` (endpoints de
  control solo-fake, loopback, fuera del contrato), o en proceso
  `server.setDown(true/false)`.
- `POST /__fake__/reset` vacía la memoria; `GET /__fake__/state`
  devuelve `{down, artifacts}`.

## Uso rápido

```sh
# 1. Servidor fake en puerto efímero
node --experimental-strip-types test/fake-smart-token/fake-smart-token-cli.ts serve --port 0 --api-key test-key
# → [FAKE] FAKE ready port=XXXXX url=http://127.0.0.1:XXXXX

# 2. Proteger y abrir (en otra terminal, con la URL del paso 1)
export SMART_TOKEN_API_URL=http://127.0.0.1:XXXXX SMART_TOKEN_API_KEY=test-key
node --experimental-strip-types test/fake-smart-token/fake-smart-token-cli.ts protect doc.txt --master secreto
node --experimental-strip-types test/fake-smart-token/fake-smart-token-cli.ts open <artifact-id> --master secreto -o doc.out
node --experimental-strip-types test/fake-smart-token/fake-smart-token-cli.ts status <artifact-id>
```

## Smoke e2e del visor

```sh
npm run smoke:viewer-e2e
```

Levanta la fake en un puerto efímero, crea un paquete TDCP en modo
`smart-token-custody` contra ella con el custodio HTTP real
(`HttpSmartTokenCekCustodian` + `SmartTokenClient`), corre el CLI real
del visor (`src/viewer/offline-viewer-cli.ts --export-offline`) con
`SMART_TOKEN_API_URL` apuntando a la fake, y verifica con el runtime
embebido del HTML que la contraseña correcta abre y la incorrecta es
DENIED, además de que con la fake caída el CLI falla cerrado. Sin
servicio real, sin red externa. El mismo test corre dentro de `npm test`.
