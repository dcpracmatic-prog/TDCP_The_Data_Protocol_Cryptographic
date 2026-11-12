# Visor HTML Offline autocontenido (TDCP)

Un solo archivo `.html` que abre un paquete TDCP sin servidor, sin red y sin
instalar nada: doble clic, contrasena maestra, documento. Sirve SOLO para
paquetes en modo `smart-token-custody`. Los paquetes de modo `grant` (modo
Oracle) siguen necesitando al Gatekeeper y al Oracle: este visor no los abre
y el generador los rechaza.

## Como funciona (en simple)

1. **El emisor protege el documento como siempre** (modo `smart-token`): la
   CEK vive custodiada por el servicio Smart Token, no en el paquete.
2. **El generador, en linea y con la contrasena maestra**, pide la CEK al
   custodio (`openCek`), la re-envuelve bajo una llave derivada de la
   contrasena maestra (PBKDF2-SHA256, 600.000 iteraciones, sal aleatoria de
   32 bytes; AES-256-GCM) y embebe la CEK ENVUELTA en el HTML, junto con el
   paquete completo, su sello CSG y, si se le da, el PolicyBinding.
3. **El receptor abre el HTML offline.** El visor, en este orden:
   - verifica el sello CSG sobre el sobre canonico recomputado desde el
     paquete embebido (remoto `csg.sello.v1`: SHA3-256 + Ed25519 en JS puro;
     local `tdcp.csg-local.v1`: ECDSA P-256 + SHA-256 con WebCrypto);
     sello invalido, desconocido o ausente en modo required → DENIED;
   - verifica el PolicyBinding si existe (hash SHA-256, firma ECDSA P-256,
     mismo `documentId`, caducidad); caducado o firma invalida → DENIED;
     sin binding abre igual y lo registra como "sin binding";
   - pide la contrasena maestra, deriva la llave con PBKDF2, desenvuelve la
     CEK en memoria y descifra el contenido con AES-256-GCM (AAD
     recomputado desde los metadatos); contrasena incorrecta → DENIED;
   - renderiza por MIME (texto, imagen, video, audio, PDF; resto solo
     descarga si `allowExtraction`) con marca forense en mosaico.
4. **Autodestruccion:** boton cerrar o temporizador de sesion (caducidad
   del binding o 15 minutos, lo que antes ocurra) → limpia las llaves
   (buffers a cero), revoca el objeto, vacia el DOM y limpia el input.

Cualquier fallo muestra el mismo mensaje opaco, "Acceso denegado", sin
distinguir si fallo el sello, el binding, la contrasena o el descifrado.

## Generar un visor

```sh
# La contrasena maestra SOLO por variable de entorno, nunca por argv.
export TDCP_MASTER='la-contrasena-del-emisor'
node --experimental-strip-types src/viewer/offline-viewer-cli.ts \
  --pkg documento.pkg.json --out documento.html \
  --master-env TDCP_MASTER --export-offline --seal-required \
  [--policy-binding binding.json --authority-spki-base64 <SPKI b64>] \
  [--notary-pubkey-hex <hex>] [--csg-seal-url <url>]
# o con npm:
npm run generate:offline-viewer -- --pkg documento.pkg.json --out documento.html \
  --master-env TDCP_MASTER --export-offline --seal-required
```

El custodio Smart Token se resuelve del entorno (`SMART_TOKEN_API_URL` /
`SMART_TOKEN_API_KEY`); sin el, el comando falla cerrado. El flag
`--export-offline` es obligatorio: generar el HTML es una exportacion
deliberada y no debe ocurrir por accidente.

El generador falla cerrado si: el paquete no es `smart-token-custody`, es
`ULTRA_CRITICAL` (fragmentos A/B/C no soportados por el visor), el sello CSG
falta en modo required o no verifica (remoto: sidecar si hay URL, si no
Node crypto con la llave del Notario; local: verificacion WebCrypto), el
PolicyBinding es invalido o caducado, o el custodio deniega la CEK.
Ademas exige que la implementacion pura-JS del runtime coincida con la
verificacion Node crypto del sello remoto, y rechaza el HTML si contiene
cualquier token prohibido (`http://`, `https://`, `//cdn`, `fetch`,
`XMLHttpRequest`, `WebSocket`, `localStorage`, `IndexedDB`, `import(`).

## Que verifica el visor, exactamente

| Capa | Algoritmo | Fuente de verdad |
|---|---|---|
| Sello remoto `csg.sello.v1` | SHA3-256 del sobre canonico; `cuerpo_hash` = SHA3-256 del JSON canonico del cuerpo; Ed25519 sobre los bytes UTF-8 del hex de `cuerpo_hash` | `server/csg-sidecar/main.py` |
| Sello local `tdcp.csg-local.v1` | SHA-256 del contenido; firma sobre `digest\|label\|createdAt\|attrs` | `src/protection/csg-local-seal.ts` |
| Sobre canonico | `JSON.stringify` con orden fijo de campos, sin `csgSeal` | `canonicalPackageEnvelopeString` |
| AAD | `TDCP-AAD-v2.5\|DOC=…\|PKG=…\|VER=…\|POLICY=…\|EXTRACT=…\|EXP_DAYS=…\|VIEW_ONCE=…\|KDF_ITERS=…` | `createAADBytes` |
| CEK envuelta | PBKDF2-SHA256 (600.000 it.) + AES-256-GCM, AAD `TDCP-OFFLINE-CEK-WRAP-v1\|DOC=…\|PKG=…` | este modulo |
| PolicyBinding | SHA-256 de `policyCanonical`, ECDSA P-256 DER, `documentId`, caducidad | `src/channel/policy-binding.ts` |

SHA3-256 y Ed25519 estan implementados en JS puro con BigInt dentro del
propio HTML (`src/viewer/viewer-runtime.ts`), porque WebCrypto no ofrece
SHA3 ni Ed25519. Ambos estan contrastados contra Node crypto y contra un
sello REAL del sidecar (vector `SIDECAR-VECTOR-1` en
`src/viewer/offline-viewer.test.ts`, verificado ademas con
`POST /v1/verify` del sidecar: `todo_valido: true`).

## Limites honestos

- **Sin revocacion remota offline.** Una vez entregado el HTML (y conocida
  la contrasena), revocar el documento en el Oracle o en Smart Token ya no
  impide abrir ESA copia. La revocacion solo vale antes de generar el HTML
  (el generador pide la CEK en ese momento y el custodio puede denegarla).
- **La seguridad del HTML descansa en la contrasena maestra.** Quien tenga
  el archivo y la contrasena abre el documento. La contrasena debe
  entregarse por un canal distinto al del archivo, y debe ser fuerte:
  PBKDF2 con 600.000 iteraciones frena, no impide, un ataque de diccionario
  contra una contrasena debil.
- **La caducidad del binding limita la ventana, no es revocacion.** Sin
  PolicyBinding embebido no hay ventana: solo el temporizador de 15 minutos
  de sesion. Con binding, la sesion se cierra en su caducidad o a los 15
  minutos, lo antes.
- **La captura no se puede impedir del todo.** Blur al perder el foco,
  bloqueo de Ctrl+P/S/C, sin menu contextual y marca forense en mosaico son
  mitigaciones; una foto con otro dispositivo o una captura a nivel de
  sistema operativo quedan fuera de lo que un HTML puede impedir.
- **El visor no sustituye al Gatekeeper.** No hay grants de un solo uso,
  ni anti-replay, ni registro de auditoria, ni control de dispositivo,
  ni revocacion por epocas. Es un canal de entrega offline para un receptor
  concreto, no el camino normal de apertura.
- **Solo `smart-token-custody`, solo paquetes normales.** Ni modo `grant`,
  ni `ULTRA_CRITICAL`. El visor nunca contacta al servicio Smart Token ni
  al Oracle: si la CEK envuelta no se puede desenvolver con la contrasena,
  no hay otro camino.

## Archivos

- `src/viewer/viewer-runtime.ts` — runtime autocontenido (JS plano, sin
  dependencias): SHA3-256 y Ed25519 puros, verificacion de sellos y de
  binding, apertura y arranque DOM. El generador incrusta este mismo texto
  en el HTML; por eso no lleva anotaciones TypeScript ni imports.
- `src/viewer/offline-viewer.ts` — generador (`buildOfflineViewer`) y
  verificacion del sello remoto con Node crypto.
- `src/viewer/offline-viewer-cli.ts` — CLI (`npm run generate:offline-viewer`).
- `src/viewer/offline-viewer.test.ts` — tests (`node:test`, en la lista de
  `npm test`).

## Smoke e2e contra la FAKE Smart Token (sin servicio real)

`test/fake-smart-token/` es un doble en memoria del servicio HTTP Smart
Token Prod v0.10.5, solo para pruebas: servidor (`fake-smart-token-server.mjs`)
+ CLI (`fake-smart-token-cli.ts`, espeja los 9 subcomandos reales +
`serve`) + tests + smoke e2e del visor. Detalle completo, correspondencia
fake-vs-real y límites en `test/fake-smart-token/README.md`.

```sh
npm run smoke:viewer-e2e   # también corre dentro de npm test
```

Levanta la fake en un puerto efímero, crea un paquete en modo
`smart-token-custody` contra ella con el custodio HTTP real, corre este
CLI con `SMART_TOKEN_API_URL` apuntando a la fake, y verifica con el
runtime embebido que la contraseña correcta abre y la incorrecta es
DENIED; con la fake caída (`--down` o `POST /__fake__/down`) el CLI
falla cerrado. La fake guarda el blob envuelto (PBKDF2 + AES-256-GCM,
del master solo su SHA-256) y **no** imita ML-KEM-768, Argon2id, la
validation ladder ni el hang de fase 3: ver README.

**Canónico:** este es el único smoke de punta a punta del visor. No existe
ningún smoke contra un despliegue externo: la suite completa y este e2e
corren sin ninguna credencial real configurada, solo con la fake local y
llaves efímeras generadas al vuelo (ver `docs/SOVEREIGN_ARCHITECTURE.md`).

## Smoke manual contra el sidecar local

El sidecar necesita el paquete Python `cryptography` (el Python del
sistema lo bloquea por PEP 668; usar un venv):

```sh
python3 -m venv /tmp/csg-venv && /tmp/csg-venv/bin/pip install cryptography
CSG_DATA_DIR=/tmp/csg-smoke CSG_PORT=8019 /tmp/csg-venv/bin/python server/csg-sidecar/main.py
curl -s http://127.0.0.1:8019/v1/status
```

Con el sidecar en marcha, generar un visor con `--csg-seal-url
http://127.0.0.1:8019` hace que el generador verifique el sello contra el
Notario en vivo en vez de con Node crypto. Los tests ya incluyen un vector
de sello real del sidecar, asi que este paso es confirmacion, no requisito.
