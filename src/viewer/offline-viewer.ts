/**
 * Generador del Visor HTML Offline autocontenido para TDCP.
 *
 * Decision de diseno (obligatoria, documentada en docs/OFFLINE_VIEWER.md):
 * el generador corre en linea, con la contrasena maestra del emisor. Pide la
 * CEK al custodio Smart Token (openCek), la re-envuelve bajo una llave
 * derivada de la contrasena maestra (PBKDF2-SHA256 + AES-256-GCM) y embebe
 * la CEK ENVUELTA en el HTML. El visor offline nunca contacta al servicio
 * Smart Token ni al Oracle: deriva la llave con la contrasena que teclea el
 * receptor, desenvuelve la CEK en memoria y descifra el paquete.
 *
 * Esto es una EXPORTACION deliberada del emisor: una vez entregado el HTML,
 * la revocacion remota ya no aplica y la seguridad del HTML descansa en la
 * contrasena maestra. Por eso el generador exige el flag explicito
 * `exportOffline` (CLI: --export-offline) y falla cerrado si el paquete no
 * esta en modo smart-token-custody, si el sello CSG no verifica o si no hay
 * custodio configurado.
 *
 * No se toca Gatekeeper, Oracle ni Authority: este modulo solo lee un
 * paquete ya creado y produce un HTML autocontenido.
 */

import { readFileSync } from 'node:fs';
import * as nodeCrypto from 'node:crypto';
import {
  arrayBufferToBase64,
  TDCP_DEFAULT_PBKDF2_ITERATIONS,
  wipeBuffer,
} from '../core/crypto/primitives.ts';
import {
  canonicalPackageEnvelopeBytes,
  deserializeTDCPPackage,
  type TDCPPackage,
} from '../core/package/package-format.ts';
import {
  csgClientFromEnv,
  CsgClient,
  type CsgRemoteSeal,
} from '../protection/csg-client.ts';
import {
  isLocalCsgSeal,
  isRemoteCsgSeal,
} from '../protection/csg-seal.ts';
import { verifyLocalCsgSeal } from '../protection/csg-local-seal.ts';
import type { SmartTokenCekCustodian } from '../protection/smart-token-cek-custody.ts';
import type { PolicyBinding } from '../channel/policy-binding.ts';
import {
  canonicalJsonPython,
  CEK_WRAP_AAD_PREFIX,
  OFFLINE_VIEWER_FORMAT,
  verifyPolicyBinding,
  verifyRemoteSeal,
} from './viewer-runtime.ts';

/** Tokens que jamas deben aparecer en el HTML emitido (sin URLs ni red). */
export const OFFLINE_VIEWER_FORBIDDEN_TOKENS = [
  'http://',
  'https://',
  '//cdn',
  'fetch',
  'XMLHttpRequest',
  'WebSocket',
  'localStorage',
  'IndexedDB',
  'import(',
] as const;

/** Salt aleatorio para envolver la CEK (>= 16 bytes exigidos). */
export const OFFLINE_VIEWER_WRAP_SALT_BYTES = 32;

export interface BuildOfflineViewerOptions {
  pkg: TDCPPackage;
  masterPassword: string;
  cekCustodian: SmartTokenCekCustodian;
  /** Flag explicito de exportacion: sin el, el generador se niega. */
  exportOffline: boolean;
  policyBinding?: PolicyBinding;
  authorityPublicKeySpkiBase64?: string;
  /** Llave publica del Notario (hex, 32 bytes) para verificar sellos remotos sin sidecar. */
  notaryPublicKeyHex?: string;
  /** URL del sidecar CSG; si no se da, se usa CSG_SEAL_URL del entorno. */
  csgSealUrl?: string;
  /**
   * 'required' (defecto): sin sello CSG valido no se genera nada.
   * 'optional': sin sello se genera igual y el visor lo registra como
   * "sin sello"; un sello presente pero invalido siempre falla.
   */
  sealMode?: 'required' | 'optional';
}

export interface OfflineViewerPayload {
  format: typeof OFFLINE_VIEWER_FORMAT;
  version: 1;
  generatedAt: number;
  sealRequired: boolean;
  sealStatus: 'sealed-valid' | 'absent';
  pkg: TDCPPackage;
  wrappedCekBase64: string;
  wrapSaltBase64: string;
  wrapIvBase64: string;
  wrapIterations: number;
  wrapAad: string;
  notaryPublicKeyHex?: string;
  authorityPublicKeySpkiBase64?: string;
  policyBinding?: PolicyBinding;
}

const encoder = new TextEncoder();

/**
 * Verifica un sello remoto (csg.sello.v1) con Node crypto, con el MISMO
 * algoritmo que el sidecar: SHA3-256 del sobre canonico, cuerpo_hash =
 * SHA3-256 del JSON canonico del cuerpo, Ed25519 sobre los bytes UTF-8 del
 * string hex de cuerpo_hash. Independiente de la implementacion pura-JS del
 * runtime: el generador exige que ambas coincidan.
 */
export function verifyRemoteSealWithNodeCrypto(
  envelopeBytes: Uint8Array,
  seal: CsgRemoteSeal,
  notaryPublicKeyHex: string
): { valid: boolean; reason: string } {
  if (seal.schema !== 'csg.sello.v1') return { valid: false, reason: 'UNKNOWN_SEAL_SCHEMA' };
  if (seal.aceptado !== true) return { valid: false, reason: 'SEAL_NOT_ACCEPTED' };
  const hashContenido = nodeCrypto.createHash('sha3-256').update(envelopeBytes).digest('hex');
  if (hashContenido !== seal.hash_contenido) {
    return { valid: false, reason: 'CONTENT_DIGEST_MISMATCH' };
  }
  const cuerpo = {
    evento_id: seal.evento_id,
    aceptado: seal.aceptado,
    razon: seal.razon ?? '',
    timestamp: seal.timestamp,
    hash_contenido: seal.hash_contenido,
    firmante_pub: seal.firmante_pub,
    sello_anterior: seal.sello_anterior,
  };
  const cuerpoHash = nodeCrypto
    .createHash('sha3-256')
    .update(canonicalJsonPython(cuerpo), 'utf8')
    .digest('hex');
  if (cuerpoHash !== seal.cuerpo_hash) return { valid: false, reason: 'CUERPO_HASH_MISMATCH' };
  // La llave fijada por el operador manda sobre la que trae el propio sello:
  // si no, el sello seria auto-certificante y fijar la llave no serviria.
  const pubHex = notaryPublicKeyHex || seal.notario_pub || '';
  if (!/^[0-9a-fA-F]{64}$/.test(pubHex)) {
    return { valid: false, reason: 'NOTARY_PUBKEY_MISSING' };
  }
  try {
    const derPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const key = nodeCrypto.createPublicKey({
      key: Buffer.concat([derPrefix, Buffer.from(pubHex, 'hex')]),
      format: 'der',
      type: 'spki',
    });
    const ok = nodeCrypto.verify(
      null,
      Buffer.from(cuerpoHash, 'utf8'),
      key,
      Buffer.from(seal.firma_notario, 'hex')
    );
    return ok ? { valid: true, reason: 'OK' } : { valid: false, reason: 'SIGNATURE_INVALID' };
  } catch {
    return { valid: false, reason: 'VERIFY_ERROR' };
  }
}

/** Lee el runtime del visor y lo deja listo para incrustar (sin `export`). */
export function loadViewerRuntimeSource(): string {
  const raw = readFileSync(new URL('./viewer-runtime.ts', import.meta.url), 'utf8');
  const stripped = raw
    .split('\n')
    .map((line) => line.replace(/^export /, ''))
    .join('\n');
  if (/^\s*import\s/m.test(stripped) || /^\s*export\s/m.test(stripped)) {
    throw new Error(
      'OFFLINE_VIEWER_RUNTIME_SOURCE_INVALID: el runtime del visor contiene import/export tras el pelado'
    );
  }
  return stripped;
}

export function assertNoForbiddenTokens(html: string): void {
  const lower = html.toLowerCase();
  for (const token of OFFLINE_VIEWER_FORBIDDEN_TOKENS) {
    if (lower.includes(token.toLowerCase())) {
      throw new Error(`OFFLINE_VIEWER_FORBIDDEN_TOKEN: el HTML emitido contiene "${token}"`);
    }
  }
}

function buildOfflineViewerHtml(payloadB64: string, runtimeSource: string): string {
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src blob:; media-src blob:; frame-src blob:; font-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>Visor TDCP offline</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;padding:24px;background:#111827;color:#f9fafb}
#tdcp-app{max-width:900px;margin:0 auto}
.tdcp-title{font-size:22px;margin:0 0 8px}
.tdcp-sub{color:#d1d5db}
.tdcp-status{color:#fbbf24;white-space:pre-wrap}
.tdcp-closed{font-size:18px}
form{display:flex;flex-direction:column;gap:8px;max-width:420px}
input[type=password]{padding:10px;font-size:16px;border-radius:6px;border:1px solid #4b5563;background:#1f2937;color:#f9fafb}
button{padding:10px 16px;font-size:16px;border-radius:6px;border:0;background:#2563eb;color:#fff;cursor:pointer}
button.tdcp-close{margin-top:16px;background:#374151}
#tdcp-content{position:relative;margin-top:16px}
.tdcp-view{position:relative;z-index:1;background:#fff;color:#111827;border-radius:8px;padding:16px}
.tdcp-text{white-space:pre-wrap;word-break:break-word;font-size:14px}
.tdcp-media{max-width:100%;max-height:75vh;display:block;margin:0 auto}
.tdcp-audio{width:100%}
.tdcp-pdf{width:100%;height:75vh;border:0}
.tdcp-download{color:#2563eb}
.tdcp-wm{position:absolute;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.tdcp-wm-tile{position:absolute;transform:rotate(-30deg);opacity:.07;font-size:11px;white-space:nowrap;color:#000}
</style>
</head>
<body>
<div id="tdcp-app"></div>
<script id="tdcp-offline-data" type="application/json">${payloadB64}</script>
<script id="tdcp-viewer-runtime">
${runtimeSource}
</script>
</body>
</html>
`;
}

/**
 * Construye el HTML autocontenido del visor offline.
 *
 * Falla cerrado (lanza) si: no se paso exportOffline, la contrasena esta
 * vacia, no hay custodio, el paquete no es valido, no esta en modo
 * smart-token-custody, es ULTRA_CRITICAL (fragmentos A/B/C no soportados
 * por el visor), el sello CSG falta en modo required o no verifica, el
 * PolicyBinding es invalido o caducado, o el custodio deniega la CEK.
 * Nunca registra la contrasena ni la CEK en claro.
 */
export async function buildOfflineViewer(options: BuildOfflineViewerOptions): Promise<string> {
  if (!options.exportOffline) {
    throw new Error(
      'OFFLINE_VIEWER_EXPORT_NOT_EXPLICIT: generar un visor offline es una exportacion deliberada; exige exportOffline: true (CLI: --export-offline)'
    );
  }
  if (!options.masterPassword) {
    throw new Error('OFFLINE_VIEWER_NO_MASTER: la contrasena maestra es obligatoria');
  }
  if (!options.cekCustodian) {
    throw new Error(
      'OFFLINE_VIEWER_NO_CUSTODIAN: sin custodio Smart Token configurado no se puede obtener la CEK; falla cerrada'
    );
  }

  const parsed = await deserializeTDCPPackage(JSON.stringify(options.pkg));
  if (!parsed.isValidEnvelope || !parsed.package) {
    throw new Error(`OFFLINE_VIEWER_BAD_PACKAGE: ${parsed.error ?? 'paquete invalido'}`);
  }
  const pkg = parsed.package;
  if (pkg.metadata?.custodyMode !== 'smart-token') {
    throw new Error(
      'OFFLINE_VIEWER_NOT_SMART_TOKEN_CUSTODY: el visor offline solo sirve para paquetes en modo smart-token-custody; los de modo grant siguen necesitando al Oracle'
    );
  }
  if (pkg.metadata?.policyLevel === 'ULTRA_CRITICAL') {
    throw new Error(
      'OFFLINE_VIEWER_ULTRA_CRITICAL_UNSUPPORTED: el visor offline no reconstruye fragmentos A/B/C'
    );
  }

  const sealMode = options.sealMode ?? 'required';
  const envelopeBytes = canonicalPackageEnvelopeBytes(pkg);
  let sealStatus: 'sealed-valid' | 'absent';
  if (pkg.csgSeal) {
    if (isRemoteCsgSeal(pkg.csgSeal)) {
      const client = options.csgSealUrl
        ? new CsgClient({ baseUrl: options.csgSealUrl })
        : csgClientFromEnv();
      let checked: { valid: boolean; reason: string };
      if (client) {
        const report = await client.verify(envelopeBytes, pkg.csgSeal);
        checked = {
          valid: report.todo_valido,
          reason: report.todo_valido ? 'OK' : 'REMOTE_VERIFY_FAILED',
        };
      } else if (options.notaryPublicKeyHex || pkg.csgSeal.notario_pub) {
        checked = verifyRemoteSealWithNodeCrypto(
          envelopeBytes,
          pkg.csgSeal,
          options.notaryPublicKeyHex ?? ''
        );
      } else {
        throw new Error(
          'OFFLINE_VIEWER_REMOTE_SEAL_UNVERIFIABLE: sello remoto sin sidecar CSG (CSG_SEAL_URL) ni llave publica del Notario; no se puede verificar y no se finge'
        );
      }
      if (!checked.valid) {
        throw new Error(`OFFLINE_VIEWER_SEAL_INVALID: ${checked.reason}`);
      }
      // Contraste: la implementacion pura-JS del runtime debe coincidir.
      const runtimeCheck = await verifyRemoteSeal(
        envelopeBytes,
        pkg.csgSeal,
        options.notaryPublicKeyHex ?? pkg.csgSeal.notario_pub ?? ''
      );
      if (!runtimeCheck.valid) {
        throw new Error(`OFFLINE_VIEWER_RUNTIME_SEAL_MISMATCH: ${runtimeCheck.reason}`);
      }
    } else if (isLocalCsgSeal(pkg.csgSeal)) {
      const r = await verifyLocalCsgSeal(envelopeBytes, pkg.csgSeal);
      if (!r.valid) {
        throw new Error(`OFFLINE_VIEWER_SEAL_INVALID: ${r.reason}`);
      }
    } else {
      throw new Error('OFFLINE_VIEWER_SEAL_INVALID: UNKNOWN_SEAL_SCHEMA');
    }
    sealStatus = 'sealed-valid';
  } else {
    if (sealMode === 'required') {
      throw new Error(
        'OFFLINE_VIEWER_SEAL_REQUIRED_MISSING: el paquete no trae sello CSG y el modo required lo exige'
      );
    }
    sealStatus = 'absent';
  }

  if (options.policyBinding) {
    if (!options.authorityPublicKeySpkiBase64) {
      throw new Error(
        'OFFLINE_VIEWER_BINDING_NO_AUTHORITY_KEY: con PolicyBinding se exige la SPKI de la Authority para verificarlo'
      );
    }
    const b = await verifyPolicyBinding(
      options.policyBinding,
      options.authorityPublicKeySpkiBase64,
      pkg.documentId
    );
    if (!b.valid) {
      throw new Error(`OFFLINE_VIEWER_BINDING_INVALID: ${b.reason}`);
    }
  }

  const release = await options.cekCustodian.openCek(
    pkg.smartTokenCustody!.artifactId,
    options.masterPassword
  );
  if (!release.ok) {
    throw new Error(
      `OFFLINE_VIEWER_SMART_TOKEN_DENIED: el custodio denego la CEK (status ${release.status}); sin CEK no hay visor`
    );
  }
  const cek = release.cek;
  if (!cek || cek.byteLength !== 32) {
    wipeBuffer(cek);
    throw new Error('OFFLINE_VIEWER_BAD_CEK: el custodio devolvio una CEK invalida');
  }

  let wrappedCek: ArrayBuffer;
  const wrapSalt = new Uint8Array(OFFLINE_VIEWER_WRAP_SALT_BYTES);
  const wrapIv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(wrapSalt);
  globalThis.crypto.getRandomValues(wrapIv);
  const wrapAadText = `${CEK_WRAP_AAD_PREFIX}|DOC=${pkg.documentId}|PKG=${pkg.packageId}`;
  try {
    const keyMaterial = await globalThis.crypto.subtle.importKey(
      'raw',
      encoder.encode(options.masterPassword),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    const bits = await globalThis.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: wrapSalt as unknown as BufferSource,
        iterations: TDCP_DEFAULT_PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      keyMaterial,
      256
    );
    const wrapKey = await globalThis.crypto.subtle.importKey(
      'raw',
      bits,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    wipeBuffer(new Uint8Array(bits));
    wrappedCek = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: wrapIv as unknown as BufferSource,
        tagLength: 128,
        additionalData: encoder.encode(wrapAadText) as unknown as BufferSource,
      },
      wrapKey,
      cek as unknown as BufferSource
    );
  } finally {
    wipeBuffer(cek);
  }

  const payload: OfflineViewerPayload = {
    format: OFFLINE_VIEWER_FORMAT,
    version: 1,
    generatedAt: Date.now(),
    sealRequired: sealMode === 'required',
    sealStatus,
    pkg,
    wrappedCekBase64: arrayBufferToBase64(wrappedCek),
    wrapSaltBase64: arrayBufferToBase64(wrapSalt),
    wrapIvBase64: arrayBufferToBase64(wrapIv),
    wrapIterations: TDCP_DEFAULT_PBKDF2_ITERATIONS,
    wrapAad: wrapAadText,
    ...(options.notaryPublicKeyHex
      ? { notaryPublicKeyHex: options.notaryPublicKeyHex }
      : pkg.csgSeal && isRemoteCsgSeal(pkg.csgSeal) && pkg.csgSeal.notario_pub
        ? { notaryPublicKeyHex: pkg.csgSeal.notario_pub }
        : {}),
    ...(options.authorityPublicKeySpkiBase64
      ? { authorityPublicKeySpkiBase64: options.authorityPublicKeySpkiBase64 }
      : {}),
    ...(options.policyBinding ? { policyBinding: options.policyBinding } : {}),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const runtimeSource = loadViewerRuntimeSource();
  const html = buildOfflineViewerHtml(payloadB64, runtimeSource);
  assertNoForbiddenTokens(html);
  return html;
}
