// @ts-nocheck
/**
 * TDCP Offline Viewer — runtime autocontenido (JS plano, sin dependencias).
 *
 * Este archivo es deliberadamente JavaScript plano SIN anotaciones de
 * TypeScript, SIN imports y SIN exports con nombre de bloque: el generador
 * (offline-viewer.ts) incrusta este mismo texto dentro del HTML emitido,
 * quitando solo el prefijo `export ` de cada declaracion. Por eso:
 * - No usar sintaxis que un navegador no entienda (tipos, `as`, enums).
 * - No usar llamadas de red ni almacenamiento persistente de ningun tipo.
 * - No mencionar en comentarios ni en cadenas los mecanismos prohibidos.
 *
 * Lo que hace, en orden: verifica el sello CSG sobre el sobre canonico,
 * verifica el PolicyBinding si existe, pide la contrasena maestra, deriva
 * la llave con PBKDF2, desenvuelve la CEK, descifra el paquete con
 * AES-256-GCM (AAD recomputado) y renderiza por MIME con marca forense.
 * Cualquier fallo devuelve DENIED opaco: el mismo mensaje para todos los
 * motivos, sin distinguir sello, binding, contrasena o descifrado.
 *
 * Solo WebCrypto (SHA-256, SHA-512, PBKDF2, AES-GCM, ECDSA P-256) mas
 * SHA3-256 y Ed25519 implementados aqui en JS puro con BigInt, porque
 * WebCrypto no ofrece SHA3 ni Ed25519.
 */

// ---------------------------------------------------------------------------
// Utilidades de bytes / base64 / hex (implementacion manual, sin atob/btoa)
// ---------------------------------------------------------------------------

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_REVERSE = {};
for (let i = 0; i < 64; i++) B64_REVERSE[B64_ALPHABET[i]] = i;

export function b64encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64_ALPHABET[b0 >> 2];
    out += B64_ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64_ALPHABET[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < bytes.length ? B64_ALPHABET[b2 & 63] : '=';
  }
  return out;
}

export function b64decode(str) {
  const clean = String(str).replace(/\s/g, '');
  if (clean.length % 4 !== 0) throw new Error('INVALID_BASE64');
  let pad = 0;
  if (clean.endsWith('==')) pad = 2;
  else if (clean.endsWith('=')) pad = 1;
  const outLen = (clean.length / 4) * 3 - pad;
  const out = new Uint8Array(outLen);
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const n =
      (B64_REVERSE[clean[i]] << 18) |
      (B64_REVERSE[clean[i + 1]] << 12) |
      ((B64_REVERSE[clean[i + 2]] || 0) << 6) |
      (B64_REVERSE[clean[i + 3]] || 0);
    if (o < outLen) out[o++] = (n >> 16) & 255;
    if (o < outLen) out[o++] = (n >> 8) & 255;
    if (o < outLen) out[o++] = n & 255;
  }
  return out;
}

const HEX_TABLE = [];
for (let i = 0; i < 256; i++) HEX_TABLE.push(i.toString(16).padStart(2, '0'));

export function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += HEX_TABLE[bytes[i]];
  return hex;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('INVALID_HEX');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function concatBytes(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function wipeBytes(buf) {
  if (!buf) return;
  try {
    const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    view.fill(0);
  } catch (_e) {
    /* buffer de solo lectura: no se puede limpiar */
  }
}

function utf8Encode(str) {
  return new TextEncoder().encode(str);
}

function subtleCrypto() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error('WEBCRYPTO_UNAVAILABLE');
  return c.subtle;
}

export async function sha256Hex(data) {
  const digest = await subtleCrypto().digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

export async function sha512Bytes(data) {
  const digest = await subtleCrypto().digest('SHA-512', data);
  return new Uint8Array(digest);
}

// ---------------------------------------------------------------------------
// SHA3-256 puro (Keccak-f[1600], rate 1088, suffix 0x06). BigInt para los
// carriles de 64 bits. Contrastado contra Node crypto sha3-256.
// ---------------------------------------------------------------------------

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_RHO = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const KECCAK_PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
const MASK64 = (1n << 64n) - 1n;

function keccakF1600(s) {
  for (let round = 0; round < 24; round++) {
    const c = new Array(5);
    for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    for (let x = 0; x < 5; x++) {
      const cx = c[(x + 4) % 5];
      const cn = c[(x + 1) % 5];
      const d = cx ^ (((cn << 1n) | (cn >> 63n)) & MASK64);
      for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d;
    }
    let t = s[1];
    for (let i = 0; i < 24; i++) {
      const j = KECCAK_PI[i];
      const tmp = s[j];
      const r = BigInt(KECCAK_RHO[i]);
      s[j] = ((t << r) | (t >> (64n - r))) & MASK64;
      t = tmp;
    }
    for (let y = 0; y < 5; y++) {
      const row0 = s[5 * y];
      const row1 = s[5 * y + 1];
      const row2 = s[5 * y + 2];
      const row3 = s[5 * y + 3];
      const row4 = s[5 * y + 4];
      s[5 * y] = row0 ^ (~row1 & row2);
      s[5 * y + 1] = row1 ^ (~row2 & row3);
      s[5 * y + 2] = row2 ^ (~row3 & row4);
      s[5 * y + 3] = row3 ^ (~row4 & row0);
      s[5 * y + 4] = row4 ^ (~row0 & row1);
    }
    s[0] ^= KECCAK_RC[round];
  }
}

export function sha3_256Bytes(data) {
  const rate = 136;
  const state = new Array(25).fill(0n);
  let offset = 0;
  const absorbBlock = (block, len) => {
    for (let i = 0; i < 17; i++) {
      let lane = 0n;
      for (let j = 0; j < 8; j++) {
        const idx = i * 8 + j;
        if (idx < len) lane |= BigInt(block[idx]) << BigInt(8 * j);
      }
      state[i] ^= lane;
    }
  };
  while (data.length - offset >= rate) {
    absorbBlock(data.subarray(offset, offset + rate), rate);
    keccakF1600(state);
    offset += rate;
  }
  const last = new Uint8Array(rate);
  const rem = data.length - offset;
  last.set(data.subarray(offset));
  last[rem] ^= 0x06;
  last[rate - 1] ^= 0x80;
  absorbBlock(last, rate);
  keccakF1600(state);
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const lane = state[i];
    for (let j = 0; j < 8; j++) out[i * 8 + j] = Number((lane >> BigInt(8 * j)) & 0xffn);
  }
  return out;
}

export function sha3_256Hex(data) {
  return bytesToHex(sha3_256Bytes(data));
}

// ---------------------------------------------------------------------------
// Ed25519 puro (RFC 8032), coordenadas extendidas, aritmetica BigInt.
// El hash SHA-512 se toma de WebCrypto; el resto es JS puro.
// ---------------------------------------------------------------------------

const ED_P = (1n << 255n) - 19n;
const ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED_I = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;

function modP(x) {
  const r = x % ED_P;
  return r >= 0n ? r : r + ED_P;
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

function modInv(a) {
  return modPow(a, ED_P - 2n, ED_P);
}

function sqrtModP(u) {
  let x = modPow(u, (ED_P + 3n) / 8n, ED_P);
  if (modP(x * x - u) !== 0n) x = modP(x * ED_I);
  if (modP(x * x - u) !== 0n) return null;
  return x;
}

function xRecover(y, signBit) {
  const yy = modP(y * y);
  const xx = modP((yy - 1n) * modInv(modP(ED_D * yy + 1n)));
  let x = sqrtModP(xx);
  if (x === null) return null;
  if ((x & 1n) !== BigInt(signBit)) x = ED_P - x;
  return x;
}

function edPoint(x, y) {
  return { X: modP(x), Y: modP(y), Z: 1n, T: modP(x * y) };
}

function edIdentity() {
  return { X: 0n, Y: 1n, Z: 1n, T: 0n };
}

function edAdd(P, Q) {
  const A = modP((P.Y - P.X) * (Q.Y - Q.X));
  const B = modP((P.Y + P.X) * (Q.Y + Q.X));
  const C = modP(P.T * 2n * ED_D * Q.T);
  const D = modP(P.Z * 2n * Q.Z);
  const E = modP(B - A);
  const F = modP(D - C);
  const G = modP(D + C);
  const H = modP(B + A);
  return { X: modP(E * F), Y: modP(G * H), T: modP(E * H), Z: modP(F * G) };
}

function edDouble(P) {
  const A = modP(P.X * P.X);
  const B = modP(P.Y * P.Y);
  const C = modP(2n * P.Z * P.Z);
  const D = modP(-A);
  const E = modP((P.X + P.Y) * (P.X + P.Y) - A - B);
  const G = modP(D + B);
  const F = modP(G - C);
  const H = modP(D - B);
  return { X: modP(E * F), Y: modP(G * H), T: modP(E * H), Z: modP(F * G) };
}

export function edScalarMult(P, e) {
  let Q = edIdentity();
  for (let i = 255; i >= 0; i--) {
    Q = edDouble(Q);
    if ((e >> BigInt(i)) & 1n) Q = edAdd(Q, P);
  }
  return Q;
}

let ED_BASE = null;
export function edBasePoint() {
  if (ED_BASE) return ED_BASE;
  const by = modP(4n * modInv(5n));
  const bx = xRecover(by, 0);
  if (bx === null) throw new Error('ED25519_BASE_POINT_ERROR');
  ED_BASE = edPoint(bx, by);
  return ED_BASE;
}

export function edDecodePoint(bytes) {
  if (bytes.length !== 32) return null;
  const yBytes = bytes.slice(0);
  const signBit = (yBytes[31] >> 7) & 1;
  yBytes[31] &= 0x7f;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(yBytes[i]);
  const x = xRecover(y, signBit);
  if (x === null) return null;
  return edPoint(x, y);
}

export function edEncodePoint(P) {
  const zInv = modInv(P.Z);
  const x = modP(P.X * zInv);
  const y = modP(P.Y * zInv);
  const out = new Uint8Array(32);
  let v = y;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (x & 1n) out[31] |= 0x80;
  return out;
}

function leBytesToInt(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

export async function ed25519Verify(pubBytes, msgBytes, sigBytes) {
  if (!pubBytes || pubBytes.length !== 32) return false;
  if (!sigBytes || sigBytes.length !== 64) return false;
  const R = edDecodePoint(sigBytes.slice(0, 32));
  if (!R) return false;
  const A = edDecodePoint(pubBytes);
  if (!A) return false;
  const S = leBytesToInt(sigBytes.slice(32, 64));
  if (S >= ED_L) return false;
  const hBytes = await sha512Bytes(concatBytes([sigBytes.slice(0, 32), pubBytes, msgBytes]));
  const h = leBytesToInt(hBytes) % ED_L;
  const sB = edScalarMult(edBasePoint(), S);
  const hA = edScalarMult(A, h);
  const rPlusHA = edAdd(R, hA);
  return bytesEqual(edEncodePoint(sB), edEncodePoint(rPlusHA));
}

// ---------------------------------------------------------------------------
// Canonico JSON estilo Python: json.dumps(sort_keys=True,
// separators=(",", ":"), ensure_ascii=False). Solo lo necesitan los campos
// del cuerpo del sello remoto (ASCII), pero la implementacion es general.
// ---------------------------------------------------------------------------

export function canonicalJsonPython(value) {
  if (value === null) return 'null';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('UNSUPPORTED_CANONICAL_VALUE');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJsonPython).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJsonPython(value[k])).join(',') + '}';
  }
  throw new Error('UNSUPPORTED_CANONICAL_VALUE');
}

// ---------------------------------------------------------------------------
// Sobre canonico del paquete: EXACTAMENTE el mismo orden de campos que
// canonicalPackageEnvelopeString en src/core/package/package-format.ts.
// El sello CSG cubre esta cadena; el visor la recomputa desde el paquete
// embebido y cualquier byte alterado invalida el sello.
// ---------------------------------------------------------------------------

export function canonicalPackageEnvelope(pkg) {
  return JSON.stringify({
    magicHeader: pkg.magicHeader,
    version: pkg.version,
    algorithm: pkg.algorithm,
    documentId: pkg.documentId,
    packageId: pkg.packageId,
    saltBase64: pkg.saltBase64,
    ivBase64: pkg.ivBase64,
    ciphertextBase64: pkg.ciphertextBase64,
    aadBase64: pkg.aadBase64,
    metadata: pkg.metadata,
    wrappedKeyBase64: pkg.wrappedKeyBase64 ?? '',
    ivKeyBase64: pkg.ivKeyBase64 ?? '',
    envelopeEpoch: pkg.envelopeEpoch,
    ultraCritical: pkg.ultraCritical ?? null,
    ...(pkg.smartTokenCustody ? { smartTokenCustody: pkg.smartTokenCustody } : {}),
  });
}

// ---------------------------------------------------------------------------
// AAD: EXACTAMENTE createAADBytes en src/core/package/package-format.ts.
// ---------------------------------------------------------------------------

export function computeAadBytes(pkg) {
  const m = pkg.metadata || {};
  const aadString = [
    'TDCP-AAD-v2.5',
    'DOC=' + pkg.documentId,
    'PKG=' + pkg.packageId,
    'VER=' + pkg.version,
    'POLICY=' + (m.policyLevel !== undefined ? m.policyLevel : 'UNSPECIFIED'),
    'EXTRACT=' + (m.allowExtraction ? '1' : '0'),
    'EXP_DAYS=' + (m.expirationDays !== undefined ? String(m.expirationDays) : ''),
    'VIEW_ONCE=' + (m.viewOnce ? '1' : '0'),
    'KDF_ITERS=' + (m.kdfIterations !== undefined ? String(m.kdfIterations) : '600000'),
  ].join('|');
  return utf8Encode(aadString);
}

// ---------------------------------------------------------------------------
// Verificacion del sello CSG remoto (csg.sello.v1, produccion).
// Algoritmo exacto del sidecar server/csg-sidecar/main.py:
// hash_contenido = SHA3-256(sobre canonico); cuerpo = {evento_id,
// aceptado, razon, timestamp, hash_contenido, firmante_pub,
// sello_anterior}; cuerpo_hash = SHA3-256(canonico_json(cuerpo));
// firma_notario = Ed25519(clave_notario, cuerpo_hash.encode utf-8).
// ---------------------------------------------------------------------------

export async function verifyRemoteSeal(envelopeBytes, seal, notaryPubHex) {
  if (!seal || typeof seal !== 'object') return { valid: false, reason: 'SEAL_MISSING' };
  if (seal.schema !== 'csg.sello.v1') return { valid: false, reason: 'UNKNOWN_SEAL_SCHEMA' };
  if (seal.aceptado !== true) return { valid: false, reason: 'SEAL_NOT_ACCEPTED' };
  const hashContenido = sha3_256Hex(envelopeBytes);
  if (hashContenido !== seal.hash_contenido) return { valid: false, reason: 'CONTENT_DIGEST_MISMATCH' };
  const cuerpo = {
    evento_id: seal.evento_id,
    aceptado: seal.aceptado,
    razon: seal.razon !== undefined ? seal.razon : '',
    timestamp: seal.timestamp,
    hash_contenido: seal.hash_contenido,
    firmante_pub: seal.firmante_pub,
    sello_anterior: seal.sello_anterior,
  };
  let cuerpoHash;
  try {
    cuerpoHash = sha3_256Hex(utf8Encode(canonicalJsonPython(cuerpo)));
  } catch (_e) {
    return { valid: false, reason: 'CUERPO_CANONICAL_ERROR' };
  }
  if (cuerpoHash !== seal.cuerpo_hash) return { valid: false, reason: 'CUERPO_HASH_MISMATCH' };
  // La llave fijada por el operador manda sobre la que trae el propio sello:
  // si no, el sello seria auto-certificante y fijar la llave no serviria.
  const pubHex = notaryPubHex || seal.notario_pub || '';
  if (!/^[0-9a-fA-F]{64}$/.test(pubHex)) return { valid: false, reason: 'NOTARY_PUBKEY_MISSING' };
  let ok = false;
  try {
    ok = await ed25519Verify(hexToBytes(pubHex), utf8Encode(cuerpoHash), hexToBytes(seal.firma_notario));
  } catch (_e) {
    return { valid: false, reason: 'VERIFY_ERROR' };
  }
  return ok ? { valid: true, reason: 'OK' } : { valid: false, reason: 'SIGNATURE_INVALID' };
}

// ---------------------------------------------------------------------------
// Verificacion del sello CSG local (tdcp.csg-local.v1, desarrollo).
// Algoritmo exacto de src/protection/csg-local-seal.ts: contentDigest =
// SHA-256(contenido); se firma `${contentDigest}|${label}|${createdAt}|`
// mas los atributos ordenados `k=v` unidos con `&`, ECDSA P-256 + SHA-256.
// ---------------------------------------------------------------------------

export async function verifyLocalSeal(envelopeBytes, seal) {
  if (!seal || typeof seal !== 'object') return { valid: false, reason: 'SEAL_MISSING' };
  if (seal.schema !== 'tdcp.csg-local.v1') return { valid: false, reason: 'UNKNOWN_SEAL_SCHEMA' };
  const digest = await sha256Hex(envelopeBytes);
  if (digest !== seal.contentDigest) return { valid: false, reason: 'CONTENT_DIGEST_MISMATCH' };
  try {
    const keys = Object.keys(seal.attributes || {}).sort();
    const attrStr = keys.map((k) => k + '=' + seal.attributes[k]).join('&');
    const toSign = utf8Encode(seal.contentDigest + '|' + seal.label + '|' + seal.createdAt + '|' + attrStr);
    const key = await subtleCrypto().importKey(
      'spki',
      b64decode(seal.publicKeySpkiBase64),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const ok = await subtleCrypto().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      b64decode(seal.signatureBase64),
      toSign
    );
    return ok ? { valid: true, reason: 'OK' } : { valid: false, reason: 'SIGNATURE_INVALID' };
  } catch (_e) {
    return { valid: false, reason: 'VERIFY_ERROR' };
  }
}

// ---------------------------------------------------------------------------
// Verificacion del PolicyBinding (Authority ECDSA P-256 + SHA-256).
// Algoritmo exacto de src/channel/policy-binding.ts: policyHash = SHA-256
// hex de policyCanonical; firma DER sobre policyCanonical utf-8.
// ---------------------------------------------------------------------------

export async function verifyPolicyBinding(binding, authoritySpkiB64, documentId) {
  if (!binding || typeof binding !== 'object') return { valid: false, reason: 'BINDING_MISSING' };
  if (!authoritySpkiB64) return { valid: false, reason: 'AUTHORITY_KEY_MISSING' };
  let hash;
  try {
    hash = await sha256Hex(utf8Encode(binding.policyCanonical));
  } catch (_e) {
    return { valid: false, reason: 'BINDING_HASH_ERROR' };
  }
  if (hash !== binding.policyHash) return { valid: false, reason: 'BINDING_HASH_MISMATCH' };
  let policy;
  try {
    policy = JSON.parse(binding.policyCanonical);
  } catch (_e) {
    return { valid: false, reason: 'BINDING_JSON_INVALID' };
  }
  if (
    !policy ||
    typeof policy.documentId !== 'string' ||
    typeof policy.grantId !== 'string' ||
    !policy.grantId ||
    !Number.isFinite(policy.expiry) ||
    !Array.isArray(policy.edges) ||
    policy.edges.length === 0
  ) {
    return { valid: false, reason: 'BINDING_POLICY_INVALID' };
  }
  if (documentId && policy.documentId !== documentId) {
    return { valid: false, reason: 'BINDING_DOCUMENT_MISMATCH' };
  }
  try {
    const key = await subtleCrypto().importKey(
      'spki',
      b64decode(authoritySpkiB64),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const ok = await subtleCrypto().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      b64decode(binding.signature),
      utf8Encode(binding.policyCanonical)
    );
    if (!ok) return { valid: false, reason: 'BINDING_SIGNATURE_INVALID' };
  } catch (_e) {
    return { valid: false, reason: 'BINDING_VERIFY_ERROR' };
  }
  if (Date.now() > policy.expiry) return { valid: false, reason: 'BINDING_EXPIRED' };
  return { valid: true, reason: 'OK', policy: policy };
}

// ---------------------------------------------------------------------------
// Apertura completa del visor. Devuelve { ok: true, ... } o
// { ok: false, reason: 'DENIED', detail: '<motivo interno>' }.
// El motivo interno NUNCA se muestra en la interfaz: la pantalla solo dice
// "Acceso denegado", igual para sello, binding, contrasena o descifrado.
// ---------------------------------------------------------------------------

export const OFFLINE_VIEWER_SESSION_MINUTES = 15;
export const OFFLINE_VIEWER_FORMAT = 'tdcp-offline-viewer-v1';
export const CEK_WRAP_AAD_PREFIX = 'TDCP-OFFLINE-CEK-WRAP-v1';

export async function openOfflineViewer(data, password) {
  const denied = (detail) => ({ ok: false, reason: 'DENIED', detail: detail });
  try {
    if (!data || data.format !== OFFLINE_VIEWER_FORMAT || !data.pkg) return denied('BAD_DATA');
    const pkg = data.pkg;
    if (
      pkg.magicHeader !== 'TDCP_SECURE_PKG' ||
      pkg.version !== '2.5-SEC' ||
      pkg.algorithm !== 'AES-256-GCM / HKDF-SHA256'
    ) {
      return denied('BAD_ENVELOPE');
    }
    if (!pkg.metadata || pkg.metadata.custodyMode !== 'smart-token') return denied('NOT_SMART_TOKEN_CUSTODY');
    if (!pkg.smartTokenCustody || !pkg.smartTokenCustody.artifactId) return denied('NO_CUSTODY_REF');
    if (pkg.metadata.policyLevel === 'ULTRA_CRITICAL') return denied('ULTRA_CRITICAL_UNSUPPORTED');
    if (!pkg.ciphertextBase64 || !pkg.ivBase64 || !pkg.saltBase64 || !pkg.aadBase64) {
      return denied('INCOMPLETE_PACKAGE');
    }

    const envelopeBytes = utf8Encode(canonicalPackageEnvelope(pkg));
    const sealInfo = { present: false, valid: null, schema: null };
    const seal = pkg.csgSeal;
    if (seal) {
      sealInfo.present = true;
      let r;
      if (seal.schema === 'csg.sello.v1') {
        sealInfo.schema = 'csg.sello.v1';
        r = await verifyRemoteSeal(envelopeBytes, seal, data.notaryPublicKeyHex);
      } else if (seal.schema === 'tdcp.csg-local.v1') {
        sealInfo.schema = 'tdcp.csg-local.v1';
        r = await verifyLocalSeal(envelopeBytes, seal);
      } else {
        return denied('UNKNOWN_SEAL_SCHEMA');
      }
      sealInfo.valid = r.valid;
      if (!r.valid) return denied('SEAL_INVALID:' + r.reason);
    } else if (data.sealRequired) {
      return denied('SEAL_REQUIRED_MISSING');
    }

    let policy = null;
    let sessionExpiresAt = Date.now() + OFFLINE_VIEWER_SESSION_MINUTES * 60 * 1000;
    if (data.policyBinding) {
      const b = await verifyPolicyBinding(data.policyBinding, data.authorityPublicKeySpkiBase64, pkg.documentId);
      if (!b.valid) return denied('BINDING_INVALID:' + b.reason);
      policy = b.policy;
      sessionExpiresAt = Math.min(sessionExpiresAt, policy.expiry);
    }

    if (typeof password !== 'string' || password.length === 0) return denied('EMPTY_PASSWORD');
    const iterations = data.wrapIterations;
    if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) {
      return denied('BAD_WRAP_ITERATIONS');
    }
    let wrapSalt;
    let wrapIv;
    let wrappedCek;
    try {
      wrapSalt = b64decode(data.wrapSaltBase64);
      wrapIv = b64decode(data.wrapIvBase64);
      wrappedCek = b64decode(data.wrappedCekBase64);
    } catch (_e) {
      return denied('BAD_WRAP_ENCODING');
    }
    if (wrapSalt.length < 16 || wrapIv.length !== 12 || wrappedCek.length === 0) {
      return denied('BAD_WRAP_PARAMS');
    }
    const wrapAadText = CEK_WRAP_AAD_PREFIX + '|DOC=' + pkg.documentId + '|PKG=' + pkg.packageId;
    if (data.wrapAad && data.wrapAad !== wrapAadText) return denied('WRAP_AAD_MISMATCH');

    let cekBytes = null;
    try {
      const subtle = subtleCrypto();
      const keyMaterial = await subtle.importKey('raw', utf8Encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
      const bits = await subtle.deriveBits(
        { name: 'PBKDF2', salt: wrapSalt, iterations: iterations, hash: 'SHA-256' },
        keyMaterial,
        256
      );
      const wrapKey = await subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      wipeBytes(new Uint8Array(bits));
      const cekBuf = await subtle.decrypt(
        { name: 'AES-GCM', iv: wrapIv, tagLength: 128, additionalData: utf8Encode(wrapAadText) },
        wrapKey,
        wrappedCek
      );
      cekBytes = new Uint8Array(cekBuf);
      if (cekBytes.length !== 32) {
        wipeBytes(cekBytes);
        return denied('BAD_CEK_LENGTH');
      }
    } catch (_e) {
      if (cekBytes) wipeBytes(cekBytes);
      return denied('UNWRAP_FAILED');
    }

    let plaintext = null;
    try {
      const subtle = subtleCrypto();
      const aad = computeAadBytes(pkg);
      const storedAad = b64decode(pkg.aadBase64);
      if (!bytesEqual(aad, storedAad)) {
        wipeBytes(cekBytes);
        return denied('AAD_MISMATCH');
      }
      const cekKey = await subtle.importKey('raw', cekBytes, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      wipeBytes(cekBytes);
      const plainBuf = await subtle.decrypt(
        { name: 'AES-GCM', iv: b64decode(pkg.ivBase64), tagLength: 128, additionalData: aad },
        cekKey,
        b64decode(pkg.ciphertextBase64)
      );
      plaintext = new Uint8Array(plainBuf);
    } catch (_e) {
      if (cekBytes) wipeBytes(cekBytes);
      return denied('DECRYPT_FAILED');
    }
    if (plaintext.length !== pkg.metadata.originalSizeBytes) {
      wipeBytes(plaintext);
      return denied('SIZE_MISMATCH');
    }

    return {
      ok: true,
      reason: 'OK',
      plaintext: plaintext,
      mimeType: pkg.metadata.mimeType,
      fileName: pkg.metadata.originalFileName,
      allowExtraction: pkg.metadata.allowExtraction === true,
      documentId: pkg.documentId,
      packageId: pkg.packageId,
      seal: sealInfo,
      binding: policy
        ? { present: true, expiry: policy.expiry, grantId: policy.grantId }
        : { present: false },
      sessionExpiresAt: sessionExpiresAt,
    };
  } catch (_e) {
    return denied('INTERNAL_ERROR');
  }
}

// ---------------------------------------------------------------------------
// Interfaz en el navegador (solo corre cuando hay documento). Construye la
// pantalla con createElement (sin inyeccion de marcado), renderiza por MIME,
// pone la marca forense en mosaico y aplica las defensas de captura.
// ---------------------------------------------------------------------------

function makeEl(doc, tag, text) {
  const el = doc.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = text;
  return el;
}

function randomNonceHex(bytes) {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

function buildWatermark(doc, container, documentId) {
  const nonce = randomNonceHex(4);
  const stamp = new Date().toISOString();
  const text = 'TDCP // DOC:' + documentId + ' // NONCE:' + nonce + ' // ' + stamp;
  const layer = makeEl(doc, 'div');
  layer.setAttribute('class', 'tdcp-wm');
  layer.setAttribute('aria-hidden', 'true');
  for (let row = 0; row < 6; row++) {
    for (let col = 0; col < 4; col++) {
      const tile = makeEl(doc, 'span', text);
      tile.setAttribute('class', 'tdcp-wm-tile');
      tile.style.left = col * 25 + '%';
      tile.style.top = row * 16.6 + '%';
      layer.appendChild(tile);
    }
  }
  container.appendChild(layer);
  return text;
}

function renderPlaintext(doc, container, result) {
  const mime = result.mimeType || 'application/octet-stream';
  const blob = new Blob([result.plaintext], { type: mime });
  const url = URL.createObjectURL(blob);
  const view = makeEl(doc, 'div');
  view.setAttribute('class', 'tdcp-view');
  if (mime.indexOf('text/') === 0 || mime === 'application/json') {
    const pre = makeEl(doc, 'pre', new TextDecoder('utf-8').decode(result.plaintext));
    pre.setAttribute('class', 'tdcp-text');
    view.appendChild(pre);
  } else if (mime.indexOf('image/') === 0) {
    const img = makeEl(doc, 'img');
    img.setAttribute('src', url);
    img.setAttribute('alt', result.fileName);
    img.setAttribute('class', 'tdcp-media');
    view.appendChild(img);
  } else if (mime.indexOf('video/') === 0) {
    const video = makeEl(doc, 'video');
    video.setAttribute('src', url);
    video.setAttribute('controls', '');
    video.setAttribute('controlsList', 'nodownload noplaybackrate');
    video.setAttribute('class', 'tdcp-media');
    view.appendChild(video);
  } else if (mime.indexOf('audio/') === 0) {
    const audio = makeEl(doc, 'audio');
    audio.setAttribute('src', url);
    audio.setAttribute('controls', '');
    audio.setAttribute('controlsList', 'nodownload');
    audio.setAttribute('class', 'tdcp-audio');
    view.appendChild(audio);
  } else if (mime === 'application/pdf') {
    const frame = makeEl(doc, 'iframe');
    frame.setAttribute('src', url);
    frame.setAttribute('class', 'tdcp-pdf');
    frame.setAttribute('title', result.fileName);
    view.appendChild(frame);
  } else if (result.allowExtraction) {
    const link = makeEl(doc, 'a', 'Descargar ' + result.fileName);
    link.setAttribute('href', url);
    link.setAttribute('download', result.fileName);
    link.setAttribute('class', 'tdcp-download');
    view.appendChild(link);
  } else {
    const msg = makeEl(
      doc,
      'p',
      'Este tipo de contenido no se puede mostrar en el visor (' + mime + ').'
    );
    view.appendChild(msg);
  }
  container.appendChild(view);
  return url;
}

export function bootOfflineViewer(doc, win) {
  const app = doc.getElementById('tdcp-app');
  if (!app) return { ok: false, reason: 'NO_APP_ELEMENT' };
  const dataEl = doc.getElementById('tdcp-offline-data');
  if (!dataEl) {
    app.appendChild(makeEl(doc, 'p', 'Acceso denegado'));
    return { ok: false, reason: 'NO_DATA_ELEMENT' };
  }
  let data;
  try {
    const raw = b64decode(dataEl.textContent || '');
    data = JSON.parse(new TextDecoder('utf-8').decode(raw));
  } catch (_e) {
    app.appendChild(makeEl(doc, 'p', 'Acceso denegado'));
    return { ok: false, reason: 'BAD_DATA_ELEMENT' };
  }

  const state = { objectUrl: null, plaintext: null, timer: null, closed: false };

  function destroyViewer(message) {
    if (state.closed) return;
    state.closed = true;
    if (state.timer !== null) {
      try {
        win.clearTimeout(state.timer);
      } catch (_e) {
        /* sin temporizador que limpiar */
      }
      state.timer = null;
    }
    if (state.objectUrl) {
      try {
        URL.revokeObjectURL(state.objectUrl);
      } catch (_e) {
        /* URL ya revocada */
      }
      state.objectUrl = null;
    }
    if (state.plaintext) {
      wipeBytes(state.plaintext);
      state.plaintext = null;
    }
    while (app.firstChild) app.removeChild(app.firstChild);
    const closed = makeEl(doc, 'p', message || 'Sesion cerrada. Cierra esta pestana.');
    closed.setAttribute('class', 'tdcp-closed');
    app.appendChild(closed);
  }

  function showDenied() {
    const form = doc.getElementById('tdcp-pass-form');
    if (form) {
      const input = doc.getElementById('tdcp-password');
      if (input) input.value = '';
    }
    let note = doc.getElementById('tdcp-status');
    if (!note) {
      note = makeEl(doc, 'p', 'Acceso denegado');
      note.setAttribute('id', 'tdcp-status');
      app.appendChild(note);
    }
    note.textContent = 'Acceso denegado';
  }

  const title = makeEl(doc, 'h1', 'Visor TDCP offline');
  title.setAttribute('class', 'tdcp-title');
  app.appendChild(title);
  const sub = makeEl(
    doc,
    'p',
    'Documento ' + (data.pkg ? data.pkg.documentId : '') + ' — introduce la contrasena maestra.'
  );
  sub.setAttribute('class', 'tdcp-sub');
  app.appendChild(sub);

  const form = makeEl(doc, 'form');
  form.setAttribute('id', 'tdcp-pass-form');
  form.setAttribute('autocomplete', 'off');
  const label = makeEl(doc, 'label', 'Contrasena maestra');
  label.setAttribute('for', 'tdcp-password');
  form.appendChild(label);
  const input = makeEl(doc, 'input');
  input.setAttribute('id', 'tdcp-password');
  input.setAttribute('type', 'password');
  input.setAttribute('autocomplete', 'off');
  input.setAttribute('required', '');
  form.appendChild(input);
  const button = makeEl(doc, 'button', 'Abrir documento');
  button.setAttribute('type', 'submit');
  form.appendChild(button);
  app.appendChild(form);

  const status = makeEl(doc, 'p', '');
  status.setAttribute('id', 'tdcp-status');
  status.setAttribute('class', 'tdcp-status');
  app.appendChild(status);

  const content = makeEl(doc, 'div');
  content.setAttribute('id', 'tdcp-content');
  app.appendChild(content);

  const closeBtn = makeEl(doc, 'button', 'Cerrar sesion');
  closeBtn.setAttribute('id', 'tdcp-close');
  closeBtn.setAttribute('type', 'button');
  closeBtn.setAttribute('class', 'tdcp-close');
  closeBtn.style.display = 'none';
  app.appendChild(closeBtn);

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    const password = input.value;
    input.value = '';
    status.textContent = 'Verificando…';
    openOfflineViewer(data, password)
      .then(function (result) {
        if (!result.ok) {
          showDenied();
          return;
        }
        state.plaintext = result.plaintext;
        form.style.display = 'none';
        sub.textContent = 'Documento ' + result.documentId + ' — ' + result.fileName;
        const sealText = result.seal.present
          ? 'Sello CSG ' + (result.seal.schema === 'csg.sello.v1' ? 'remoto' : 'local') + ' valido'
          : 'Sin sello CSG (modo opcional)';
        const bindingText = result.binding.present
          ? 'Binding de politica vigente hasta ' + new Date(result.binding.expiry).toISOString()
          : 'Sin binding de politica';
        status.textContent =
          sealText + ' — ' + bindingText + ' — la sesion se cierra a las ' +
          new Date(result.sessionExpiresAt).toISOString();
        buildWatermark(doc, content, result.documentId);
        state.objectUrl = renderPlaintext(doc, content, result);
        closeBtn.style.display = '';
        const remaining = result.sessionExpiresAt - Date.now();
        state.timer = win.setTimeout(function () {
          destroyViewer('Sesion cerrada por tiempo. Cierra esta pestana.');
        }, Math.max(1000, remaining));
      })
      .catch(function () {
        showDenied();
      });
  });

  closeBtn.addEventListener('click', function () {
    destroyViewer('Sesion cerrada. Cierra esta pestana.');
  });

  win.addEventListener('blur', function () {
    content.style.visibility = 'hidden';
  });
  win.addEventListener('focus', function () {
    if (!state.closed) content.style.visibility = '';
  });
  doc.addEventListener('visibilitychange', function () {
    if (doc.hidden) content.style.visibility = 'hidden';
    else if (!state.closed) content.style.visibility = '';
  });
  doc.addEventListener('keydown', function (event) {
    const key = (event.key || '').toLowerCase();
    if ((event.ctrlKey || event.metaKey) && (key === 'p' || key === 's' || key === 'c')) {
      event.preventDefault();
    }
  });
  content.addEventListener('contextmenu', function (event) {
    event.preventDefault();
  });

  return { ok: true, reason: 'OK', data: data };
}

export const TDCPOfflineViewer = {
  b64encode: b64encode,
  b64decode: b64decode,
  bytesToHex: bytesToHex,
  hexToBytes: hexToBytes,
  bytesEqual: bytesEqual,
  wipeBytes: wipeBytes,
  sha256Hex: sha256Hex,
  sha512Bytes: sha512Bytes,
  sha3_256Bytes: sha3_256Bytes,
  sha3_256Hex: sha3_256Hex,
  ed25519Verify: ed25519Verify,
  canonicalJsonPython: canonicalJsonPython,
  canonicalPackageEnvelope: canonicalPackageEnvelope,
  computeAadBytes: computeAadBytes,
  verifyRemoteSeal: verifyRemoteSeal,
  verifyLocalSeal: verifyLocalSeal,
  verifyPolicyBinding: verifyPolicyBinding,
  openOfflineViewer: openOfflineViewer,
  bootOfflineViewer: bootOfflineViewer,
  OFFLINE_VIEWER_SESSION_MINUTES: OFFLINE_VIEWER_SESSION_MINUTES,
  OFFLINE_VIEWER_FORMAT: OFFLINE_VIEWER_FORMAT,
  CEK_WRAP_AAD_PREFIX: CEK_WRAP_AAD_PREFIX,
};

if (typeof globalThis !== 'undefined') {
  globalThis.TDCPOfflineViewer = TDCPOfflineViewer;
}

if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      bootOfflineViewer(document, window);
    });
  } else {
    bootOfflineViewer(document, window);
  }
}
