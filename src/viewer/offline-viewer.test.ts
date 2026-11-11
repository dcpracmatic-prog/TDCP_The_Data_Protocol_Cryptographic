/**
 * Visor HTML Offline autocontenido — tests.
 *
 * Reglas:
 * - El doble en memoria de Smart Token, nunca el servicio real.
 * - Los sellos remotos se construyen con Node crypto con el MISMO algoritmo
 *   que el sidecar (SHA3-256 + Ed25519 sobre cuerpo_hash UTF-8); ademas hay
 *   un vector REAL producido por server/csg-sidecar/main.py (ver
 *   SIDECAR_SEAL_VECTOR) para que el runtime puro quede contrastado contra
 *   el Notario de verdad, no solo contra Node.
 * - El runtime del visor se prueba TAL COMO SE EMBEBE: se extrae el
 *   <script> del HTML generado y se ejecuta, en vez de probar solo el
 *   modulo TS. Asi un error de incrustacion tambien fallaria el test.
 * - La contrasena maestra de estos tests es un valor de test, no un
 *   secreto real: solo existe dentro del proceso de test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import vm from 'node:vm';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createTDCPPackage } from '../core/package/tdcp-factory.ts';
import {
  canonicalPackageEnvelopeBytes,
  type TDCPPackage,
} from '../core/package/package-format.ts';
import { AuthorizationOracle } from '../oracle/authorization-oracle.ts';
import {
  createInMemorySmartTokenCekCustodyFake,
  type SmartTokenCekCustodian,
} from '../protection/smart-token-cek-custody.ts';
import { createLocalCsgSeal } from '../protection/csg-local-seal.ts';
import { createPolicyBinding } from '../channel/policy-binding.ts';
import { arrayBufferToBase64 } from '../core/crypto/primitives.ts';
import {
  buildOfflineViewer,
  OFFLINE_VIEWER_FORBIDDEN_TOKENS,
  verifyRemoteSealWithNodeCrypto,
} from './offline-viewer.ts';
import {
  edBasePoint,
  edEncodePoint,
  edScalarMult,
  ed25519Verify,
  openOfflineViewer,
  sha3_256Hex,
  verifyRemoteSeal,
  bytesToHex,
} from './viewer-runtime.ts';

const MASTER = 'master-de-emisor-solo-para-test';
const PLAINTEXT = 'Documento de prueba del visor offline TDCP.';
const WRONG_MASTER = 'contrasena-equivocada-de-test';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------------------------------------------------------------------------
// Vector REAL del sidecar (server/csg-sidecar/main.py, puerto 8019).
// Paquete fijo sellado con POST /v1/seal (evento SIDECAR-VECTOR-1); el
// propio sidecar confirmo /v1/verify todo_valido:true sobre estos bytes.
// El sello trae notario_pub, asi que la verificacion es autocontenida.
// ---------------------------------------------------------------------------

const SIDECAR_VECTOR_PKG = {
  magicHeader: 'TDCP_SECURE_PKG',
  version: '2.5-SEC',
  algorithm: 'AES-256-GCM / HKDF-SHA256',
  documentId: 'DOC-SIDECAR-VECTOR',
  packageId: 'PKG-SIDECAR-VECTOR',
  saltBase64: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
  ivBase64: 'AAECAwQFBgcICQoLDA==',
  ciphertextBase64: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
  aadBase64:
    'VEQzQy1BQUQtdjIuNXxET0M9RE9DLVNJREVDQVItVkVDVE9SfFBGRz1QS0ctU0lERUNBUi1WRUNUT1J8VkVSPTIuNS1TRUN8UE9MSUNZPVNUQU5EQVJEfEVYVFJBQ1Q9MHxFWFBfREFZUz18VklFV19PTkNFPXwwfEtERl9JVEVSUz02MDAwMDA=',
  metadata: {
    originalFileName: 'vector.txt',
    mimeType: 'text/plain',
    originalSizeBytes: 4,
    createdAt: 1700000000000,
    policyLevel: 'STANDARD',
    allowExtraction: false,
    kdfIterations: 600000,
    documentId: 'DOC-SIDECAR-VECTOR',
    packageId: 'PKG-SIDECAR-VECTOR',
    custodyMode: 'smart-token',
  },
  integrityHash: '00'.repeat(32),
  envelopeEpoch: 1,
  smartTokenCustody: { artifactId: 'STK-VECTOR', version: 1 },
};

const SIDECAR_SEAL_VECTOR = {
  evento_id: 'SIDECAR-VECTOR-1',
  aceptado: true,
  razon: '',
  timestamp: 1794439271,
  hash_contenido: '14376fceb730f9382cafe78701db00c777b3c33057350e92a27b93acd1456d02',
  firmante_pub: 'c0046aa0addced3798dc5f95c44fa71fd48ea228f689769f91faff065bf71d5b',
  sello_anterior: 'f94e5d9225071fc5b16c2c0eaf71bc25cac9efc9edf1773fd1723f76845f6182',
  cuerpo_hash: '1e5c2550f2afea2254e8f4a38e8910d8b243e70cfca25f56ccc42c305e98674e',
  firma_notario:
    'd088e7e166b10411011f3045b2645f81bfb8a40810dd75491cfa277d2677d140ab193c12d5f4e92d0a9f96ba71dc377045e74125f19dc391efb046ad8a85c50d',
  schema: 'csg.sello.v1',
  label: 'tdcp-pkg',
  attributes: {},
  notario_pub: 'cbc6b9a6943aa81931052b063e6c634ba64444d385ef9c94ae02041828d6b8b8',
  developmentOnly: false,
};

// ---------------------------------------------------------------------------
// Ayudas
// ---------------------------------------------------------------------------

function canonicalJsonCompact(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) {
    const v = obj[k];
    sorted[k] =
      v && typeof v === 'object' && !Array.isArray(v)
        ? JSON.parse(canonicalJsonCompact(v as Record<string, unknown>))
        : v;
  }
  return JSON.stringify(sorted);
}

function sha3Hex(data: Uint8Array): string {
  return createHash('sha3-256').update(data).digest('hex');
}

/** Sello remoto csg.sello.v1 con el algoritmo exacto del sidecar. */
function sealRemoteWithNode(
  content: Uint8Array,
  keypair: { publicKey: unknown; privateKey: unknown },
  eventoId: string
) {
  const pubDer = (keypair.publicKey as { export: (o: unknown) => Buffer }).export({
    type: 'spki',
    format: 'der',
  });
  const pubHex = Buffer.from(pubDer.subarray(-32)).toString('hex');
  const cuerpo = {
    evento_id: eventoId,
    aceptado: true,
    razon: '',
    timestamp: 1700000000,
    hash_contenido: sha3Hex(content),
    firmante_pub: pubHex,
    sello_anterior: '0'.repeat(64),
  };
  const cuerpoHash = sha3Hex(encoder.encode(canonicalJsonCompact(cuerpo)));
  const sig = sign(
    null,
    Buffer.from(cuerpoHash, 'utf8'),
    keypair.privateKey as never
  );
  return {
    schema: 'csg.sello.v1',
    ...cuerpo,
    cuerpo_hash: cuerpoHash,
    firma_notario: sig.toString('hex'),
    label: 'tdcp-pkg',
    attributes: {},
    notario_pub: pubHex,
    developmentOnly: false,
  };
}

async function makeCustodyPkg(
  oracle: AuthorizationOracle,
  custodian: SmartTokenCekCustodian,
  plaintextStr = PLAINTEXT
): Promise<TDCPPackage> {
  return createTDCPPackage({
    plaintext: encoder.encode(plaintextStr).buffer,
    password: 'PasswordOriginal!',
    originalFileName: 'documento.txt',
    mimeType: 'text/plain',
    policyLevel: 'STANDARD',
    allowExtraction: false,
    oracle,
    cekCustodyMode: 'smart-token',
    smartTokenCustodian: custodian,
    smartTokenMaster: MASTER,
    csgSeal: 'off',
  });
}

function attachRemoteSeal(pkg: TDCPPackage, eventoId = 'evt-test-1') {
  const keypair = generateKeyPairSync('ed25519');
  const seal = sealRemoteWithNode(canonicalPackageEnvelopeBytes(pkg), keypair, eventoId);
  pkg.csgSeal = seal as never;
  return { seal, keypair };
}

async function attachLocalSeal(pkg: TDCPPackage) {
  const seal = await createLocalCsgSeal(canonicalPackageEnvelopeBytes(pkg), {
    label: 'tdcp-pkg',
    attributes: { documentId: pkg.documentId },
  });
  pkg.csgSeal = seal as never;
  return seal;
}

async function makeAuthority() {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const spki = await globalThis.crypto.subtle.exportKey('spki', pair.publicKey);
  return { privateKey: pair.privateKey, spkiBase64: arrayBufferToBase64(spki) };
}

async function makeBinding(
  authority: { privateKey: CryptoKey },
  documentId: string,
  expiry: number
) {
  return createPolicyBinding(
    {
      documentId,
      grantId: 'GRANT-TEST-1',
      expiry,
      edges: [{ source: 'A', destination: 'B', expectedBytes: PLAINTEXT.length, allowed: true }],
    },
    authority.privateKey,
    'kid-test'
  );
}

/** Custodio que registra la CEK que devuelve openCek (solo para el test). */
function recordingCustodian(fake: ReturnType<typeof createInMemorySmartTokenCekCustodyFake>) {
  let captured: Uint8Array | null = null;
  const wrapper: SmartTokenCekCustodian = {
    async protectCek(cek: Uint8Array, masterSecret: string) {
      return fake.protectCek(cek, masterSecret);
    },
    async openCek(artifactId: string, masterSecret: string) {
      const res = await fake.openCek(artifactId, masterSecret);
      if (res.ok) captured = res.cek.slice();
      return res;
    },
  };
  return { wrapper, captured: () => captured };
}

function extractRuntimeSource(html: string): string {
  const m = html.match(/<script id="tdcp-viewer-runtime">([\s\S]*?)<\/script>/);
  assert.ok(m, 'el HTML debe llevar el runtime embebido');
  return m[1];
}

function extractDataB64(html: string): string {
  const m = html.match(
    /<script id="tdcp-offline-data" type="application\/json">([^<]*)<\/script>/
  );
  assert.ok(m, 'el HTML debe llevar los datos embebidos');
  return m[1];
}

function extractData(html: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(extractDataB64(html), 'base64').toString('utf8'));
}

/** Ejecuta el runtime TAL COMO SE EMBEBE en el HTML y devuelve su API. */
function loadEmbeddedViewer(html: string): any {
  const src = extractRuntimeSource(html);
  return vm.runInThisContext(`(function(){\n${src}\n; return TDCPOfflineViewer; })()`, {
    filename: 'offline-viewer-runtime-embebido.js',
  });
}

async function openHtml(html: string, password: string) {
  const viewer = loadEmbeddedViewer(html);
  return viewer.openOfflineViewer(extractData(html), password);
}

async function buildSealedHtml(opts: {
  plaintext?: string;
  custodian?: SmartTokenCekCustodian;
  sealMode?: 'required' | 'optional';
  withLocalSeal?: boolean;
  policyBinding?: Awaited<ReturnType<typeof makeBinding>>;
  authoritySpkiBase64?: string;
} = {}) {
  const oracle = new AuthorizationOracle();
  const fake = createInMemorySmartTokenCekCustodyFake();
  const custodian = opts.custodian ?? fake;
  const pkg = await makeCustodyPkg(oracle, fake, opts.plaintext);
  let notaryPublicKeyHex: string | undefined;
  if (opts.withLocalSeal) {
    await attachLocalSeal(pkg);
  } else {
    const attached = attachRemoteSeal(pkg);
    notaryPublicKeyHex = (attached.seal as { notario_pub: string }).notario_pub;
  }
  const html = await buildOfflineViewer({
    pkg,
    masterPassword: MASTER,
    cekCustodian: custodian,
    exportOffline: true,
    sealMode: opts.sealMode ?? 'required',
    notaryPublicKeyHex,
    policyBinding: opts.policyBinding,
    authorityPublicKeySpkiBase64: opts.authoritySpkiBase64,
  });
  return { html, pkg, fake, oracle };
}

function flipBase64Char(b64: string): string {
  const first = b64[0] === 'A' ? 'B' : 'A';
  return first + b64.slice(1);
}

function tamperCiphertext(data: Record<string, unknown>): Record<string, unknown> {
  const pkg = { ...(data['pkg'] as Record<string, unknown>) };
  const raw = Buffer.from(pkg['ciphertextBase64'] as string, 'base64');
  raw[0] ^= 1;
  pkg['ciphertextBase64'] = raw.toString('base64');
  return { ...data, pkg };
}

async function waitFor(cond: () => boolean, timeoutMs = 15000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor: tiempo agotado');
    await new Promise((r) => setTimeout(r, 50));
  }
}

// ---------------------------------------------------------------------------
// DOM minimo para probar el arranque del visor sin navegador
// ---------------------------------------------------------------------------

class FakeEl {
  tagName: string;
  children: FakeEl[] = [];
  attributes = new Map<string, string>();
  style: Record<string, string> = {};
  listeners = new Map<string, Array<(ev: never) => void>>();
  _text = '';
  value = '';
  parent: FakeEl | null = null;
  doc: FakeDoc;
  constructor(doc: FakeDoc, tag: string) {
    this.doc = doc;
    this.tagName = tag.toUpperCase();
  }
  get textContent(): string {
    return this._text;
  }
  set textContent(v: string) {
    this._text = String(v ?? '');
  }
  get firstChild(): FakeEl | null {
    return this.children[0] ?? null;
  }
  setAttribute(k: string, v: string): void {
    this.attributes.set(k, String(v));
    if (k === 'id') this.doc.register(this);
  }
  getAttribute(k: string): string | null {
    return this.attributes.get(k) ?? null;
  }
  appendChild(c: FakeEl): FakeEl {
    c.parent = this;
    this.children.push(c);
    return c;
  }
  removeChild(c: FakeEl): FakeEl {
    const i = this.children.indexOf(c);
    if (i >= 0) this.children.splice(i, 1);
    return c;
  }
  addEventListener(t: string, fn: (ev: never) => void): void {
    if (!this.listeners.has(t)) this.listeners.set(t, []);
    this.listeners.get(t)!.push(fn);
  }
  fire(t: string, ev: Record<string, unknown> = {}): void {
    for (const fn of this.listeners.get(t) ?? []) {
      fn({ preventDefault() {}, ...ev } as never);
    }
  }
}

class FakeDoc {
  byId = new Map<string, FakeEl>();
  listeners = new Map<string, Array<(ev: never) => void>>();
  hidden = false;
  readyState = 'complete';
  register(el: FakeEl): void {
    const id = el.getAttribute('id');
    if (id) this.byId.set(id, el);
  }
  getElementById(id: string): FakeEl | null {
    return this.byId.get(id) ?? null;
  }
  createElement(tag: string): FakeEl {
    return new FakeEl(this, tag);
  }
  addEventListener(t: string, fn: (ev: never) => void): void {
    if (!this.listeners.has(t)) this.listeners.set(t, []);
    this.listeners.get(t)!.push(fn);
  }
  fire(t: string, ev: Record<string, unknown> = {}): void {
    for (const fn of this.listeners.get(t) ?? []) {
      fn({ preventDefault() {}, ...ev } as never);
    }
  }
}

class FakeWin {
  listeners = new Map<string, Array<(ev: never) => void>>();
  addEventListener(t: string, fn: (ev: never) => void): void {
    if (!this.listeners.has(t)) this.listeners.set(t, []);
    this.listeners.get(t)!.push(fn);
  }
  fire(t: string, ev: Record<string, unknown> = {}): void {
    for (const fn of this.listeners.get(t) ?? []) {
      fn({ preventDefault() {}, ...ev } as never);
    }
  }
  setTimeout(fn: () => void, ms: number): ReturnType<typeof setTimeout> {
    return setTimeout(fn, ms);
  }
  clearTimeout(id: ReturnType<typeof setTimeout>): void {
    clearTimeout(id);
  }
}

function findDescendant(root: FakeEl | null, tag: string): FakeEl | null {
  if (!root) return null;
  for (const c of root.children) {
    if (c.tagName === tag) return c;
    const found = findDescendant(c, tag);
    if (found) return found;
  }
  return null;
}

function findByClass(root: FakeEl | null, cls: string): FakeEl | null {
  if (!root) return null;
  for (const c of root.children) {
    if ((c.getAttribute('class') ?? '').split(' ').includes(cls)) return c;
    const found = findByClass(c, cls);
    if (found) return found;
  }
  return null;
}

function collectText(root: FakeEl | null): string {
  if (!root) return '';
  let out = root._text;
  for (const c of root.children) out += collectText(c);
  return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Visor HTML Offline', () => {
  it('SHA3-256 puro coincide con Node crypto', () => {
    for (const s of ['', 'abc', 'hello tdcp envelope', 'a'.repeat(1000)]) {
      const mine = sha3_256Hex(encoder.encode(s));
      const ref = createHash('sha3-256').update(s, 'utf8').digest('hex');
      assert.equal(mine, ref, `SHA3-256 de ${JSON.stringify(s.slice(0, 20))}`);
    }
  });

  it('Ed25519 puro: punto base, [L]B identidad y firmas Node', async () => {
    const B = edBasePoint();
    assert.equal(
      bytesToHex(edEncodePoint(B)),
      '5866666666666666666666666666666666666666666666666666666666666666'
    );
    const L = (1n << 252n) + 27742317777372353535851937790883648493n;
    assert.equal(
      bytesToHex(edEncodePoint(edScalarMult(B, L))),
      '0100000000000000000000000000000000000000000000000000000000000000'
    );
    assert.equal(
      bytesToHex(edEncodePoint(edScalarMult(B, 2n))),
      'c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022'
    );
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const pubBytes = new Uint8Array(
      publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)
    );
    const msg = encoder.encode('mensaje de prueba ed25519');
    const sig = sign(null, msg, privateKey);
    assert.equal(await ed25519Verify(pubBytes, msg, new Uint8Array(sig)), true);
    const badSig = new Uint8Array(sig);
    badSig[0] ^= 1;
    assert.equal(await ed25519Verify(pubBytes, msg, badSig), false);
    assert.equal(
      await ed25519Verify(pubBytes, encoder.encode('otro mensaje'), new Uint8Array(sig)),
      false
    );
  });

  it('vector REAL del sidecar: el runtime puro verifica el sello del Notario', async () => {
    const bytes = canonicalPackageEnvelopeBytes(SIDECAR_VECTOR_PKG as never);
    const r = await verifyRemoteSeal(bytes, SIDECAR_SEAL_VECTOR as never, null);
    assert.deepEqual(r, { valid: true, reason: 'OK' });
    const n = verifyRemoteSealWithNodeCrypto(
      bytes,
      SIDECAR_SEAL_VECTOR as never,
      SIDECAR_SEAL_VECTOR.notario_pub
    );
    assert.deepEqual(n, { valid: true, reason: 'OK' });
    const tampered = {
      ...SIDECAR_SEAL_VECTOR,
      firma_notario: '00' + SIDECAR_SEAL_VECTOR.firma_notario.slice(2),
    };
    assert.equal((await verifyRemoteSeal(bytes, tampered as never, null)).valid, false);
  });

  it('sello remoto valido + contrasena correcta abre (runtime embebido)', async () => {
    const { html } = await buildSealedHtml();
    const result = await openHtml(html, MASTER);
    if (!result.ok) assert.fail(`no abrio: ${JSON.stringify(result)}`);
    assert.equal(decoder.decode(result.plaintext), PLAINTEXT);
    assert.equal(result.mimeType, 'text/plain');
    assert.equal(result.fileName, 'documento.txt');
    assert.equal(result.seal.schema, 'csg.sello.v1');
    assert.equal(result.binding.present, false);
    assert.ok(
      result.sessionExpiresAt > Date.now() &&
        result.sessionExpiresAt <= Date.now() + 15 * 60 * 1000
    );
  });

  it('HTML emitido: sin URLs externas ni mecanismos prohibidos; CEK en claro ausente', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const rec = recordingCustodian(fake);
    const pkg = await makeCustodyPkg(oracle, fake);
    const { notario_pub } = attachRemoteSeal(pkg).seal as { notario_pub: string };
    const html = await buildOfflineViewer({
      pkg,
      masterPassword: MASTER,
      cekCustodian: rec.wrapper,
      exportOffline: true,
      sealMode: 'required',
      notaryPublicKeyHex: notario_pub,
    });
    const lower = html.toLowerCase();
    for (const token of OFFLINE_VIEWER_FORBIDDEN_TOKENS) {
      assert.ok(!lower.includes(token.toLowerCase()), `HTML contiene "${token}"`);
    }
    const cek = rec.captured();
    assert.ok(cek, 'el test debe haber capturado la CEK del custodio');
    assert.ok(!html.includes(bytesToHex(cek!)), 'la CEK en hex aparece en el HTML');
    assert.ok(
      !html.includes(Buffer.from(cek!).toString('base64')),
      'la CEK en base64 aparece en el HTML'
    );
    assert.ok(!html.includes(MASTER), 'la contrasena maestra aparece en el HTML');
    // El paquete viaja embebido (base64), el runtime tambien: el HTML es autocontenido.
    assert.ok(html.includes('tdcp-offline-data'));
    assert.ok(html.includes('tdcp-viewer-runtime'));
  });

  it('paquete alterado (1 byte del ciphertext) con sello valido -> DENIED', async () => {
    const { html } = await buildSealedHtml();
    const viewer = loadEmbeddedViewer(html);
    const tampered = tamperCiphertext(extractData(html));
    const result = await viewer.openOfflineViewer(tampered, MASTER);
    if (result.ok) assert.fail('debió denegar el paquete alterado');
    assert.equal(result.reason, 'DENIED');
    assert.match(result.detail, /SEAL_INVALID/);
  });

  it('paquete alterado sin sello (modo optional) -> DENIED por AES-GCM', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await makeCustodyPkg(oracle, fake);
    const html = await buildOfflineViewer({
      pkg,
      masterPassword: MASTER,
      cekCustodian: fake,
      exportOffline: true,
      sealMode: 'optional',
    });
    const viewer = loadEmbeddedViewer(html);
    const tampered = tamperCiphertext(extractData(html));
    const result = await viewer.openOfflineViewer(tampered, MASTER);
    if (result.ok) assert.fail('debió denegar el paquete alterado sin sello');
    assert.equal(result.reason, 'DENIED');
    assert.match(result.detail, /DECRYPT_FAILED/);
  });

  it('contrasena incorrecta -> DENIED opaco', async () => {
    const { html } = await buildSealedHtml();
    const result = await openHtml(html, WRONG_MASTER);
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'DENIED');
  });

  it('PolicyBinding vigente abre; caducado -> DENIED; firma invalida -> DENIED', async () => {
    const authority = await makeAuthority();
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await makeCustodyPkg(oracle, fake);
    const expirySoon = Date.now() + 5 * 60 * 1000;
    const binding = await makeBinding(authority, pkg.documentId, expirySoon);
    const { notario_pub } = attachRemoteSeal(pkg).seal as { notario_pub: string };
    const html = await buildOfflineViewer({
      pkg,
      masterPassword: MASTER,
      cekCustodian: fake,
      exportOffline: true,
      sealMode: 'required',
      notaryPublicKeyHex: notario_pub,
      policyBinding: binding,
      authorityPublicKeySpkiBase64: authority.spkiBase64,
    });
    const ok = await openHtml(html, MASTER);
    if (!ok.ok) assert.fail(`no abrio con binding vigente: ${JSON.stringify(ok)}`);
    assert.equal(ok.binding.present, true);
    assert.equal(ok.sessionExpiresAt, expirySoon);

    const viewer = loadEmbeddedViewer(html);
    const data = extractData(html);
    const expiredBinding = await makeBinding(authority, pkg.documentId, Date.now() - 1000);
    const expired = await viewer.openOfflineViewer(
      { ...data, policyBinding: expiredBinding },
      MASTER
    );
    if (expired.ok) assert.fail('debió denegar el binding caducado');
    assert.equal(expired.reason, 'DENIED');
    assert.match(expired.detail, /BINDING_INVALID:.*EXPIRED/);
    const badSig = {
      ...binding,
      signature: flipBase64Char(binding.signature),
    };
    const bad = await viewer.openOfflineViewer({ ...data, policyBinding: badSig }, MASTER);
    if (bad.ok) assert.fail('debió denegar el binding con firma invalida');
    assert.equal(bad.reason, 'DENIED');
    assert.match(bad.detail, /BINDING_INVALID/);
  });

  it('sello local valido abre; sello local alterado -> DENIED', async () => {
    const { html } = await buildSealedHtml({ withLocalSeal: true });
    const ok = await openHtml(html, MASTER);
    if (!ok.ok) assert.fail(`no abrio con sello local: ${JSON.stringify(ok)}`);
    assert.equal(ok.seal.schema, 'tdcp.csg-local.v1');
    const viewer = loadEmbeddedViewer(html);
    const data = extractData(html);
    const pkg = { ...(data['pkg'] as Record<string, unknown>) };
    const seal = { ...(pkg['csgSeal'] as Record<string, unknown>) };
    seal['signatureBase64'] = flipBase64Char(seal['signatureBase64'] as string);
    pkg['csgSeal'] = seal;
    const tampered = await viewer.openOfflineViewer({ ...data, pkg }, MASTER);
    if (tampered.ok) assert.fail('debió denegar el sello local alterado');
    assert.equal(tampered.reason, 'DENIED');
    assert.match(tampered.detail, /SEAL_INVALID/);
  });

  it('generador rechaza paquete oracle (no smart-token)', async () => {
    const oracle = new AuthorizationOracle();
    const pkg = await createTDCPPackage({
      plaintext: encoder.encode(PLAINTEXT).buffer,
      password: 'PasswordOriginal!',
      originalFileName: 'documento.txt',
      mimeType: 'text/plain',
      policyLevel: 'STANDARD',
      allowExtraction: false,
      oracle,
      csgSeal: 'off',
    });
    const fake = createInMemorySmartTokenCekCustodyFake();
    await assert.rejects(
      () =>
        buildOfflineViewer({
          pkg,
          masterPassword: MASTER,
          cekCustodian: fake,
          exportOffline: true,
        }),
      /NOT_SMART_TOKEN_CUSTODY/
    );
  });

  it('generador exige exportOffline explicito', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await makeCustodyPkg(oracle, fake);
    await assert.rejects(
      () =>
        buildOfflineViewer({
          pkg,
          masterPassword: MASTER,
          cekCustodian: fake,
          exportOffline: false,
        }),
      /EXPORT_NOT_EXPLICIT/
    );
  });

  it('generador rechaza sello remoto firmado con otra llave que la del Notario', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await makeCustodyPkg(oracle, fake);
    attachRemoteSeal(pkg);
    const other = generateKeyPairSync('ed25519');
    const otherPub = Buffer.from(
      other.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)
    ).toString('hex');
    await assert.rejects(
      () =>
        buildOfflineViewer({
          pkg,
          masterPassword: MASTER,
          cekCustodian: fake,
          exportOffline: true,
          sealMode: 'required',
          notaryPublicKeyHex: otherPub,
        }),
      /SEAL_INVALID/
    );
  });

  it('generador: sin sello en required falla; en optional genera y el visor abre sin sello', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await makeCustodyPkg(oracle, fake);
    await assert.rejects(
      () =>
        buildOfflineViewer({
          pkg,
          masterPassword: MASTER,
          cekCustodian: fake,
          exportOffline: true,
          sealMode: 'required',
        }),
      /SEAL_REQUIRED_MISSING/
    );
    const html = await buildOfflineViewer({
      pkg,
      masterPassword: MASTER,
      cekCustodian: fake,
      exportOffline: true,
      sealMode: 'optional',
    });
    const ok = await openHtml(html, MASTER);
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal((ok.seal as { present: boolean }).present, false);
  });

  it('generador rechaza cuando el custodio deniega la CEK', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await makeCustodyPkg(oracle, fake);
    attachRemoteSeal(pkg);
    await assert.rejects(
      () =>
        buildOfflineViewer({
          pkg,
          masterPassword: WRONG_MASTER,
          cekCustodian: fake,
          exportOffline: true,
          sealMode: 'required',
          notaryPublicKeyHex: (pkg.csgSeal as unknown as { notario_pub: string }).notario_pub,
        }),
      /SMART_TOKEN_DENIED/
    );
  });

  it('boot con DOM minimo: abre, renderiza texto con marca, blur oculta, cerrar destruye', async () => {
    const { html } = await buildSealedHtml();
    const viewer = loadEmbeddedViewer(html);
    const doc = new FakeDoc();
    const win = new FakeWin();
    const app = doc.createElement('div');
    app.setAttribute('id', 'tdcp-app');
    doc.register(app);
    const dataEl = doc.createElement('script');
    dataEl.setAttribute('id', 'tdcp-offline-data');
    dataEl.textContent = extractDataB64(html);
    doc.register(dataEl);
    const boot = viewer.bootOfflineViewer(doc as never, win as never);
    assert.equal(boot.ok, true);
    const input = doc.getElementById('tdcp-password')!;
    const form = doc.getElementById('tdcp-pass-form')!;
    input.value = MASTER;
    form.fire('submit', { preventDefault() {} });
    await waitFor(() =>
      (doc.getElementById('tdcp-status')?.textContent ?? '').includes('Sello CSG')
    );
    const content = doc.getElementById('tdcp-content')!;
    const pre = findDescendant(content, 'PRE');
    assert.ok(pre, 'el texto debe renderizarse en <pre>');
    assert.equal(pre!.textContent, PLAINTEXT);
    assert.ok(findByClass(content, 'tdcp-wm'), 'falta la marca forense en mosaico');
    win.fire('blur');
    assert.equal(content.style.visibility, 'hidden');
    win.fire('focus');
    assert.equal(content.style.visibility, '');
    doc.getElementById('tdcp-close')!.fire('click');
    assert.equal(app.children.length, 1);
    assert.match(collectText(app), /Sesion cerrada/);
  });

  it('boot con DOM minimo: contrasena incorrecta muestra solo "Acceso denegado"', async () => {
    const { html } = await buildSealedHtml();
    const viewer = loadEmbeddedViewer(html);
    const doc = new FakeDoc();
    const win = new FakeWin();
    const app = doc.createElement('div');
    app.setAttribute('id', 'tdcp-app');
    doc.register(app);
    const dataEl = doc.createElement('script');
    dataEl.setAttribute('id', 'tdcp-offline-data');
    dataEl.textContent = extractDataB64(html);
    doc.register(dataEl);
    const boot = viewer.bootOfflineViewer(doc as never, win as never);
    assert.equal(boot.ok, true);
    const input = doc.getElementById('tdcp-password')!;
    const form = doc.getElementById('tdcp-pass-form')!;
    input.value = WRONG_MASTER;
    form.fire('submit', { preventDefault() {} });
    await waitFor(() => doc.getElementById('tdcp-status')?.textContent === 'Acceso denegado');
    assert.equal(doc.getElementById('tdcp-content')!.children.length, 0);
  });

  it('CLI rechaza sin --export-offline (codigo 2, sin leer el paquete)', async () => {
    const cliPath = fileURLToPath(new URL('./offline-viewer-cli.ts', import.meta.url));
    const run = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
      execFile(
        process.execPath,
        ['--experimental-strip-types', cliPath, '--pkg', 'x.pkg', '--out', 'x.html'],
        (error, _stdout, stderr) => {
          resolve({ code: error ? (error as { code?: number }).code ?? 1 : 0, stderr });
        }
      );
    });
    assert.equal(run.code, 2);
    assert.match(run.stderr, /EXPORT_NOT_EXPLICIT/);
  });
});
