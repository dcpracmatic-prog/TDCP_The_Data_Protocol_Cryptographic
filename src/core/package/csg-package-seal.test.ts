/**
 * P2-5 — CSG package seal wiring tests.
 *
 * The real CSG sidecar is an HTTP service; here it is replaced by a stub
 * `fetch` that implements the same seal/verify contract (SHA3-256 content
 * digest + Notario-style cuerpo hash + aceptado flag) so the wiring is
 * tested without network. The real sidecar is exercised by
 * scripts/csg-pkg-smoke.mjs.
 *
 * Rules under test:
 * - seal covers the canonical envelope bytes (structure + full content);
 * - tampering 1 byte fails the seal even when the (unkeyed) integrityHash
 *   is recomputed by the attacker;
 * - legacy packages without a seal still open (no CSG guarantee);
 * - a present seal that cannot be verified (sidecar down) fails CLOSED;
 * - `required` seal mode throws at protect when the sidecar is down;
 *   `optional` leaves the package unsealed instead of faking a seal.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createTDCPPackage } from './tdcp-factory.ts';
import {
  computePackageIntegrityHash,
  canonicalPackageEnvelopeBytes,
  serializeTDCPPackage,
  deserializeTDCPPackage,
  type TDCPPackage,
} from './package-format.ts';
import {
  sealPackage,
  verifyPackageSeal,
  attachPackageSeal,
} from './csg-package-seal.ts';
import { AuthorizationOracle } from '../../oracle/authorization-oracle.ts';
import { DCPGatekeeper } from '../../gatekeeper/gatekeeper.ts';
import { MockNFCProvider } from '../../identity/credential-provider.ts';
import { MockDeviceIdentityProvider } from '../../identity/device-identity-provider.ts';
import { MockBiometricProvider } from '../../identity/biometric-provider.ts';
import { LocalAuditSink } from '../../audit/audit-sink.ts';
import { arrayBufferToBase64, base64ToUint8Array } from '../crypto/primitives.ts';

const SIDECAR_URL = 'http://127.0.0.1:8010';
const PLAINTEXT = 'TDCP P2-5: contenido secreto de prueba';
const PASSWORD = 'contrasena-de-prueba-123';

function sha3Hex(data: Uint8Array): string {
  return createHash('sha3-256').update(data).digest('hex');
}

function canonicalJson(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) {
    const v = obj[k];
    sorted[k] =
      v && typeof v === 'object' && !Array.isArray(v)
        ? JSON.parse(canonicalJson(v as Record<string, unknown>))
        : v;
  }
  return JSON.stringify(sorted);
}

function fakeSeal(content: Uint8Array, label: string, attributes: Record<string, string>) {
  const cuerpo = {
    evento_id: 'evt-test-1',
    aceptado: true,
    razon: '',
    timestamp: 1_700_000_000,
    hash_contenido: sha3Hex(content),
    firmante_pub: 'aa'.repeat(32),
    sello_anterior: '0'.repeat(64),
  };
  return {
    schema: 'csg.sello.v1',
    ...cuerpo,
    cuerpo_hash: sha3Hex(new TextEncoder().encode(canonicalJson(cuerpo))),
    firma_notario: 'bb'.repeat(64),
    label,
    attributes,
    notario_pub: 'cc'.repeat(32),
    developmentOnly: false,
  };
}

/** Stub fetch implementing the sidecar /v1/seal + /v1/verify contract. */
function makeStubFetch(seen: { sealedContentB64?: string }) {
  return async (url: string, init?: { method?: string; body?: string }) => {
    const path = new URL(url).pathname;
    const body = init?.body ? JSON.parse(init.body as string) : {};
    const json = async () => payload;
    let payload: unknown;
    if (path === '/v1/seal') {
      const content = base64ToUint8Array(body.content_base64);
      seen.sealedContentB64 = body.content_base64;
      payload = fakeSeal(content, body.label ?? '', body.attributes ?? {});
    } else if (path === '/v1/verify') {
      const content = base64ToUint8Array(body.content_base64);
      const sello = body.sello as Record<string, unknown>;
      const cuerpo = {
        evento_id: sello.evento_id,
        aceptado: sello.aceptado,
        razon: sello.razon ?? '',
        timestamp: sello.timestamp,
        hash_contenido: sello.hash_contenido,
        firmante_pub: sello.firmante_pub,
        sello_anterior: sello.sello_anterior,
      };
      const checks = {
        content_digest_match: sha3Hex(content) === sello.hash_contenido,
        cuerpo_no_alterado:
          sha3Hex(new TextEncoder().encode(canonicalJson(cuerpo))) === sello.cuerpo_hash,
        firma_notario_valida: true,
        aceptado: sello.aceptado === true,
      };
      payload = {
        todo_valido: Object.values(checks).every(Boolean),
        checks,
        hash_contenido: sha3Hex(content),
        schema: 'csg.sello.v1',
      };
    } else {
      payload = { ok: true };
    }
    return { ok: true, status: 200, json, text: async () => JSON.stringify(payload) };
  };
}

async function makePkg(
  oracle: AuthorizationOracle,
  csgSeal: 'required' | 'optional' | 'off' = 'off'
): Promise<TDCPPackage> {
  return createTDCPPackage({
    plaintext: new TextEncoder().encode(PLAINTEXT).buffer,
    password: PASSWORD,
    originalFileName: 'prueba.txt',
    mimeType: 'text/plain',
    policyLevel: 'STANDARD',
    allowExtraction: false,
    oracle,
    csgSeal,
  });
}

async function unlock(pkg: TDCPPackage, oracle: AuthorizationOracle) {
  return DCPGatekeeper.executeUnlock({
    packageData: pkg,
    userPassword: PASSWORD,
    requestedOperation: 'READ',
    nfcProvider: new MockNFCProvider(),
    deviceProvider: new MockDeviceIdentityProvider(),
    biometricProvider: new MockBiometricProvider(),
    oracle,
    auditSink: new LocalAuditSink(),
  });
}

/** Flip one base64 char (keeps valid base64, changes decoded bytes). */
function flipB64Char(s: string): string {
  const first = s[0];
  const replacement = first === 'A' ? 'B' : 'A';
  return replacement + s.slice(1);
}

const realFetch = globalThis.fetch;

describe('P2-5 CSG package seal', () => {
  beforeEach(() => {
    process.env.CSG_SEAL_URL = SIDECAR_URL;
  });

  afterEach(() => {
    delete process.env.CSG_SEAL_URL;
    globalThis.fetch = realFetch;
  });

  it('seals the canonical envelope bytes and verifies OK', async () => {
    const seen: { sealedContentB64?: string } = {};
    globalThis.fetch = makeStubFetch(seen) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'required');
    assert.ok(pkg.csgSeal, 'sealed package must carry csgSeal');
    assert.equal(pkg.csgSeal.schema, 'csg.sello.v1');
    // The sealed bytes are exactly the canonical envelope bytes.
    assert.equal(
      seen.sealedContentB64,
      arrayBufferToBase64(canonicalPackageEnvelopeBytes({ ...pkg, csgSeal: undefined })),
      'seal must cover the canonical envelope bytes'
    );
    const check = await verifyPackageSeal(pkg);
    assert.equal(check.status, 'sealed-valid');
    assert.equal(check.valid, true);
  });

  it('seal survives a serialize -> parse round-trip', async () => {
    const seen: { sealedContentB64?: string } = {};
    globalThis.fetch = makeStubFetch(seen) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'required');
    const blob = await serializeTDCPPackage(pkg);
    const parsed = await deserializeTDCPPackage(await blob.arrayBuffer());
    assert.equal(parsed.isValidEnvelope, true);
    const check = await verifyPackageSeal(parsed.package!);
    assert.equal(check.status, 'sealed-valid');
  });

  it('tampering 1 ciphertext byte fails the seal even with recomputed integrityHash', async () => {
    globalThis.fetch = makeStubFetch({}) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'required');
    const tampered: TDCPPackage = {
      ...pkg,
      ciphertextBase64: flipB64Char(pkg.ciphertextBase64),
    };
    // Attacker recomputes the UNKEYED integrity hash — that check alone
    // would pass. The CSG seal must still catch the tamper.
    tampered.integrityHash = await computePackageIntegrityHash(tampered);
    assert.equal(
      tampered.integrityHash !== pkg.integrityHash,
      true,
      'tampered package hash differs (sanity)'
    );
    const check = await verifyPackageSeal(tampered);
    assert.equal(check.status, 'sealed-invalid');
    assert.equal(check.valid, false);
  });

  it('corrupt seal and unknown schema fail closed', async () => {
    globalThis.fetch = makeStubFetch({}) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'required');
    const corrupt = {
      ...pkg,
      csgSeal: { ...pkg.csgSeal!, hash_contenido: '00'.repeat(32) },
    };
    assert.equal((await verifyPackageSeal(corrupt)).valid, false);
    const unknown = { ...pkg, csgSeal: { schema: 'evil.v9' } as never };
    const unknownCheck = await verifyPackageSeal(unknown);
    assert.equal(unknownCheck.status, 'sealed-invalid');
    assert.equal(unknownCheck.valid, false);
  });

  it('legacy package without seal reports absent (valid null)', async () => {
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'off');
    assert.equal(pkg.csgSeal, undefined);
    const check = await verifyPackageSeal(pkg);
    assert.equal(check.status, 'absent');
    assert.equal(check.valid, null);
  });

  it('required seal throws at protect when the sidecar is down; optional leaves it unsealed', async () => {
    globalThis.fetch = (async () => {
      throw new Error('fetch failed: connection refused');
    }) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    await assert.rejects(() => makePkg(oracle, 'required'), /CSG_SEAL_FAILED/);
    const pkg = await makePkg(oracle, 'optional');
    assert.equal(pkg.csgSeal, undefined, 'optional must not fake a seal');
  });

  it('required seal throws at protect when no sidecar is configured', async () => {
    delete process.env.CSG_SEAL_URL;
    const oracle = new AuthorizationOracle();
    await assert.rejects(() => makePkg(oracle, 'required'), /CSG_SIDECAR_UNAVAILABLE/);
    const pkg = await makePkg(oracle, 'optional');
    assert.equal(pkg.csgSeal, undefined);
  });

  it('sealed package with sidecar down at open is unverifiable (fail closed)', async () => {
    globalThis.fetch = makeStubFetch({}) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'required');
    globalThis.fetch = (async () => {
      throw new Error('fetch failed: connection refused');
    }) as unknown as typeof fetch;
    const check = await verifyPackageSeal(pkg);
    assert.equal(check.status, 'unverifiable');
    assert.equal(check.valid, false);
  });

  it('Gatekeeper opens a sealed package and reports sealed-valid', async () => {
    globalThis.fetch = makeStubFetch({}) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'required');
    const result = await unlock(pkg, oracle);
    assert.equal(result.success, true);
    assert.equal(result.csgSealStatus, 'sealed-valid');
    assert.equal(new TextDecoder().decode(result.plaintextBuffer), PLAINTEXT);
  });

  it('Gatekeeper rejects a tampered sealed package with CSG_PACKAGE_SEAL_FAILED and decrypts nothing', async () => {
    globalThis.fetch = makeStubFetch({}) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'required');
    const tampered: TDCPPackage = {
      ...pkg,
      ciphertextBase64: flipB64Char(pkg.ciphertextBase64),
    };
    tampered.integrityHash = await computePackageIntegrityHash(tampered);
    const result = await unlock(tampered, oracle);
    assert.equal(result.success, false);
    assert.equal(result.errorCode, 'CSG_PACKAGE_SEAL_FAILED');
    assert.equal(result.plaintextBuffer, undefined);
    assert.equal(result.csgSealStatus, 'sealed-invalid');
  });

  it('Gatekeeper still opens a legacy package without seal (absent)', async () => {
    // No sidecar configured at all: the legacy path (local operation
    // attestation fallback) must still open the package.
    delete process.env.CSG_SEAL_URL;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'off');
    const result = await unlock(pkg, oracle);
    assert.equal(result.success, true);
    assert.equal(result.csgSealStatus, 'absent');
    assert.equal(new TextDecoder().decode(result.plaintextBuffer), PLAINTEXT);
  });

  it('Gatekeeper fails closed when a sealed package cannot be verified (sidecar down)', async () => {
    globalThis.fetch = makeStubFetch({}) as unknown as typeof fetch;
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'required');
    globalThis.fetch = (async () => {
      throw new Error('fetch failed: connection refused');
    }) as unknown as typeof fetch;
    const result = await unlock(pkg, oracle);
    assert.equal(result.success, false);
    assert.equal(result.errorCode, 'CSG_PACKAGE_SEAL_FAILED');
    assert.equal(result.plaintextBuffer, undefined);
  });

  it('attachPackageSeal does not mutate the original package', async () => {
    const oracle = new AuthorizationOracle();
    const pkg = await makePkg(oracle, 'off');
    const seal = fakeSeal(canonicalPackageEnvelopeBytes(pkg), 'tdcp-pkg', {});
    const sealed = attachPackageSeal(pkg, seal as never);
    assert.equal(pkg.csgSeal, undefined);
    assert.equal(sealed.csgSeal, seal);
  });
});
