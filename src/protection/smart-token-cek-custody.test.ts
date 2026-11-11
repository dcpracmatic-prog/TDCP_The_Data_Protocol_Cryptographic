/**
 * P2-6: Smart Token como custodio de la CEK.
 *
 * Las pruebas usan el doble en memoria (`createInMemorySmartTokenCekCustodyFake`),
 * nunca un servidor real: el doble imita el contrato observable del servicio
 * (artifact_id opaco, 403 DENIED con master incorrecto, excepción si está
 * caído) pero guarda la CEK en memoria sin cifrar. El adaptador HTTP real
 * se prueba aparte con un `fetch` falso, sin red.
 *
 * La contraseña maestra de estos tests es un valor de test, no un secreto
 * real: solo existe dentro del proceso de test.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createTDCPPackage } from '../core/package/tdcp-factory.ts';
import {
  deserializeTDCPPackage,
  serializeTDCPPackage,
  type TDCPPackage,
} from '../core/package/package-format.ts';
import { AuthorizationOracle } from '../oracle/authorization-oracle.ts';
import { DCPGatekeeper } from '../gatekeeper/gatekeeper.ts';
import { MockNFCProvider } from '../identity/credential-provider.ts';
import { MockDeviceIdentityProvider } from '../identity/device-identity-provider.ts';
import { MockBiometricProvider } from '../identity/biometric-provider.ts';
import { LocalAuditSink } from '../audit/audit-sink.ts';
import {
  createInMemorySmartTokenCekCustodyFake,
  HttpSmartTokenCekCustodian,
  type SmartTokenCekCustodian,
} from './smart-token-cek-custody.ts';
import { SmartTokenClient } from '../../sdk/typescript/src/smart-token-client.ts';

const MASTER = 'master-de-emisor-solo-para-test';
const PLAINTEXT = 'Documento custodiado por Smart Token: la CEK no vive en el paquete.';

async function createCustodyPkg(
  oracle: AuthorizationOracle,
  custodian: SmartTokenCekCustodian,
  plaintextStr = PLAINTEXT
): Promise<TDCPPackage> {
  return createTDCPPackage({
    plaintext: new TextEncoder().encode(plaintextStr).buffer,
    password: 'PasswordOriginal!',
    originalFileName: 'documento_custodiado.txt',
    mimeType: 'text/plain',
    policyLevel: 'STANDARD',
    allowExtraction: false,
    oracle,
    cekCustodyMode: 'smart-token',
    smartTokenCustodian: custodian,
    smartTokenMaster: MASTER,
  });
}

function unlockCustody(
  pkg: TDCPPackage,
  oracle: AuthorizationOracle,
  opts: { master?: string; custodian?: SmartTokenCekCustodian } = {}
) {
  return DCPGatekeeper.executeUnlock({
    packageData: pkg,
    userPassword: 'PasswordOriginal!',
    requestedOperation: 'RENDER_RAM',
    nfcProvider: new MockNFCProvider(),
    deviceProvider: new MockDeviceIdentityProvider(),
    biometricProvider: new MockBiometricProvider(),
    oracle,
    auditSink: new LocalAuditSink(),
    smartTokenCustodian: opts.custodian,
    smartTokenMaster: opts.master,
  });
}

describe('P2-6 Smart Token como custodio de la CEK', () => {
  it('roundtrip: proteger con custodia y abrir tras grant válido, bytes idénticos', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await createCustodyPkg(oracle, fake);

    // El paquete en custodia NO contiene ninguna CEK envuelta por el Oracle.
    assert.equal(pkg.metadata.custodyMode, 'smart-token');
    assert.equal(pkg.wrappedKeyBase64, undefined);
    assert.equal(pkg.ivKeyBase64, undefined);
    assert.equal(pkg.smartTokenCustody?.version, 1);
    assert.ok(pkg.smartTokenCustody?.artifactId.startsWith('STK-'));
    assert.equal(fake.protects, 1);

    const res = await unlockCustody(pkg, oracle, { master: MASTER, custodian: fake });
    assert.equal(res.success, true, res.errorMessage);
    assert.equal(fake.opens, 1);
    assert.equal(new TextDecoder().decode(res.plaintextBuffer), PLAINTEXT);
  });

  it('smoke end-to-end: el .pkg sobrevive a serializar/deserializar y se abre', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await createCustodyPkg(oracle, fake);
    const blob = await serializeTDCPPackage(pkg);
    const parsed = await deserializeTDCPPackage(await blob.arrayBuffer());
    assert.equal(parsed.isValidEnvelope, true, parsed.error);
    const res = await unlockCustody(parsed.package!, oracle, { master: MASTER, custodian: fake });
    assert.equal(res.success, true, res.errorMessage);
    assert.equal(new TextDecoder().decode(res.plaintextBuffer), PLAINTEXT);
  });

  it('sin grant válido (documento revocado): falla y Smart Token ni se contacta', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await createCustodyPkg(oracle, fake);
    oracle.getRevocationManager().revokeDocument(pkg.documentId, 'Robo reportado');
    const opensBefore = fake.opens;
    const res = await unlockCustody(pkg, oracle, { master: MASTER, custodian: fake });
    assert.equal(res.success, false);
    assert.match(res.errorCode ?? '', /DOCUMENT_REVOKED|AUTHORIZATION_DENIED/);
    assert.equal(fake.opens, opensBefore, 'sin grant válido no se debe llamar a Smart Token');
    assert.equal(res.plaintextBuffer, undefined);
  });

  it('master incorrecto: DENIED opaco; con el master correcto después, abre', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await createCustodyPkg(oracle, fake);

    const denied = await unlockCustody(pkg, oracle, { master: 'master-equivocado', custodian: fake });
    assert.equal(denied.success, false);
    assert.equal(denied.errorCode, 'SMART_TOKEN_DENIED');
    assert.equal(denied.plaintextBuffer, undefined);

    // El intento fallido consumió su grant (un solo uso), pero una apertura
    // nueva pide un grant nuevo y con el master correcto abre.
    const ok = await unlockCustody(pkg, oracle, { master: MASTER, custodian: fake });
    assert.equal(ok.success, true, ok.errorMessage);
    assert.equal(new TextDecoder().decode(ok.plaintextBuffer), PLAINTEXT);
  });

  it('servicio Smart Token caído: falla cerrado, sin texto en claro', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await createCustodyPkg(oracle, fake);
    fake.setDown(true);
    const res = await unlockCustody(pkg, oracle, { master: MASTER, custodian: fake });
    assert.equal(res.success, false);
    assert.equal(res.errorCode, 'SMART_TOKEN_UNAVAILABLE');
    assert.equal(res.plaintextBuffer, undefined);
    fake.setDown(false);
  });

  it('sin custodio configurado: falla cerrado, sin fallback al wrap del Oracle', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await createCustodyPkg(oracle, fake);
    const savedUrl = process.env.SMART_TOKEN_API_URL;
    const savedKey = process.env.SMART_TOKEN_API_KEY;
    delete process.env.SMART_TOKEN_API_URL;
    delete process.env.SMART_TOKEN_API_KEY;
    try {
      const res = await unlockCustody(pkg, oracle, { master: MASTER });
      assert.equal(res.success, false);
      assert.equal(res.errorCode, 'SMART_TOKEN_CUSTODY_NOT_CONFIGURED');
      assert.equal(res.plaintextBuffer, undefined);
    } finally {
      if (savedUrl !== undefined) process.env.SMART_TOKEN_API_URL = savedUrl;
      if (savedKey !== undefined) process.env.SMART_TOKEN_API_KEY = savedKey;
    }
  });

  it('sin master: falla cerrado con SMART_TOKEN_MASTER_REQUIRED', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await createCustodyPkg(oracle, fake);
    const res = await unlockCustody(pkg, oracle, { custodian: fake });
    assert.equal(res.success, false);
    assert.equal(res.errorCode, 'SMART_TOKEN_MASTER_REQUIRED');
    assert.equal(res.plaintextBuffer, undefined);
  });

  it('proteger en custodia sin custodio o sin master: no se crea el paquete', async () => {
    const oracle = new AuthorizationOracle();
    await assert.rejects(
      () =>
        createTDCPPackage({
          plaintext: new TextEncoder().encode('x').buffer,
          password: 'PasswordOriginal!',
          originalFileName: 'x.txt',
          mimeType: 'text/plain',
          policyLevel: 'STANDARD',
          allowExtraction: false,
          oracle,
          cekCustodyMode: 'smart-token',
          smartTokenMaster: MASTER,
        }),
      /SMART_TOKEN_CUSTODY_REQUIRES_CUSTODIAN/
    );
    await assert.rejects(
      () =>
        createTDCPPackage({
          plaintext: new TextEncoder().encode('x').buffer,
          password: 'PasswordOriginal!',
          originalFileName: 'x.txt',
          mimeType: 'text/plain',
          policyLevel: 'STANDARD',
          allowExtraction: false,
          oracle,
          cekCustodyMode: 'smart-token',
          smartTokenCustodian: createInMemorySmartTokenCekCustodyFake(),
        }),
      /SMART_TOKEN_CUSTODY_REQUIRES_MASTER/
    );
  });

  it('formato: un paquete en custodia con CEK del Oracle o sin artefacto es inválido', async () => {
    const oracle = new AuthorizationOracle();
    const fake = createInMemorySmartTokenCekCustodyFake();
    const pkg = await createCustodyPkg(oracle, fake);

    const withOracleWrap = {
      ...pkg,
      wrappedKeyBase64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      ivKeyBase64: 'AAAAAAAAAAAAAAAA',
    };
    const tampered = await deserializeTDCPPackage(JSON.stringify(withOracleWrap));
    assert.equal(tampered.isValidEnvelope, false);
    assert.match(tampered.error ?? '', /CEK envuelta por el Oracle/);

    const withoutArtifact = { ...pkg, smartTokenCustody: undefined };
    const missing = await deserializeTDCPPackage(JSON.stringify(withoutArtifact));
    assert.equal(missing.isValidEnvelope, false);
    assert.match(missing.error ?? '', /sin referencia de custodia/);
  });

  it('regresión: el modo oracle por defecto sigue con roundtrip sin cambios', async () => {
    const oracle = new AuthorizationOracle();
    const pkg = await createTDCPPackage({
      plaintext: new TextEncoder().encode(PLAINTEXT).buffer,
      password: 'PasswordOriginal!',
      originalFileName: 'documento_oracle.txt',
      mimeType: 'text/plain',
      policyLevel: 'STANDARD',
      allowExtraction: false,
      oracle,
    });
    assert.equal(pkg.metadata.custodyMode, undefined);
    assert.ok(pkg.wrappedKeyBase64);
    assert.equal(pkg.smartTokenCustody, undefined);
    const res = await DCPGatekeeper.executeUnlock({
      packageData: pkg,
      userPassword: 'PasswordOriginal!',
      requestedOperation: 'RENDER_RAM',
      nfcProvider: new MockNFCProvider(),
      deviceProvider: new MockDeviceIdentityProvider(),
      biometricProvider: new MockBiometricProvider(),
      oracle,
      auditSink: new LocalAuditSink(),
    });
    assert.equal(res.success, true, res.errorMessage);
    assert.equal(new TextDecoder().decode(res.plaintextBuffer), PLAINTEXT);
  });

  it('adaptador HTTP: protect/open hablan el contrato del SmartTokenClient (fetch falso)', async () => {
    const cek = new Uint8Array(32).map((_, i) => i);
    const calls: string[] = [];
    const fetchImpl = (async (url: string | URL, init?: RequestInit): Promise<Response> => {
      const u = String(url);
      calls.push(`${init?.method ?? 'GET'} ${u}`);
      if (u.endsWith('/v1/artifacts') && init?.method === 'POST') {
        return Response.json({ artifact_id: 'STK-falso-http', status: 'PROTECTED' });
      }
      if (u.endsWith('/open') && init?.method === 'POST') {
        return new Response(cek as unknown as BodyInit, {
          status: 200,
          headers: { 'X-Smart-Token-Status': 'OPEN' },
        });
      }
      return new Response('nope', { status: 404 });
    }) as unknown as typeof fetch;

    const custodian = new HttpSmartTokenCekCustodian(
      new SmartTokenClient({ baseUrl: 'http://127.0.0.1:8000', apiKey: 'k', fetchImpl })
    );
    const ref = await custodian.protectCek(cek, MASTER);
    assert.equal(ref.artifactId, 'STK-falso-http');
    const release = await custodian.openCek(ref.artifactId, MASTER);
    assert.equal(release.ok, true);
    if (release.ok) assert.deepEqual([...release.cek], [...cek]);
    assert.deepEqual(calls, [
      'POST http://127.0.0.1:8000/v1/artifacts',
      'POST http://127.0.0.1:8000/v1/artifacts/STK-falso-http/open',
    ]);
  });
});
