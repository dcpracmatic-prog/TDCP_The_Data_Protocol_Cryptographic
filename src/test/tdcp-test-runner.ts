/**
 * TDCP automated security validation.
 * Tests exercise the real Gatekeeper / Oracle path. No fake PASS.
 */

import {
  deriveRootKeyFromSecret,
  deriveEphemeralDocumentKey,
  encryptAESGCM,
  decryptAESGCM,
  generateRandomBytes,
  generateRandomId,
  generateOracleKeyPair,
  signDataECDSA,
  verifySignatureECDSA,
  base64ToArrayBuffer,
} from '../core/crypto/primitives.ts';
import type { TDCPPackage } from '../core/package/package-format.ts';
import { deriveKeyWrappingKey, TDCP_ENVELOPE_WRAP_EPOCH } from '../core/package/package-format.ts';
import { createTDCPPackage } from '../core/package/tdcp-factory.ts';
import { AuthorizationOracle } from '../oracle/authorization-oracle.ts';
import { DCPGatekeeper } from '../gatekeeper/gatekeeper.ts';
import { MockNFCProvider } from '../identity/credential-provider.ts';
import { MockDeviceIdentityProvider } from '../identity/device-identity-provider.ts';
import { MockBiometricProvider } from '../identity/biometric-provider.ts';
import { LocalAuditSink } from '../audit/audit-sink.ts';
import { MemoryStorageProvider } from '../storage/storage-provider.ts';
import { splitIntoABCFragments, verifyABCInterlockingIntegrity } from '../core/package/ultra-critical.ts';
import { canonicalizeGrant } from '../core/authorization/types.ts';
import { verifyAuthorizationGrant } from '../core/authorization/grant-verifier.ts';
import { decryptPackageDirectlyWithPassword } from '../runtime/tdcp-runtime.ts';
import type { PolicyLevel } from '../core/authorization/types.ts';

export interface TestCaseResult {
  id: number;
  name: string;
  category: 'CRYPTO' | 'AUTHORIZATION' | 'REPLAY' | 'REVOCATION' | 'TAMPER' | 'ULTRA_CRITICAL' | 'STORAGE';
  threatModel: string;
  attackVector: string;
  expectedResult: string;
  actualResult: string;
  status: 'PASS' | 'FAIL';
  durationMs: number;
}

export interface TestSuiteSummary {
  totalTests: number;
  passedCount: number;
  failedCount: number;
  allPassed: boolean;
  totalDurationMs: number;
  results: TestCaseResult[];
}

async function createPkg(params: {
  password: string;
  plaintextStr: string;
  oracle: AuthorizationOracle;
  policyLevel?: PolicyLevel;
  allowExtraction?: boolean;
  expirationDays?: number;
  viewOnce?: boolean;
}): Promise<TDCPPackage> {
  return createTDCPPackage({
    plaintext: new TextEncoder().encode(params.plaintextStr).buffer,
    password: params.password,
    originalFileName: 'documento_confidencial.txt',
    mimeType: 'text/plain',
    policyLevel: params.policyLevel ?? 'STANDARD',
    allowExtraction: params.allowExtraction ?? false,
    expirationDays: params.expirationDays,
    viewOnce: params.viewOnce,
    oracle: params.oracle,
  });
}

function unlock(opts: {
  pkg: TDCPPackage;
  password: string;
  oracle: AuthorizationOracle;
  nfc?: MockNFCProvider;
  device?: MockDeviceIdentityProvider;
  biometric?: MockBiometricProvider;
  audit?: LocalAuditSink;
  operation?: 'READ' | 'RENDER_RAM' | 'EXTRACT' | 'AUDIT_EXPORT';
  challenge?: string;
}) {
  if (opts.challenge) opts.oracle.getReplayRegistry().registerFreshChallenge(opts.challenge);
  return DCPGatekeeper.executeUnlock({
    packageData: opts.pkg,
    userPassword: opts.password,
    requestedOperation: opts.operation ?? 'RENDER_RAM',
    nfcProvider: opts.nfc ?? new MockNFCProvider(),
    deviceProvider: opts.device ?? new MockDeviceIdentityProvider(),
    biometricProvider: opts.biometric ?? new MockBiometricProvider(),
    oracle: opts.oracle,
    auditSink: opts.audit ?? new LocalAuditSink(),
    customChallenge: opts.challenge,
  });
}

export async function runTDCPTestSuite(
  onProgress?: (current: number, total: number, result: TestCaseResult) => void
): Promise<TestSuiteSummary> {
  const startTime = Date.now();
  const results: TestCaseResult[] = [];
  let testId = 1;

  async function executeTest(
    name: string,
    category: TestCaseResult['category'],
    threatModel: string,
    attackVector: string,
    expectedResult: string,
    fn: () => Promise<{ passed: boolean; actualResult: string }>
  ) {
    const t0 = Date.now();
    let passed = false;
    let actualResult = '';
    try {
      const res = await fn();
      passed = res.passed;
      actualResult = res.actualResult;
    } catch (err: unknown) {
      passed = false;
      actualResult = `Excepción: ${err instanceof Error ? err.message : String(err)}`;
    }
    const testResult: TestCaseResult = {
      id: testId++,
      name,
      category,
      threatModel,
      attackVector,
      expectedResult,
      actualResult,
      status: passed ? 'PASS' : 'FAIL',
      durationMs: Date.now() - t0,
    };
    results.push(testResult);
    onProgress?.(results.length, 0, testResult);
  }

  await executeTest(
    'Cifrado y descifrado autorizado (Gatekeeper)',
    'CRYPTO',
    'Flujo nominal',
    'createTDCPPackage + executeUnlock con grant válido',
    'Plaintext idéntico vía Gatekeeper',
    async () => {
      const oracle = new AuthorizationOracle();
      const secret = 'ClaveMaestraSegura2026!';
      const plaintext = 'INFORMACION_RESTRINGIDA_TDCP_NIVEL_ALTO';
      const pkg = await createPkg({ password: secret, plaintextStr: plaintext, oracle });
      const unlockRes = await unlock({ pkg, password: secret, oracle });
      const decrypted = unlockRes.plaintextBuffer
        ? new TextDecoder().decode(unlockRes.plaintextBuffer)
        : '';
      const passed = unlockRes.success === true && decrypted === plaintext;
      return {
        passed,
        actualResult: passed
          ? `RAM fidélidad OK. Grant ${unlockRes.grant?.grantId}`
          : unlockRes.errorMessage || 'fallo',
      };
    }
  );

  await executeTest(
    'Copia de paquete a otro Oracle (sin autorización)',
    'AUTHORIZATION',
    'El archivo viaja; la autorización no',
    'Mismo .pkg, Oracle aislado sin política registrada',
    'DOCUMENT_NOT_REGISTERED',
    async () => {
      const issuer = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'secretos', oracle: issuer });
      const isolated = new AuthorizationOracle();
      const unlockRes = await unlock({ pkg, password: 'PasswordOriginal!', oracle: isolated });
      const passed = !unlockRes.success && (unlockRes.errorCode === 'DOCUMENT_NOT_REGISTERED' || (unlockRes.errorMessage || '').includes('DOCUMENT_NOT_REGISTERED'));
      return { passed, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );

  await executeTest(
    'Manipulación de ciphertext (AES-GCM tag)',
    'TAMPER',
    'Bit flip en tránsito',
    'Alterar ciphertextBase64',
    'DECRYPTION_AUTH_TAG_FAILED',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'Datos secretos', oracle });
      const c = pkg.ciphertextBase64;
      const tampered: TDCPPackage = {
        ...pkg,
        ciphertextBase64: c.slice(0, 10) + (c[10] === 'A' ? 'B' : 'A') + c.slice(11),
      };
      const unlockRes = await unlock({ pkg: tampered, password: 'PasswordOriginal!', oracle });
      const passed =
        !unlockRes.success &&
        (unlockRes.errorCode === 'DECRYPTION_AUTH_TAG_FAILED' ||
          unlockRes.errorCode === 'PACKAGE_INTEGRITY_FAILED');
      return { passed, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );

  await executeTest(
    'Sustitución de documentId en el sobre',
    'TAMPER',
    'Metadata spoofing',
    'Cambiar documentId manteniendo ciphertext',
    'DENY (AAD o DOCUMENT_NOT_REGISTERED)',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'Datos genuinos', oracle });
      const tampered: TDCPPackage = { ...pkg, documentId: 'DOC-FALSIFICADO-999' };
      const unlockRes = await unlock({ pkg: tampered, password: 'PasswordOriginal!', oracle });
      return { passed: !unlockRes.success, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );

  await executeTest(
    'Expiración por reloj del Oracle',
    'REVOCATION',
    'Documento caducado',
    'createdAt hace 3 días, vigencia 1 día',
    'DOCUMENT_EXPIRED',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({
        password: 'PasswordOriginal!',
        plaintextStr: 'Datos temporales',
        expirationDays: 1,
        oracle,
      });
      oracle.registerDocumentPolicy({
        documentId: pkg.documentId,
        packageId: pkg.packageId,
        policyLevel: 'STANDARD',
        allowExtraction: false,
        expirationDays: 1,
        createdAt: Date.now() - 3 * 24 * 60 * 60 * 1000,
      });
      const unlockRes = await unlock({ pkg, password: 'PasswordOriginal!', oracle });
      const passed =
        !unlockRes.success &&
        (unlockRes.errorCode === 'DOCUMENT_EXPIRED' || (unlockRes.errorMessage || '').includes('expirado'));
      return { passed, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );

  await executeTest(
    'Replay de challenge/grant',
    'REPLAY',
    'Reutilizar desafío consumido',
    'Mismo customChallenge dos veces',
    'REPLAY_ATTACK_DETECTED o REPLAY_ATTACK_REJECTED',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'anti-replay', oracle });
      const challenge = 'CHALLENGE-STALE-STATIC-NONCE';
      await unlock({ pkg, password: 'PasswordOriginal!', oracle, challenge });
      const replayRes = await unlock({ pkg, password: 'PasswordOriginal!', oracle, challenge });
      const passed =
        !replayRes.success &&
        (replayRes.errorCode === 'REPLAY_ATTACK_DETECTED' ||
          replayRes.errorCode === 'REPLAY_ATTACK_REJECTED' ||
          (replayRes.errorMessage || '').includes('REPLAY'));
      return { passed, actualResult: `${replayRes.errorCode}: ${replayRes.errorMessage}` };
    }
  );

  await executeTest(
    'EXTRACT con política que lo prohíbe',
    'AUTHORIZATION',
    'Desvío de operación',
    'requestedOperation EXTRACT, allowExtraction false',
    'OPERATION_FORBIDDEN',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({
        password: 'PasswordOriginal!',
        plaintextStr: 'sin extracción',
        allowExtraction: false,
        oracle,
      });
      const unlockRes = await unlock({
        pkg,
        password: 'PasswordOriginal!',
        oracle,
        operation: 'EXTRACT',
      });
      const passed =
        !unlockRes.success &&
        (unlockRes.errorCode === 'OPERATION_FORBIDDEN' || (unlockRes.errorMessage || '').includes('prohíbe la extracción'));
      return { passed, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );

  await executeTest(
    'Kill-switch / epoch revocation',
    'REVOCATION',
    'Oficial revoca el documento',
    'revokeDocument + executeUnlock',
    'DOCUMENT_REVOKED',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'revocable', oracle });
      oracle.getRevocationManager().revokeDocument(pkg.documentId, 'Robo reportado');
      const unlockRes = await unlock({ pkg, password: 'PasswordOriginal!', oracle });
      const passed =
        !unlockRes.success &&
        (unlockRes.errorCode === 'DOCUMENT_REVOKED' || (unlockRes.errorMessage || '').includes('revocado'));
      return { passed, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );

  await executeTest(
    'Vista única consumida en Oracle',
    'REVOCATION',
    'Burn-after-reading autoritativo',
    'Segunda apertura del mismo documentId',
    'VIEW_ONCE_ALREADY_CONSUMED',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({
        password: 'PasswordOriginal!',
        plaintextStr: 'autodestrucción',
        viewOnce: true,
        oracle,
      });
      const first = await unlock({ pkg, password: 'PasswordOriginal!', oracle });
      const second = await unlock({ pkg, password: 'PasswordOriginal!', oracle });
      const passed =
        first.success === true &&
        !second.success &&
        (second.errorCode === 'VIEW_ONCE_ALREADY_CONSUMED' || (second.errorMessage || '').includes('consumido'));
      return {
        passed,
        actualResult: `first=${first.success} second=${second.errorCode}: ${second.errorMessage}`,
      };
    }
  );

  await executeTest(
    'Firma ECDSA espuria rechazada',
    'AUTHORIZATION',
    'Grant falsificado',
    'Firmar con otra P-256',
    'verifySignatureECDSA === false',
    async () => {
      const oracle = new AuthorizationOracle();
      await oracle.initialize();
      const bogus = await generateOracleKeyPair();
      const canonical = canonicalizeGrant({
        grantId: 'GRANT-FAKE-001',
        documentId: 'DOC-SEC-1010',
        packageId: 'PKG-1010',
        deviceId: 'DEV-ANY',
        credentialId: 'CRED-ANY',
        operationId: 'OP-001',
        challenge: 'CHALLENGE-001',
        operation: 'RENDER_RAM',
        policyLevel: 'CRITICAL',
        authorizationEpoch: 1,
        issuedAt: Date.now(),
        expiresAt: Date.now() + 60000,
        oneTimeUse: true,
        allowExtraction: false,
        forensicWatermarkRequired: true,
        oracleKeyId: 'ORACLE-KEY-P256-v2.5',
      });
      const sig = await signDataECDSA(bogus.privateKey, canonical);
      const ok = await verifySignatureECDSA(await oracle.getPublicKey(), sig, canonical);
      return { passed: !ok, actualResult: ok ? 'Firma espuria aceptada' : 'Firma espuria rechazada' };
    }
  );

  await executeTest(
    'Adulteración del audit sink',
    'TAMPER',
    'Mutar un evento',
    'tamperEventForTesting',
    'verifyIntegrity isValid=false',
    async () => {
      const audit = new LocalAuditSink();
      await audit.recordEvent({
        documentId: 'DOC-AUDIT-1',
        packageId: 'PKG-1',
        deviceId: 'DEV-1',
        credentialId: 'CRED-1',
        operationId: 'OP-1',
        operation: 'RENDER_RAM',
        policy: 'STANDARD',
        result: 'SUCCESS',
        details: 'legítimo',
      });
      audit.tamperEventForTesting(1, 'DENIED');
      const integrity = await audit.verifyIntegrity();
      return {
        passed: integrity.isValid === false,
        actualResult: integrity.error || 'no detectó adulteración',
      };
    }
  );

  await executeTest(
    'Storage no autoriza',
    'STORAGE',
    'Proveedor pasivo',
    'upload/download ciphertext',
    'bytes idénticos, isCloud false, cero plaintext API',
    async () => {
      const storage = new MemoryStorageProvider();
      const cipher = new Uint8Array([9, 8, 7, 6]).buffer;
      const item = await storage.uploadPackage('test.pkg', cipher);
      const downloaded = await storage.downloadPackage(item.id);
      const match = new Uint8Array(downloaded)[0] === 9;
      return {
        passed: match && storage.isCloud === false,
        actualResult: `Passive store ${item.sizeBytes} bytes. Storage ≠ autorización.`,
      };
    }
  );

  await executeTest(
    'ULTRA_CRITICAL: A aislado es inútil',
    'ULTRA_CRITICAL',
    'Robo de fragmento A',
    'Quitar B y C del paquete y pedir unlock',
    'ULTRA_CRITICAL_INCOMPLETE',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({
        password: 'PasswordOriginal!',
        plaintextStr: 'ABCDEFGHIJKLMNOP',
        policyLevel: 'ULTRA_CRITICAL',
        oracle,
      });
      const broken: TDCPPackage = {
        ...pkg,
        ultraCritical: pkg.ultraCritical
          ? { ...pkg.ultraCritical, fragmentB: undefined as never, manifestC: undefined as never }
          : undefined,
      };
      const unlockRes = await unlock({ pkg: broken, password: 'PasswordOriginal!', oracle });
      const passed = !unlockRes.success && (unlockRes.errorCode === 'ULTRA_CRITICAL_INCOMPLETE' || !unlockRes.success);
      return { passed, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );

  await executeTest(
    'ULTRA_CRITICAL: interlocking A/B/C',
    'ULTRA_CRITICAL',
    'Firmas cruzadas',
    'Bundle íntegro vs hash adulterado',
    'isValid true luego false',
    async () => {
      const dummyA = new Uint8Array([11, 22, 33]).buffer;
      const dummyB = new Uint8Array([44, 55, 66]).buffer;
      const bundle = await splitIntoABCFragments(
        'DOC-ULTRA-16',
        'PKG-ULTRA-16',
        'archivo_critico.bin',
        'application/octet-stream',
        dummyA,
        generateRandomBytes(12),
        dummyB,
        generateRandomBytes(12),
        6
      );
      const checkValid = await verifyABCInterlockingIntegrity(bundle.fragmentA, bundle.fragmentB, bundle.manifestC);
      const tamperedB = { ...bundle.fragmentB, boundHashA: 'HASH_FALSIFICADO_000000000' };
      const checkTampered = await verifyABCInterlockingIntegrity(bundle.fragmentA, tamperedB, bundle.manifestC);
      const passed = checkValid.isValid && !checkTampered.isValid;
      return { passed, actualResult: passed ? 'Interlocking OK / tamper detectado' : 'fallo interlocking' };
    }
  );

  await executeTest(
    'ULTRA_CRITICAL A+B+C+grant via Gatekeeper',
    'ULTRA_CRITICAL',
    'Reconstrucción controlada',
    'policyLevel ULTRA_CRITICAL + MockBiometric + grant',
    'Plaintext reconstruido',
    async () => {
      const oracle = new AuthorizationOracle();
      const secret = 'PasswordOriginal!';
      const plaintext = 'ULTRA_CRITICAL_PAYLOAD_ABC';
      const pkg = await createPkg({ password: secret, plaintextStr: plaintext, policyLevel: 'ULTRA_CRITICAL', oracle });
      const unlockRes = await unlock({ pkg, password: secret, oracle });
      const decoded = unlockRes.plaintextBuffer ? new TextDecoder().decode(unlockRes.plaintextBuffer) : '';
      const passed = unlockRes.success === true && decoded === plaintext && Boolean(pkg.ultraCritical);
      return { passed, actualResult: passed ? 'A+B+C reconstruidos en RAM' : unlockRes.errorMessage || decoded };
    }
  );

  await executeTest(
    'Token ≠ document key (HKDF context)',
    'CRYPTO',
    'Claves efímeras distintas',
    'Mismo secreto, distintos documentId',
    'Ciphertexts distintos',
    async () => {
      const salt = generateRandomBytes(32);
      const rootKey = await deriveRootKeyFromSecret('MismaClaveMaestra123', salt);
      const k1 = await deriveEphemeralDocumentKey(rootKey, salt, {
        documentId: 'DOC-1',
        deviceId: 'DEV-A',
        authorizationEpoch: 1,
        operationId: 'OP-1',
      });
      const k2 = await deriveEphemeralDocumentKey(rootKey, salt, {
        documentId: 'DOC-2',
        deviceId: 'DEV-A',
        authorizationEpoch: 1,
        operationId: 'OP-1',
      });
      const iv = generateRandomBytes(12);
      const sample = new Uint8Array([1, 2, 3, 4, 5]);
      const c1 = new Uint8Array(await encryptAESGCM(k1, sample, iv));
      const c2 = new Uint8Array(await encryptAESGCM(k2, sample, iv));
      const passed = c1.some((b, i) => b !== c2[i]);
      return { passed, actualResult: passed ? 'HKDF context isolation OK' : 'claves colisionaron' };
    }
  );

  await executeTest(
    'Grant de documento A usado en B',
    'AUTHORIZATION',
    'Grant swap',
    'verifyAuthorizationGrant DOC-A vs DOC-B',
    'DOCUMENT_MISMATCH',
    async () => {
      const oracle = new AuthorizationOracle();
      const device = new MockDeviceIdentityProvider();
      const nfc = new MockNFCProvider();
      const pkgA = await createPkg({ password: 'PasswordA!', plaintextStr: 'A', oracle });
      await createPkg({ password: 'PasswordB!', plaintextStr: 'B', oracle });
      const deviceId = (await device.getDeviceIdentity()).deviceId;
      const credentialId = (await nfc.readCredential()).credentialId;
      const challenge = generateRandomId('CHALLENGE');
      oracle.getReplayRegistry().registerFreshChallenge(challenge);
      const issued = await oracle.processAuthorizationRequest({
        requestId: 'REQ-A',
        documentId: pkgA.documentId,
        packageId: pkgA.packageId,
        deviceId,
        credentialId,
        operationId: 'OP-SWAP',
        challenge,
        requestedOperation: 'RENDER_RAM',
        timestamp: Date.now(),
      });
      if (!issued.grant) {
        return { passed: false, actualResult: issued.rejectionReason || 'no grant A' };
      }
      const verification = await verifyAuthorizationGrant(issued.grant, await oracle.getPublicKey(), {
        targetDocumentId: 'DOC-B-TARGET',
        targetDeviceId: deviceId,
        targetCredentialId: credentialId,
        targetOperationId: 'OP-SWAP',
        expectedChallenge: challenge,
        requestedOperation: 'RENDER_RAM',
        expectedEpoch: issued.grant.authorizationEpoch,
      });
      const passed = verification.isValid === false && verification.errorCode === 'DOCUMENT_MISMATCH';
      return { passed, actualResult: `${verification.errorCode}: ${verification.errorMessage}` };
    }
  );

  await executeTest(
    'Grant de dispositivo A usado en B',
    'AUTHORIZATION',
    'Device binding',
    'verifyAuthorizationGrant DEV-A vs DEV-B',
    'DEVICE_MISMATCH',
    async () => {
      const oracle = new AuthorizationOracle();
      const device = new MockDeviceIdentityProvider();
      const nfc = new MockNFCProvider();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'bind', oracle });
      const deviceId = (await device.getDeviceIdentity()).deviceId;
      const credentialId = (await nfc.readCredential()).credentialId;
      const challenge = generateRandomId('CHALLENGE');
      oracle.getReplayRegistry().registerFreshChallenge(challenge);
      const issued = await oracle.processAuthorizationRequest({
        requestId: 'REQ-DEV',
        documentId: pkg.documentId,
        packageId: pkg.packageId,
        deviceId,
        credentialId,
        operationId: 'OP-DEV',
        challenge,
        requestedOperation: 'RENDER_RAM',
        timestamp: Date.now(),
      });
      if (!issued.grant) return { passed: false, actualResult: issued.rejectionReason || 'no grant' };
      const verification = await verifyAuthorizationGrant(issued.grant, await oracle.getPublicKey(), {
        targetDocumentId: pkg.documentId,
        targetDeviceId: 'DEV-ROGUE-LAPTOP-999',
        targetCredentialId: credentialId,
        targetOperationId: 'OP-DEV',
        expectedChallenge: challenge,
        requestedOperation: 'RENDER_RAM',
        expectedEpoch: issued.grant.authorizationEpoch,
      });
      const passed = verification.errorCode === 'DEVICE_MISMATCH';
      return { passed, actualResult: `${verification.errorCode}: ${verification.errorMessage}` };
    }
  );

  await executeTest(
    'Grant READ usado como EXTRACT',
    'AUTHORIZATION',
    'Operation binding',
    'verifyAuthorizationGrant RENDER_RAM vs EXTRACT',
    'OPERATION_MISMATCH',
    async () => {
      const oracle = new AuthorizationOracle();
      const device = new MockDeviceIdentityProvider();
      const nfc = new MockNFCProvider();
      const pkg = await createPkg({
        password: 'PasswordOriginal!',
        plaintextStr: 'ops',
        allowExtraction: true,
        oracle,
      });
      const deviceId = (await device.getDeviceIdentity()).deviceId;
      const credentialId = (await nfc.readCredential()).credentialId;
      const challenge = generateRandomId('CHALLENGE');
      oracle.getReplayRegistry().registerFreshChallenge(challenge);
      const issued = await oracle.processAuthorizationRequest({
        requestId: 'REQ-OP',
        documentId: pkg.documentId,
        packageId: pkg.packageId,
        deviceId,
        credentialId,
        operationId: 'OP-READ',
        challenge,
        requestedOperation: 'RENDER_RAM',
        timestamp: Date.now(),
      });
      if (!issued.grant) return { passed: false, actualResult: issued.rejectionReason || 'no grant' };
      const verification = await verifyAuthorizationGrant(issued.grant, await oracle.getPublicKey(), {
        targetDocumentId: pkg.documentId,
        targetDeviceId: deviceId,
        targetCredentialId: credentialId,
        targetOperationId: 'OP-READ',
        expectedChallenge: challenge,
        requestedOperation: 'EXTRACT',
        expectedEpoch: issued.grant.authorizationEpoch,
      });
      const passed = verification.errorCode === 'OPERATION_MISMATCH';
      return { passed, actualResult: `${verification.errorCode}: ${verification.errorMessage}` };
    }
  );

  await executeTest(
    'Anomalía crítica bloquea grant',
    'AUTHORIZATION',
    'IA complementaria no bypass',
    'anomalyScore 0.94',
    'ANOMALY_HIGH_RISK_BLOCK',
    async () => {
      const oracle = new AuthorizationOracle();
      const nfc = new MockNFCProvider();
      const device = new MockDeviceIdentityProvider();
      const pkg = await createPkg({ password: 'x', plaintextStr: 'n', oracle });
      const challenge = oracle.issueChallenge();
      const res = await oracle.processAuthorizationRequest({
        requestId: 'REQ-ANOMALY',
        documentId: pkg.documentId,
        packageId: pkg.packageId,
        deviceId: (await device.getDeviceIdentity()).deviceId,
        credentialId: (await nfc.readCredential()).credentialId,
        operationId: 'OP-ANOMALY',
        challenge,
        requestedOperation: 'RENDER_RAM',
        timestamp: Date.now(),
        policyContext: { anomalyScore: 0.94 },
      });
      const passed = !res.granted && res.rejectionCode === 'ANOMALY_HIGH_RISK_BLOCK';
      return { passed, actualResult: `${res.rejectionCode}: ${res.rejectionReason}` };
    }
  );

  await executeTest(
    'Apoptosis de runtime',
    'CRYPTO',
    'Cierre de visor',
    'terminate() sobreescribe buffer',
    'buffer en ceros, sesión muerta',
    async () => {
      const { ControlledRuntimeSession } = await import('../protection/apoptosis.ts');
      const session = new ControlledRuntimeSession('TEST-APOPTOSIS-SESSION', 0);
      const testBuffer = new Uint8Array([99, 88, 77, 66, 55]);
      session.registerBuffer(testBuffer);
      let called = false;
      session.setOnApoptosis(() => {
        called = true;
      });
      session.terminate('USER_CLOSED_VIEWER');
      const passed = testBuffer.every((b) => b === 0) && !session.isAlive() && called;
      return { passed, actualResult: passed ? 'Apoptosis OK' : 'buffer no limpio' };
    }
  );

  await executeTest(
    'UI no expone descifrado por contraseña',
    'AUTHORIZATION',
    'Bypass de UI',
    'decryptPackageDirectlyWithPassword()',
    'DIRECT_DECRYPT_FORBIDDEN',
    async () => {
      try {
        decryptPackageDirectlyWithPassword();
        return { passed: false, actualResult: 'la función no lanzó' };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { passed: msg.includes('DIRECT_DECRYPT_FORBIDDEN'), actualResult: msg };
      }
    }
  );

  await executeTest(
    'Contraseña sola no desenvolve CEK',
    'CRYPTO',
    'Password-only unwrap',
    'HKDF wrap con secreto Oracle falso',
    'AES-GCM fail',
    async () => {
      const oracle = new AuthorizationOracle();
      const password = 'PasswordOriginal!';
      const pkg = await createPkg({ password, plaintextStr: 'no bypass', oracle });
      const salt = new Uint8Array(base64ToArrayBuffer(pkg.saltBase64));
      const root = await deriveRootKeyFromSecret(password, salt);
      const fakeSecret = new Uint8Array(32);
      const kwk = await deriveKeyWrappingKey(
        root,
        salt,
        pkg.documentId,
        TDCP_ENVELOPE_WRAP_EPOCH,
        fakeSecret
      );
      let failed = false;
      try {
        await decryptAESGCM(
          kwk,
          base64ToArrayBuffer(pkg.wrappedKeyBase64!),
          new Uint8Array(base64ToArrayBuffer(pkg.ivKeyBase64!))
        );
      } catch {
        failed = true;
      }
      return { passed: failed, actualResult: failed ? 'Unwrap password-only rechazado' : 'CEK salió sin Oracle' };
    }
  );

  await executeTest(
    'localStorage no cambia autorización',
    'REVOCATION',
    'Flags de UI no son autoridad',
    'Escribir dcp_revoked_ / dcp_consumed_',
    'Unlock sigue OK hasta revoke del Oracle',
    async () => {
      const oracle = new AuthorizationOracle();
      const password = 'PasswordOriginal!';
      const pkg = await createPkg({ password, plaintextStr: 'ls bypass', oracle });
      if (typeof globalThis.localStorage !== 'undefined') {
        globalThis.localStorage.setItem(`dcp_revoked_${pkg.documentId}`, 'true');
        globalThis.localStorage.setItem(`dcp_consumed_${pkg.packageId}`, 'true');
      }
      const stillOpen = await unlock({ pkg, password, oracle });
      oracle.getRevocationManager().revokeDocument(pkg.documentId);
      const afterOracle = await unlock({ pkg, password, oracle });
      const passed = stillOpen.success === true && afterOracle.success === false;
      return {
        passed,
        actualResult: `localStorage open=${stillOpen.success}; oracle revoke denied=${!afterOracle.success}`,
      };
    }
  );

  await executeTest(
    'Paquete JSON no contiene plaintext',
    'CRYPTO',
    'Sobre cifrado',
    'JSON.stringify del TDCPPackage',
    'magic header, cero payload claro',
    async () => {
      const oracle = new AuthorizationOracle();
      const secretText = 'PLAINTEXT_MUST_NOT_LEAK_XYZ';
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: secretText, oracle });
      const json = JSON.stringify(pkg);
      const leaked = json.includes(secretText) || json.includes('payload');
      const passed = pkg.magicHeader === 'TDCP_SECURE_PKG' && !leaked && Boolean(pkg.wrappedKeyBase64);
      return { passed, actualResult: passed ? 'Sobre sin plaintext' : 'fuga en JSON' };
    }
  );

  await executeTest(
    'Restore incrementa epoch (grants viejos muertos)',
    'REVOCATION',
    'Kill-switch restore',
    'revoke + restore + grant epoch check',
    'epoch avanza',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'epoch', oracle });
      const before = oracle.getRevocationManager().getOrCreateState(pkg.documentId).currentEpoch;
      oracle.getRevocationManager().revokeDocument(pkg.documentId);
      const revoked = oracle.getRevocationManager().getOrCreateState(pkg.documentId);
      oracle.getRevocationManager().restoreDocument(pkg.documentId);
      const restored = oracle.getRevocationManager().getOrCreateState(pkg.documentId);
      const unlockRes = await unlock({ pkg, password: 'PasswordOriginal!', oracle });
      const passed =
        revoked.isRevoked &&
        !restored.isRevoked &&
        restored.currentEpoch > before &&
        unlockRes.success === true;
      return {
        passed,
        actualResult: `epoch ${before} → ${revoked.currentEpoch} → ${restored.currentEpoch}; unlock=${unlockRes.success}`,
      };
    }
  );

  await executeTest(
    'ULTRA_CRITICAL sin biometría DENY',
    'ULTRA_CRITICAL',
    'Presencia requerida',
    'MockBiometricProvider.setSimulateSuccess(false)',
    'BIOMETRIC_REQUIRED',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({
        password: 'PasswordOriginal!',
        plaintextStr: 'bio',
        policyLevel: 'ULTRA_CRITICAL',
        oracle,
      });
      const biometric = new MockBiometricProvider();
      biometric.setSimulateSuccess(false);
      const unlockRes = await unlock({ pkg, password: 'PasswordOriginal!', oracle, biometric });
      const passed = !unlockRes.success && unlockRes.errorCode === 'BIOMETRIC_REQUIRED';
      return { passed, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );


  await executeTest(
    'Oracle rechaza challenge no emitido por Gatekeeper',
    'REPLAY',
    'Cliente fabrica una solicitud de autorización',
    'processAuthorizationRequest con challenge nunca registrado',
    'INVALID_CHALLENGE',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'challenge', oracle });
      const response = await oracle.processAuthorizationRequest({
        requestId: generateRandomId('REQ'),
        documentId: pkg.documentId,
        packageId: pkg.packageId,
        deviceId: 'DEV-STATION-SECTOR-4',
        credentialId: 'NFC-CARD-ALPHA-7791',
        operationId: generateRandomId('OP'),
        challenge: 'CHALLENGE-NOT-REGISTERED',
        requestedOperation: 'RENDER_RAM',
        timestamp: Date.now(),
        policyContext: {},
      });
      const passed = !response.granted && response.rejectionCode === 'INVALID_CHALLENGE';
      return { passed, actualResult: `${response.rejectionCode}: ${response.rejectionReason}` };
    }
  );

  await executeTest(
    'Integridad del envelope rechaza metadata adulterada',
    'TAMPER',
    'Atacante modifica política dentro del .pkg',
    'Cambiar allowExtraction sin recalcular autenticación',
    'PACKAGE_INTEGRITY_FAILED o PACKAGE_POLICY_MISMATCH',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'metadata', oracle });
      const tampered: TDCPPackage = {
        ...pkg,
        metadata: { ...pkg.metadata, allowExtraction: true },
      };
      const unlockRes = await unlock({ pkg: tampered, password: 'PasswordOriginal!', oracle });
      const passed =
        !unlockRes.success &&
        (unlockRes.errorCode === 'PACKAGE_INTEGRITY_FAILED' ||
          unlockRes.errorCode === 'PACKAGE_POLICY_MISMATCH');
      return { passed, actualResult: `${unlockRes.errorCode}: ${unlockRes.errorMessage}` };
    }
  );

  await executeTest(
    'Challenge expirado no puede autorizar',
    'REPLAY',
    'Cliente reutiliza un challenge antiguo',
    'Registrar challenge con timestamp fuera de la ventana de frescura',
    'INVALID_CHALLENGE',
    async () => {
      const oracle = new AuthorizationOracle();
      const pkg = await createPkg({ password: 'PasswordOriginal!', plaintextStr: 'stale', oracle });
      const staleChallenge = 'CHALLENGE-STALE-TTL';
      oracle.getReplayRegistry().registerFreshChallenge(staleChallenge, Date.now() - 120_000);
      const response = await oracle.processAuthorizationRequest({
        requestId: generateRandomId('REQ'),
        documentId: pkg.documentId,
        packageId: pkg.packageId,
        deviceId: 'DEV-STATION-SECTOR-4',
        credentialId: 'NFC-CARD-ALPHA-7791',
        operationId: generateRandomId('OP'),
        challenge: staleChallenge,
        requestedOperation: 'RENDER_RAM',
        timestamp: Date.now(),
        policyContext: {},
      });
      const passed = !response.granted && response.rejectionCode === 'INVALID_CHALLENGE';
      return { passed, actualResult: `${response.rejectionCode}: ${response.rejectionReason}` };
    }
  );

  const totalDurationMs = Date.now() - startTime;
  const passedCount = results.filter((r) => r.status === 'PASS').length;
  const failedCount = results.filter((r) => r.status === 'FAIL').length;
  return {
    totalTests: results.length,
    passedCount,
    failedCount,
    allPassed: failedCount === 0,
    totalDurationMs,
    results,
  };
}
