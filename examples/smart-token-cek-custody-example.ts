/**
 * Example: Smart Token como custodio de la CEK (P2-6) — smoke end-to-end.
 *
 * Este ejemplo corre SIN servidor real: usa el doble en memoria
 * (`createInMemorySmartTokenCekCustodyFake`) para mostrar el flujo completo
 * proteger → abrir vía Gatekeeper. El doble es solo para demostrar/probar;
 * en producción el custodio es el servicio Smart-Token-Prod real:
 *
 *   import { smartTokenCekCustodianFromEnv } from '../src/protection/smart-token-cek-custody.ts';
 *   const custodian = smartTokenCekCustodianFromEnv(); // SMART_TOKEN_API_URL + SMART_TOKEN_API_KEY
 *   // ...y pásalo igual a createTDCPPackage / executeUnlock.
 *
 * La contraseña maestra la decide el emisor y se entrega por operación:
 * aquí es un valor de ejemplo, nunca se guarda en ningún archivo.
 *
 * Usage (from repo root, with Node that supports strip-types):
 *   node --experimental-strip-types examples/smart-token-cek-custody-example.ts
 */

import { createTDCPPackage } from '../src/core/package/tdcp-factory.ts';
import { serializeTDCPPackage, deserializeTDCPPackage } from '../src/core/package/package-format.ts';
import { AuthorizationOracle } from '../src/oracle/authorization-oracle.ts';
import { DCPGatekeeper } from '../src/gatekeeper/gatekeeper.ts';
import { MockNFCProvider } from '../src/identity/credential-provider.ts';
import { MockDeviceIdentityProvider } from '../src/identity/device-identity-provider.ts';
import { MockBiometricProvider } from '../src/identity/biometric-provider.ts';
import { LocalAuditSink } from '../src/audit/audit-sink.ts';
import { createInMemorySmartTokenCekCustodyFake } from '../src/protection/smart-token-cek-custody.ts';

async function main(): Promise<void> {
  const t0 = Date.now();
  const oracle = new AuthorizationOracle();
  const custodian = createInMemorySmartTokenCekCustodyFake();
  const master = 'master-de-ejemplo-decide-el-emisor';
  const plaintext = 'Documento con CEK custodiada por Smart Token.';

  // 1. PROTEGER en modo smart-token-custody (la CEK va al custodio, no al Oracle).
  const pkg = await createTDCPPackage({
    plaintext: new TextEncoder().encode(plaintext).buffer,
    password: 'PasswordOriginal!',
    originalFileName: 'documento_custodiado.txt',
    mimeType: 'text/plain',
    policyLevel: 'STANDARD',
    allowExtraction: false,
    oracle,
    cekCustodyMode: 'smart-token',
    smartTokenCustodian: custodian,
    smartTokenMaster: master,
  });
  console.log(`PROTEGER ok (${Date.now() - t0} ms): DOC=${pkg.documentId}`);
  console.log(`  custodyMode=${pkg.metadata.custodyMode} artifactId=${pkg.smartTokenCustody?.artifactId}`);
  console.log(`  wrappedKeyBase64 presente: ${pkg.wrappedKeyBase64 !== undefined} (debe ser false)`);

  // 2. El .pkg viaja solo (serializar/deserializar) y se abre vía Gatekeeper.
  const blob = await serializeTDCPPackage(pkg);
  const parsed = await deserializeTDCPPackage(await blob.arrayBuffer());
  if (!parsed.isValidEnvelope || !parsed.package) throw new Error(`Sobre inválido: ${parsed.error}`);

  const t1 = Date.now();
  const res = await DCPGatekeeper.executeUnlock({
    packageData: parsed.package,
    userPassword: 'PasswordOriginal!',
    requestedOperation: 'RENDER_RAM',
    nfcProvider: new MockNFCProvider(),
    deviceProvider: new MockDeviceIdentityProvider(),
    biometricProvider: new MockBiometricProvider(),
    oracle,
    auditSink: new LocalAuditSink(),
    smartTokenCustodian: custodian,
    smartTokenMaster: master,
  });
  console.log(`ABRIR ok=${res.success} (${Date.now() - t1} ms, grant=${res.grant?.grantId ?? '—'})`);
  if (!res.success || !res.plaintextBuffer) throw new Error(`Apertura fallida: ${res.errorCode} ${res.errorMessage}`);
  const text = new TextDecoder().decode(res.plaintextBuffer);
  console.log(`  texto idéntico: ${text === plaintext}`);

  // 3. Sin grant válido no hay apertura: documento revocado, Smart Token ni se contacta.
  const opensBefore = custodian.opens;
  oracle.getRevocationManager().revokeDocument(pkg.documentId, 'Ejemplo: revocado');
  const denied = await DCPGatekeeper.executeUnlock({
    packageData: parsed.package,
    userPassword: 'PasswordOriginal!',
    requestedOperation: 'RENDER_RAM',
    nfcProvider: new MockNFCProvider(),
    deviceProvider: new MockDeviceIdentityProvider(),
    biometricProvider: new MockBiometricProvider(),
    oracle,
    auditSink: new LocalAuditSink(),
    smartTokenCustodian: custodian,
    smartTokenMaster: master,
  });
  console.log(`Revocado: success=${denied.success} error=${denied.errorCode} opens nuevos=${custodian.opens - opensBefore} (debe ser 0)`);
  if (denied.success) throw new Error('Un documento revocado NO debe abrirse');
  console.log('Smoke P2-6 OK: custodia Smart Token de extremo a extremo con doble local.');
  // La sesión controlada del Gatekeeper deja un temporizador de 300 s que
  // mantiene vivo un script pelado (los tests usan --test-force-exit).
  // Salida explícita: el trabajo ya terminó y no hay nada pendiente.
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
