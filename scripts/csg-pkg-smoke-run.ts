/**
 * P2-5 smoke driver (run via scripts/csg-pkg-smoke.mjs, NOT directly).
 *
 * Phase A (sidecar UP):   protect sealed -> open OK; tamper 1 byte -> open
 *                          rejects with CSG_PACKAGE_SEAL_FAILED; legacy opens.
 * Phase B (sidecar DOWN): the sealed .pkg saved by phase A must still be
 *                          rejected (fail closed, no unverified open).
 *
 * Env: CSG_SEAL_URL, CSG_SMOKE_PHASE=A|B, CSG_SMOKE_PKG_PATH.
 */

import { writeFileSync, readFileSync } from 'node:fs';
import { createTDCPPackage } from '../src/core/package/tdcp-factory.ts';
import {
  computePackageIntegrityHash,
  serializeTDCPPackage,
  deserializeTDCPPackage,
  type TDCPPackage,
} from '../src/core/package/package-format.ts';
import { AuthorizationOracle } from '../src/oracle/authorization-oracle.ts';
import { DCPGatekeeper } from '../src/gatekeeper/gatekeeper.ts';
import { MockNFCProvider } from '../src/identity/credential-provider.ts';
import { MockDeviceIdentityProvider } from '../src/identity/device-identity-provider.ts';
import { MockBiometricProvider } from '../src/identity/biometric-provider.ts';
import { LocalAuditSink } from '../src/audit/audit-sink.ts';

const PLAINTEXT = 'TDCP P2-5 smoke: el sello viaja dentro del .pkg';
const PASSWORD = 'contrasena-smoke-123456';
const PHASE = process.env.CSG_SMOKE_PHASE ?? 'A';
const PKG_PATH = process.env.CSG_SMOKE_PKG_PATH ?? '/tmp/csg-pkg-smoke.pkg.json';

function fail(message: string): never {
  console.error(`SMOKE FAIL: ${message}`);
  process.exit(1);
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

function flipB64Char(s: string): string {
  return (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
}

async function phaseA(): Promise<void> {
  const health = await fetch(`${process.env.CSG_SEAL_URL}/healthz`);
  if (!health.ok) fail('sidecar /healthz not OK');
  const healthJson = (await health.json()) as { ok?: boolean };
  console.log(`[A1] sidecar healthz ok=${healthJson.ok}`);

  const oracle = new AuthorizationOracle();
  const t0 = Date.now();
  const pkg = await createTDCPPackage({
    plaintext: new TextEncoder().encode(PLAINTEXT).buffer,
    password: PASSWORD,
    originalFileName: 'smoke.txt',
    mimeType: 'text/plain',
    policyLevel: 'STANDARD',
    allowExtraction: false,
    oracle,
    csgSeal: 'required',
  });
  const sealMs = Date.now() - t0;
  if (!pkg.csgSeal || pkg.csgSeal.schema !== 'csg.sello.v1') {
    fail('sealed package has no remote csg.sello.v1 seal');
  }
  console.log(
    `[A2] protect sealed in ${sealMs} ms: schema=${pkg.csgSeal.schema} evento_id=${pkg.csgSeal.evento_id} hash=${pkg.csgSeal.hash_contenido.slice(0, 16)}...`
  );

  // The .pkg file as it would travel: serialize -> parse -> unlock.
  const blob = await serializeTDCPPackage(pkg);
  const pkgJson = await blob.text();
  writeFileSync(PKG_PATH, pkgJson);
  const parsed = await deserializeTDCPPackage(pkgJson);
  if (!parsed.isValidEnvelope || !parsed.package) fail(`parse failed: ${parsed.error}`);
  const opened = await unlock(parsed.package, oracle);
  if (!opened.success || new TextDecoder().decode(opened.plaintextBuffer) !== PLAINTEXT) {
    fail(`sealed open failed: ${opened.errorCode} ${opened.errorMessage}`);
  }
  console.log(`[A3] open sealed OK: csgSealStatus=${opened.csgSealStatus} bytes=${opened.plaintextBuffer!.byteLength}`);

  // Tamper 1 byte of ciphertext, recompute the UNKEYED integrity hash the
  // way an attacker could, and confirm the CSG seal still rejects it.
  const tampered: TDCPPackage = {
    ...parsed.package,
    ciphertextBase64: flipB64Char(parsed.package.ciphertextBase64),
  };
  tampered.integrityHash = await computePackageIntegrityHash(tampered);
  const denied = await unlock(tampered, oracle);
  if (denied.success || denied.errorCode !== 'CSG_PACKAGE_SEAL_FAILED' || denied.plaintextBuffer) {
    fail(`tampered open should fail CSG_PACKAGE_SEAL_FAILED, got success=${denied.success} code=${denied.errorCode}`);
  }
  console.log(`[A4] tampered 1 byte -> DENIED ${denied.errorCode}, plaintext=none (fail closed)`);

  // Legacy package (no seal) still opens, documented as no CSG guarantee.
  const legacy = await createTDCPPackage({
    plaintext: new TextEncoder().encode(PLAINTEXT).buffer,
    password: PASSWORD,
    originalFileName: 'smoke-legacy.txt',
    mimeType: 'text/plain',
    policyLevel: 'STANDARD',
    allowExtraction: false,
    oracle,
    csgSeal: 'off',
  });
  const legacyOpened = await unlock(legacy, oracle);
  if (!legacyOpened.success || legacyOpened.csgSealStatus !== 'absent') {
    fail(`legacy open failed: ${legacyOpened.errorCode}`);
  }
  console.log(`[A5] legacy (no seal) opens OK: csgSealStatus=${legacyOpened.csgSealStatus}`);
}

async function phaseB(): Promise<void> {
  // Sidecar is DOWN here on purpose. The sealed package must NOT open:
  // its seal cannot be verified, so fail closed (before any policy/grant).
  const pkgJson = readFileSync(PKG_PATH, 'utf-8');
  const parsed = await deserializeTDCPPackage(pkgJson);
  if (!parsed.isValidEnvelope || !parsed.package) fail(`phase B parse failed: ${parsed.error}`);
  const oracle = new AuthorizationOracle();
  const denied = await unlock(parsed.package, oracle);
  if (denied.success || denied.errorCode !== 'CSG_PACKAGE_SEAL_FAILED' || denied.plaintextBuffer) {
    fail(`sidecar-down open should fail CSG_PACKAGE_SEAL_FAILED, got success=${denied.success} code=${denied.errorCode}`);
  }
  console.log(`[B1] sidecar DOWN + sealed package -> DENIED ${denied.errorCode}, plaintext=none (fail closed)`);
}

if (PHASE === 'A') await phaseA();
else if (PHASE === 'B') await phaseB();
else fail(`unknown phase ${PHASE}`);
console.log(`SMOKE ${PHASE} OK`);
// Explicit exit: undici keep-alive sockets to the sidecar would otherwise
// keep the event loop alive after all work is done.
process.exit(0);
