/**
 * Example: unlock a TDCP package only through Gatekeeper.
 *
 * Run (after creating a package in the demo UI or tests):
 *   node --experimental-strip-types examples/unlock-via-gatekeeper.ts
 *
 * This script demonstrates the integrator shape; it does not bypass crypto.
 */

import { AuthorizationOracle } from '../src/oracle/authorization-oracle.ts';
import { InProcessAuthority } from '../src/authority/in-process-authority.ts';
import { createTDCPPackage } from '../src/core/package/tdcp-factory.ts';
import { unlockViaGatekeeper } from '../sdk/typescript/src/index.ts';
import { MockNFCProvider } from '../src/identity/credential-provider.ts';
import { MockDeviceIdentityProvider } from '../src/identity/device-identity-provider.ts';
import { MockBiometricProvider } from '../src/identity/biometric-provider.ts';

const password = 'example-passphrase-not-for-production';
const plaintext = new TextEncoder().encode('Hello from TDCP integrator example');

const oracle = new AuthorizationOracle();
const authority = new InProcessAuthority(oracle);
await authority.initialize();

const pkg = await createTDCPPackage({
  plaintext: plaintext.buffer,
  password,
  originalFileName: 'hello.txt',
  mimeType: 'text/plain',
  policyLevel: 'STANDARD',
  allowExtraction: false,
  authority,
  oracle,
});

const result = await unlockViaGatekeeper({
  packageData: pkg,
  userPassword: password,
  requestedOperation: 'READ',
  nfcProvider: new MockNFCProvider(),
  deviceProvider: new MockDeviceIdentityProvider(),
  biometricProvider: new MockBiometricProvider(),
  authority,
});

if (!result.success) {
  console.error('Unlock failed:', result.errorCode, result.errorMessage);
  process.exit(1);
}

const text = new TextDecoder().decode(result.plaintextBuffer);
console.log('Unlock OK via Gatekeeper. Plaintext:', text);
console.log('Grant id:', result.grant?.grantId);
console.log('Authority kind: IN_PROCESS (set TDCP_AUTHORITY_URL for remote)');
