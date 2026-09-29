/**
 * USB-HSM as the user's hardware ID: enrollment, per-request signatures,
 * lifecycle (ACTIVE → SUSPENDED → REVOKED → REPLACED) and clone detection.
 * Uses a software FIDO2 authenticator that emits real WebAuthn structures.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Server } from 'node:http';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { startAuthorityHttpServer } from '../../server/authority/http-server.ts';
import { UsbHsmRegistry, UsbHsmError, type UsbHsmConfig } from '../../server/authority/usb-hsm.ts';
import { HttpAuthorityClient } from './http-authority-client.ts';
import { SoftUsbHsm } from '../test/soft-usb-hsm.ts';
import {
  usbHsmChallenge,
  usbHsmDeviceIdFromCredentialId,
} from '../core/authorization/usb-hsm.ts';
import type { AuthorizationRequest, PolicyLevel } from '../core/authorization/types.ts';
import { createTDCPPackage } from '../core/package/tdcp-factory.ts';
import { DCPGatekeeper } from '../gatekeeper/gatekeeper.ts';
import { MockNFCProvider } from '../identity/credential-provider.ts';
import { MockDeviceIdentityProvider } from '../identity/device-identity-provider.ts';
import { LocalAuditSink } from '../audit/audit-sink.ts';

const ISSUER = 'http://localhost:8080';
const ORIGIN = 'http://localhost:8080';
const RP_ID = 'localhost';

let signingKey: CryptoKey;
let server: Server;
let baseUrl: string;
let dataDir: string;

async function tokenFor(sub: string) {
  return new SignJWT({ email: `${sub}@example.com`, email_verified: true })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'k1' })
    .setSubject(sub)
    .setIssuer(ISSUER)
    .setAudience('tdcp-authority')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(signingKey);
}

const client = (sub: string) =>
  new HttpAuthorityClient({ baseUrl, getUserToken: async () => tokenFor(sub) });

const newKey = (over: Partial<ConstructorParameters<typeof SoftUsbHsm>[0]> = {}) =>
  new SoftUsbHsm({ origin: ORIGIN, rpId: RP_ID, ...over });

async function enroll(sub: string, key: SoftUsbHsm, label = 'Llave', replaceDeviceId?: string) {
  const c = client(sub);
  const options = await c.usbHsmRegistrationOptions({ label, replaceDeviceId });
  return c.registerUsbHsm((await key.register(options)) as never);
}

async function registerDoc(owner: string, documentId: string, policyLevel: PolicyLevel = 'CRITICAL', extra = {}) {
  await client(owner).registerDocumentPolicy({
    documentId,
    packageId: `PKG-${documentId}`,
    policyLevel,
    allowExtraction: false,
    createdAt: Date.now(),
    ...extra,
  });
}

async function authorizeWith(
  sub: string,
  documentId: string,
  key: SoftUsbHsm | null,
  opts: { signFor?: string; counter?: number } = {}
) {
  const c = client(sub);
  const challenge = await c.issueChallenge();
  const operationId = `OP-${Math.random().toString(36).slice(2)}`;
  const base: AuthorizationRequest = {
    requestId: `REQ-${operationId}`,
    documentId,
    packageId: `PKG-${documentId}`,
    deviceId: 'DEV-X',
    credentialId: 'CRED-X',
    operationId,
    challenge,
    requestedOperation: 'READ',
    timestamp: Date.now(),
    policyContext: { biometricVerified: true }, // self-declared: must be ignored
  };
  if (key) {
    const deviceId = await usbHsmDeviceIdFromCredentialId(key.id);
    const expected = await usbHsmChallenge({
      challenge,
      documentId: opts.signFor ?? documentId,
      packageId: `PKG-${opts.signFor ?? documentId}`,
      operationId,
      requestedOperation: 'READ',
    });
    base.deviceId = deviceId;
    base.credentialId = deviceId;
    base.usbHsmAssertion = (await key.sign(expected, { counter: opts.counter })) as never;
  }
  return { c, result: await c.processAuthorizationRequest(base) };
}

describe('USB-HSM as hardware ID', () => {
  before(async () => {
    const kp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    signingKey = kp.privateKey as CryptoKey;
    const jwks = { keys: [{ ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'EdDSA' }] };
    dataDir = mkdtempSync(join(tmpdir(), 'tdcp-usbhsm-'));
    const started = await startAuthorityHttpServer({
      dataDir,
      host: '127.0.0.1',
      port: 0,
      adminToken: 'admin-usbhsm',
      rateLimit: { windowMs: 60_000, maxHits: 5000 },
      userAuth: { mode: 'required', issuer: ISSUER, audience: 'tdcp-authority', jwks },
      usbHsm: { rpId: RP_ID, rpName: 'TDCP', origins: [ORIGIN], maxDevicesPerUser: 3, requireVerifiedEmail: true, attestationMode: 'none', mdsVerificationMode: 'strict', allowedAaguids: [] },
    });
    server = started.server;
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((r, j) => server.close((e) => (e ? j(e) : r())));
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('enrolls a USB key as the user ID (ACTIVE, public key only)', async () => {
    const key = newKey();
    const device = await enroll('alice', key, 'YubiKey trabajo');
    assert.equal(device.status, 'ACTIVE');
    assert.match(device.deviceId, /^USBHSM-[0-9A-F]{16}$/);
    assert.equal(device.label, 'YubiKey trabajo');
    const list = await client('alice').listUsbHsm();
    assert.equal(list.length, 1);
    assert.equal(JSON.stringify(list).includes('publicKey'), false);
    assert.equal((await client('bob').listUsbHsm()).length, 0);
  });

  it('rejects synced passkeys, non-USB authenticators, no-PIN keys and foreign origins', async () => {
    await assert.rejects(() => enroll('carol', newKey({ synced: true })), /USB_HSM_NOT_HARDWARE_BOUND/);
    await assert.rejects(() => enroll('carol', newKey({ transports: ['internal'] })), /USB_HSM_NOT_USB/);
    await assert.rejects(() => enroll('carol', newKey({ userVerification: false })), /USB_HSM_REGISTRATION_INVALID/);
    await assert.rejects(() => enroll('carol', newKey({ origin: 'https://evil.example' })), /USB_HSM_REGISTRATION_INVALID/);
    await assert.rejects(() => enroll('carol', newKey({ rpId: 'evil.example' })), /USB_HSM_REGISTRATION_INVALID/);
    assert.equal((await client('carol').listUsbHsm()).length, 0);
  });

  it('a registration challenge is single-use and bound to the user', async () => {
    const key = newKey();
    const options = await client('dave').usbHsmRegistrationOptions({});
    const response = await key.register(options);
    await assert.rejects(() => client('erin').registerUsbHsm(response as never), /USB_HSM_REGISTRATION_EXPIRED/);
    await client('dave').registerUsbHsm(response as never);
    await assert.rejects(() => client('dave').registerUsbHsm(response as never), /USB_HSM_REGISTRATION_EXPIRED/);
  });

  it('CRITICAL documents require a valid USB-HSM signature', async () => {
    const key = newKey();
    await enroll('frank', key);
    await registerDoc('frank', 'DOC-H1');

    const none = await authorizeWith('frank', 'DOC-H1', null);
    assert.equal(none.result.granted, false);
    assert.equal(none.result.rejectionCode, 'USB_HSM_REQUIRED');

    const ok = await authorizeWith('frank', 'DOC-H1', key);
    assert.equal(ok.result.granted, true, ok.result.rejectionReason);
    const deviceId = await usbHsmDeviceIdFromCredentialId(key.id);
    assert.equal(ok.result.grant!.deviceId, deviceId);
    assert.equal(ok.result.grant!.credentialId, deviceId);
    assert.ok(await ok.c.releaseDocumentWrapSecretForGrant(ok.result.grant!));
  });

  it('a signature for another document or from another user is rejected', async () => {
    const key = newKey();
    await enroll('gina', key);
    await registerDoc('gina', 'DOC-H2');
    await registerDoc('gina', 'DOC-H3');
    const cross = await authorizeWith('gina', 'DOC-H2', key, { signFor: 'DOC-H3' });
    assert.equal(cross.result.granted, false);
    assert.equal(cross.result.rejectionCode, 'USB_HSM_ASSERTION_INVALID');

    // hank is on the ACL but tries to use gina's key
    await registerDoc('gina', 'DOC-H4', 'CRITICAL', { allowedUserIds: ['hank'] });
    const stolen = await authorizeWith('hank', 'DOC-H4', key);
    assert.equal(stolen.result.granted, false);
    assert.equal(stolen.result.rejectionCode, 'USB_HSM_NOT_REGISTERED');
  });

  it('requireUsbHsm also applies to STANDARD documents; plain docs use the account credential', async () => {
    const key = newKey();
    await enroll('ivan', key);
    await registerDoc('ivan', 'DOC-H5', 'STANDARD', { requireUsbHsm: true });
    assert.equal((await authorizeWith('ivan', 'DOC-H5', null)).result.rejectionCode, 'USB_HSM_REQUIRED');
    assert.equal((await authorizeWith('ivan', 'DOC-H5', key)).result.granted, true);

    await registerDoc('ivan', 'DOC-H6', 'STANDARD');
    const plain = await authorizeWith('ivan', 'DOC-H6', null);
    assert.equal(plain.result.granted, true, plain.result.rejectionReason);
    assert.equal(plain.result.grant!.credentialId, 'ACCOUNT-ivan');
  });

  it('a replayed signature counter suspends the key as a possible clone', async () => {
    const key = newKey();
    const dev = await enroll('judy', key);
    await registerDoc('judy', 'DOC-H7');
    assert.equal((await authorizeWith('judy', 'DOC-H7', key, { counter: 10 })).result.granted, true);
    const clone = await authorizeWith('judy', 'DOC-H7', key, { counter: 5 });
    assert.equal(clone.result.rejectionCode, 'USB_HSM_CLONE_SUSPECTED');
    const after = await authorizeWith('judy', 'DOC-H7', key, { counter: 50 });
    assert.equal(after.result.rejectionCode, 'USB_HSM_SUSPENDED');
    await assert.rejects(() => client('judy').changeUsbHsmStatus(dev.deviceId, 'reactivate'), /USB_HSM_CLONE_SUSPECTED/);
  });

  it('revocation kills the key and grants issued before it', async () => {
    const key = newKey();
    const dev = await enroll('kate', key);
    await registerDoc('kate', 'DOC-H8');
    const pending = await authorizeWith('kate', 'DOC-H8', key);
    assert.equal(pending.result.granted, true);
    await client('kate').changeUsbHsmStatus(dev.deviceId, 'revoke');
    assert.equal(await pending.c.releaseDocumentWrapSecretForGrant(pending.result.grant!), null);
    assert.equal((await authorizeWith('kate', 'DOC-H8', key)).result.rejectionCode, 'USB_HSM_REVOKED');
    await assert.rejects(() => client('mallory').changeUsbHsmStatus(dev.deviceId, 'revoke'), /USB_HSM_NOT_FOUND/);
  });

  it('user suspend/reactivate and replacement (old key → REPLACED)', async () => {
    const oldKey = newKey();
    const old = await enroll('leo', oldKey);
    await registerDoc('leo', 'DOC-H9');
    await client('leo').changeUsbHsmStatus(old.deviceId, 'suspend');
    assert.equal((await authorizeWith('leo', 'DOC-H9', oldKey)).result.rejectionCode, 'USB_HSM_SUSPENDED');
    await client('leo').changeUsbHsmStatus(old.deviceId, 'reactivate');
    assert.equal((await authorizeWith('leo', 'DOC-H9', oldKey)).result.granted, true);

    const newer = newKey();
    const replacement = await enroll('leo', newer, 'Nueva', old.deviceId);
    const list = await client('leo').listUsbHsm();
    assert.equal(list.find((d) => d.deviceId === old.deviceId)?.status, 'REPLACED');
    assert.equal(list.find((d) => d.deviceId === old.deviceId)?.replacedBy, replacement.deviceId);
    assert.equal((await authorizeWith('leo', 'DOC-H9', oldKey)).result.rejectionCode, 'USB_HSM_REVOKED');
    assert.equal((await authorizeWith('leo', 'DOC-H9', newer)).result.granted, true);
  });

  it('enforces the per-user key limit and verified email', async () => {
    for (let i = 0; i < 3; i++) await enroll('max', newKey());
    await assert.rejects(() => enroll('max', newKey()), /USB_HSM_LIMIT/);
    const unverified = new HttpAuthorityClient({
      baseUrl,
      getUserToken: async () =>
        new SignJWT({ email: 'n@example.com', email_verified: false })
          .setProtectedHeader({ alg: 'EdDSA', kid: 'k1' })
          .setSubject('nora').setIssuer(ISSUER).setAudience('tdcp-authority')
          .setIssuedAt().setExpirationTime('5m').sign(signingKey),
    });
    await assert.rejects(() => unverified.usbHsmRegistrationOptions({}), /EMAIL_NOT_VERIFIED/);
  });

  it('end-to-end: Gatekeeper opens a CRITICAL package only with the USB-HSM', async () => {
    const key = newKey();
    await enroll('olga', key);
    const authority = client('olga');
    await authority.initialize();
    const pkg = await createTDCPPackage({
      plaintext: new TextEncoder().encode('Expediente CRITICAL').buffer,
      password: 'Factor-Olga-2026',
      originalFileName: 'x.txt',
      mimeType: 'text/plain',
      policyLevel: 'CRITICAL',
      allowExtraction: false,
      authority,
    });
    const unlock = (prover?: Parameters<typeof DCPGatekeeper.executeUnlock>[0]['usbHsmProver']) =>
      DCPGatekeeper.executeUnlock({
        packageData: pkg,
        userPassword: 'Factor-Olga-2026',
        requestedOperation: 'READ',
        nfcProvider: new MockNFCProvider(),
        deviceProvider: new MockDeviceIdentityProvider(),
        authority,
        auditSink: new LocalAuditSink(),
        usbHsmProver: prover,
      });

    const without = await unlock();
    assert.equal(without.success, false);
    assert.equal(without.errorCode, 'USB_HSM_REQUIRED');

    const withKey = await unlock(async (ctx) => ({
      deviceId: await usbHsmDeviceIdFromCredentialId(key.id),
      assertion: (await key.sign(await usbHsmChallenge(ctx))) as never,
    }));
    assert.equal(withKey.success, true, withKey.errorMessage);
    assert.equal(new TextDecoder().decode(withKey.plaintextBuffer!), 'Expediente CRITICAL');
  });

  it('USB-HSM records survive an Authority restart', async () => {
    const other = await startAuthorityHttpServer({
      dataDir,
      host: '127.0.0.1',
      port: 0,
      adminToken: 'admin-usbhsm',
      userAuth: { mode: 'required', issuer: ISSUER, audience: 'tdcp-authority', jwks: { keys: [] } },
      usbHsm: { rpId: RP_ID, rpName: 'TDCP', origins: [ORIGIN], maxDevicesPerUser: 3, requireVerifiedEmail: true, attestationMode: 'none', mdsVerificationMode: 'strict', allowedAaguids: [] },
    });
    const devices = other.service.getUsbHsm().listForUser('alice');
    assert.equal(devices.length, 1);
    assert.equal(devices[0]!.status, 'ACTIVE');
    await new Promise<void>((r) => other.server.close(() => r()));
  });
});

describe('USB-HSM attestation mode: direct (vendor/model verification)', () => {
  // The software authenticator always reports AAGUID 00000000-... (see
  // src/test/soft-usb-hsm.ts). That is exactly the "unrecognized model"
  // case direct mode exists to catch: 'none' mode only checks that the key
  // is single-device + reports 'usb' transport, both self-declared by the
  // client. 'direct' mode additionally requires the AAGUID to resolve
  // against FIDO MDS or an operator-configured allowlist.
  const ZERO_AAGUID = '00000000-0000-0000-0000-000000000000';

  function newRegistry(over: Partial<UsbHsmConfig> = {}) {
    return new UsbHsmRegistry(
      {
        rpId: RP_ID,
        rpName: 'TDCP',
        origins: [ORIGIN],
        maxDevicesPerUser: 5,
        requireVerifiedEmail: false,
        attestationMode: 'direct',
        mdsVerificationMode: 'permissive',
        allowedAaguids: [],
        ...over,
      },
      [],
      () => {}
    );
  }

  it('rejects an unrecognized AAGUID even in permissive MDS mode with no allowlist', async () => {
    // 'permissive' MDS mode still requires *some* MDS statement for AAGUIDs
    // it has actually seen; an all-zero AAGUID resolves to nothing at all,
    // so registration must fail closed rather than silently accept it.
    const registry = newRegistry({ mdsVerificationMode: 'strict' });
    const key = new SoftUsbHsm({ origin: ORIGIN, rpId: RP_ID });
    const options = await registry.registrationOptions({ userId: 'dave', emailVerified: true });
    const response = await key.register(options);
    await assert.rejects(
      () => registry.completeRegistration('dave', response as never),
      (err: unknown) => err instanceof UsbHsmError && err.code === 'USB_HSM_UNRECOGNIZED_MODEL'
    );
  });

  it('accepts an unrecognized AAGUID when it is on the operator allowlist', async () => {
    const registry = newRegistry({ allowedAaguids: [ZERO_AAGUID] });
    const key = new SoftUsbHsm({ origin: ORIGIN, rpId: RP_ID });
    const options = await registry.registrationOptions({ userId: 'erin', emailVerified: true });
    const response = await key.register(options);
    const info = await registry.completeRegistration('erin', response as never);
    assert.equal(info.status, 'ACTIVE');
  });

  it('attestationMode "none" (default) does not require AAGUID recognition', async () => {
    const registry = newRegistry({ attestationMode: 'none' });
    const key = new SoftUsbHsm({ origin: ORIGIN, rpId: RP_ID });
    const options = await registry.registrationOptions({ userId: 'frank', emailVerified: true });
    const response = await key.register(options);
    const info = await registry.completeRegistration('frank', response as never);
    assert.equal(info.status, 'ACTIVE');
  });
});
