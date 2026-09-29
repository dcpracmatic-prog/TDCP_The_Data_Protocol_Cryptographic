/**
 * Authority ↔ user session binding (TDCP_USER_AUTH=required).
 * Tokens are signed like Better Auth's `jwt` plugin (EdDSA, iss/aud/sub, 5 min).
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Server } from 'node:http';
import { SignJWT, exportJWK, generateKeyPair, type JSONWebKeySet } from 'jose';
import { startAuthorityHttpServer } from '../../server/authority/http-server.ts';
import { HttpAuthorityClient } from './http-authority-client.ts';
import type { AuthorizationGrant, AuthorizationRequest } from '../core/authorization/types.ts';
import { verifyAuthorizationGrant } from '../core/authorization/grant-verifier.ts';

const ISSUER = 'http://app.test';
const AUDIENCE = 'tdcp-authority';

let privateKey: CryptoKey;
let otherPrivateKey: CryptoKey;
let jwks: JSONWebKeySet;

async function tokenFor(
  sub: string,
  opts: { key?: CryptoKey; iss?: string; aud?: string; exp?: string } = {}
): Promise<string> {
  return new SignJWT({ email: `${sub}@example.com` })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'k1' })
    .setSubject(sub)
    .setIssuer(opts.iss ?? ISSUER)
    .setAudience(opts.aud ?? AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? '5m')
    .sign(opts.key ?? privateKey);
}

function clientFor(baseUrl: string, sub: string | null) {
  return new HttpAuthorityClient({
    baseUrl,
    getUserToken: async () => (sub ? tokenFor(sub) : null),
  });
}

function req(
  documentId: string,
  challenge: string,
  operationId: string,
  extra: Partial<AuthorizationRequest> = {}
): AuthorizationRequest {
  return {
    requestId: `REQ-${operationId}`,
    documentId,
    packageId: `PKG-${documentId}`,
    deviceId: 'DEV-1',
    credentialId: 'CRED-1',
    operationId,
    challenge,
    requestedOperation: 'READ',
    timestamp: Date.now(),
    ...extra,
  };
}

async function registerAs(baseUrl: string, owner: string, documentId: string, allowed: string[] = [], viewOnce = false) {
  const c = clientFor(baseUrl, owner);
  await c.registerDocumentPolicy({
    documentId,
    packageId: `PKG-${documentId}`,
    policyLevel: 'STANDARD',
    allowExtraction: false,
    createdAt: Date.now(),
    allowedUserIds: allowed,
    viewOnce,
  });
}

describe('Authority user auth (required)', () => {
  let server: Server;
  let baseUrl: string;
  let dataDir: string;

  before(async () => {
    const kp = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    privateKey = kp.privateKey as CryptoKey;
    const other = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    otherPrivateKey = other.privateKey as CryptoKey;
    const pub = await exportJWK(kp.publicKey);
    jwks = { keys: [{ ...pub, kid: 'k1', alg: 'EdDSA' }] };

    dataDir = mkdtempSync(join(tmpdir(), 'tdcp-user-auth-'));
    const started = await startAuthorityHttpServer({
      dataDir,
      host: '127.0.0.1',
      port: 0,
      adminToken: 'admin-token-user-auth',
      rateLimit: { windowMs: 60_000, maxHits: 1000 },
      userAuth: { mode: 'required', issuer: ISSUER, audience: AUDIENCE, jwks },
    });
    server = started.server;
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('rejects Gatekeeper calls without a user token', async () => {
    const res = await fetch(`${baseUrl}/v1/challenge`, { method: 'POST' });
    assert.equal(res.status, 401);
    assert.equal(((await res.json()) as { error: string }).error, 'USER_AUTH_REQUIRED');
    for (const path of ['/v1/authorize', '/v1/wrap-secret/release', '/v1/view-once/commit', '/v1/documents']) {
      const r = await fetch(`${baseUrl}${path}`, { method: 'POST', body: '{}' });
      assert.equal(r.status, 401, path);
    }
  });

  it('rejects forged, foreign-key, wrong-issuer, wrong-audience and long-lived tokens', async () => {
    const bad = [
      'not-a-jwt',
      await tokenFor('alice', { key: otherPrivateKey }),
      await tokenFor('alice', { iss: 'http://evil.test' }),
      await tokenFor('alice', { aud: 'other-service' }),
      await tokenFor('alice', { exp: '1d' }),
      await tokenFor('alice', { exp: '-1m' }),
    ];
    for (const token of bad) {
      const res = await fetch(`${baseUrl}/v1/challenge`, {
        method: 'POST',
        headers: { 'x-tdcp-user-token': token },
      });
      assert.equal(res.status, 401, token.slice(0, 20));
      assert.equal(((await res.json()) as { error: string }).error, 'USER_TOKEN_INVALID');
    }
  });

  it('owner registers, gets a user-bound grant and the wrap secret', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U1');
    const alice = clientFor(baseUrl, 'alice');
    await alice.initialize();
    const challenge = await alice.issueChallenge();
    const result = await alice.processAuthorizationRequest(req('DOC-U1', challenge, 'OP-U1'));
    assert.equal(result.granted, true, result.rejectionReason);
    assert.equal(result.grant!.subjectUserId, 'alice');
    // Without a USB-HSM the Authority pins the credential to the verified account.
    assert.equal(result.grant!.credentialId, 'ACCOUNT-alice');
    const g = result.grant!;
    const check = await verifyAuthorizationGrant(g, await alice.getPublicKey(), {
      targetDocumentId: 'DOC-U1',
      targetDeviceId: 'DEV-1',
      targetCredentialId: 'ACCOUNT-alice',
      targetOperationId: 'OP-U1',
      expectedChallenge: challenge,
      requestedOperation: 'READ',
      expectedEpoch: g.authorizationEpoch,
    });
    assert.equal(check.isValid, true, check.errorMessage);
    // Tampering with the signed subject breaks the signature.
    const forged = await verifyAuthorizationGrant({ ...g, subjectUserId: 'mallory' }, await alice.getPublicKey(), {
      targetDocumentId: 'DOC-U1',
      targetDeviceId: 'DEV-1',
      targetCredentialId: 'ACCOUNT-alice',
      targetOperationId: 'OP-U1',
      expectedChallenge: challenge,
      requestedOperation: 'READ',
      expectedEpoch: g.authorizationEpoch,
    });
    assert.equal(forged.isValid, false);
    assert.ok(await alice.releaseDocumentWrapSecretForGrant(result.grant!));
  });

  it('ignores a client-supplied subjectUserId', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U2');
    const mallory = clientFor(baseUrl, 'mallory');
    const challenge = await mallory.issueChallenge();
    const result = await mallory.processAuthorizationRequest(
      req('DOC-U2', challenge, 'OP-U2', { subjectUserId: 'alice' })
    );
    assert.equal(result.granted, false);
    assert.equal(result.rejectionCode, 'CREDENTIAL_UNAUTHORIZED');
  });

  it('denies users outside the ACL and admits shared users', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U3', ['bob']);
    const bob = clientFor(baseUrl, 'bob');
    const carol = clientFor(baseUrl, 'carol');

    const cb = await bob.issueChallenge();
    const rb = await bob.processAuthorizationRequest(req('DOC-U3', cb, 'OP-U3-B'));
    assert.equal(rb.granted, true, rb.rejectionReason);

    const cc = await carol.issueChallenge();
    const rc = await carol.processAuthorizationRequest(req('DOC-U3', cc, 'OP-U3-C'));
    assert.equal(rc.granted, false);
    assert.equal(rc.rejectionCode, 'CREDENTIAL_UNAUTHORIZED');
  });

  it('a grant stolen by another user cannot release the wrap secret', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U4', ['bob']);
    const bob = clientFor(baseUrl, 'bob');
    const c = await bob.issueChallenge();
    const r = await bob.processAuthorizationRequest(req('DOC-U4', c, 'OP-U4'));
    assert.equal(r.granted, true);
    const thief = clientFor(baseUrl, 'mallory');
    assert.equal(await thief.releaseDocumentWrapSecretForGrant(r.grant as AuthorizationGrant), null);
    // …and the legitimate user can still redeem it once.
    assert.ok(await bob.releaseDocumentWrapSecretForGrant(r.grant!));
    assert.equal(await bob.releaseDocumentWrapSecretForGrant(r.grant!), null);
  });

  it('a challenge issued to one user cannot be used by another', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U5', ['bob']);
    const alice = clientFor(baseUrl, 'alice');
    const bob = clientFor(baseUrl, 'bob');
    const aliceChallenge = await alice.issueChallenge();
    const r = await bob.processAuthorizationRequest(req('DOC-U5', aliceChallenge, 'OP-U5'));
    assert.equal(r.granted, false);
    assert.equal(r.rejectionCode, 'CHALLENGE_SUBJECT_MISMATCH');
  });

  it('refuses to re-register an existing document (no hijack / reset)', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U6');
    const res = await fetch(`${baseUrl}/v1/documents`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-tdcp-user-token': await tokenFor('mallory') },
      body: JSON.stringify({
        documentId: 'DOC-U6',
        packageId: 'PKG-DOC-U6',
        policyLevel: 'NORMAL',
        allowExtraction: true,
        createdAt: Date.now(),
        ownerUserId: 'mallory',
      }),
    });
    assert.equal(res.status, 409);
    const admin = await fetch(`${baseUrl}/v1/documents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer admin-token-user-auth' },
      body: JSON.stringify({ documentId: 'DOC-U6', packageId: 'X', policyLevel: 'NORMAL', allowExtraction: true, createdAt: 1 }),
    });
    assert.equal(admin.status, 409);
  });

  it('owner-scoped ACL, revoke and restore; others get 404', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U7');
    const alice = clientFor(baseUrl, 'alice');
    const bob = clientFor(baseUrl, 'bob');

    await assert.rejects(() => bob.updateDocumentAcl('DOC-U7', ['bob']), /DOCUMENT_NOT_FOUND/);
    await assert.rejects(() => bob.revokeDocument('DOC-U7'), /DOCUMENT_NOT_FOUND/);

    const updated = await alice.updateDocumentAcl('DOC-U7', ['bob', 'bob', 'alice']);
    assert.deepEqual(updated.allowedUserIds, ['bob']);

    const c1 = await bob.issueChallenge();
    assert.equal((await bob.processAuthorizationRequest(req('DOC-U7', c1, 'OP-U7-1'))).granted, true);

    const state = await alice.revokeDocument('DOC-U7', 'test');
    assert.equal(state.isRevoked, true);
    const c2 = await bob.issueChallenge();
    const denied = await bob.processAuthorizationRequest(req('DOC-U7', c2, 'OP-U7-2'));
    assert.equal(denied.granted, false);

    await alice.restoreDocument('DOC-U7');
    await alice.updateDocumentAcl('DOC-U7', []);
    const c3 = await bob.issueChallenge();
    const r3 = await bob.processAuthorizationRequest(req('DOC-U7', c3, 'OP-U7-3'));
    assert.equal(r3.granted, false);
    assert.equal(r3.rejectionCode, 'CREDENTIAL_UNAUTHORIZED');
  });

  it('ACL removal after issuance blocks redemption', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U8', ['bob']);
    const alice = clientFor(baseUrl, 'alice');
    const bob = clientFor(baseUrl, 'bob');
    const c = await bob.issueChallenge();
    const r = await bob.processAuthorizationRequest(req('DOC-U8', c, 'OP-U8'));
    assert.equal(r.granted, true);
    await alice.updateDocumentAcl('DOC-U8', []);
    assert.equal(await bob.releaseDocumentWrapSecretForGrant(r.grant!), null);
  });

  it('view-once is consumed atomically at secret release', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U9', [], true);
    const alice = clientFor(baseUrl, 'alice');
    const c = await alice.issueChallenge();
    const r = await alice.processAuthorizationRequest(req('DOC-U9', c, 'OP-U9'));
    assert.equal(r.granted, true);
    assert.ok(await alice.releaseDocumentWrapSecretForGrant(r.grant!));
    // Client "forgets" to commit — the document must still be consumed.
    const c2 = await alice.issueChallenge();
    const r2 = await alice.processAuthorizationRequest(req('DOC-U9', c2, 'OP-U9-2'));
    assert.equal(r2.granted, false);
  });

  it('documents without owner/ACL are denied in required mode', async () => {
    const res = await fetch(`${baseUrl}/v1/documents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer admin-token-user-auth' },
      body: JSON.stringify({ documentId: 'DOC-U10', packageId: 'PKG-DOC-U10', policyLevel: 'STANDARD', allowExtraction: false, createdAt: Date.now() }),
    });
    assert.equal(res.status, 200);
    const alice = clientFor(baseUrl, 'alice');
    const c = await alice.issueChallenge();
    const r = await alice.processAuthorizationRequest(req('DOC-U10', c, 'OP-U10'));
    assert.equal(r.granted, false);
    assert.equal(r.rejectionCode, 'DOCUMENT_HAS_NO_ACL');
  });

  it('policy ACL is visible only to the owner; /v1/me/documents is scoped', async () => {
    await registerAs(baseUrl, 'alice', 'DOC-U11', ['bob']);
    const alice = clientFor(baseUrl, 'alice');
    const bob = clientFor(baseUrl, 'bob');
    const asOwner = await alice.getDocumentPolicy('DOC-U11');
    assert.deepEqual(asOwner?.allowedUserIds, ['bob']);
    const asBob = await bob.getDocumentPolicy('DOC-U11');
    assert.equal(asBob?.allowedUserIds, undefined);
    assert.equal(asBob?.ownerUserId, undefined);

    const mine = await bob.listMyDocuments();
    assert.ok(mine.some((p) => p.documentId === 'DOC-U11'));
    const carolDocs = await clientFor(baseUrl, 'carol').listMyDocuments();
    assert.equal(carolDocs.length, 0);
  });
});
