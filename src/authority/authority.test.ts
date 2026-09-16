/**
 * Authority durable revoke/replay + one-time grant semantics.
 * Uses DurableAuthorityService (file store) — restart store, not process.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableAuthorityService } from '../../server/authority/service.ts';
import { HttpAuthorityClient } from './http-authority-client.ts';
import { startAuthorityHttpServer } from '../../server/authority/http-server.ts';
import { InProcessAuthority } from './in-process-authority.ts';
import { AuthorizationOracle } from '../oracle/authorization-oracle.ts';
import type { AuthorizationRequest } from '../core/authorization/types.ts';
import type { Server } from 'node:http';

function makeRequest(
  overrides: Partial<AuthorizationRequest> &
    Pick<AuthorizationRequest, 'documentId' | 'packageId' | 'challenge' | 'operationId'>
): AuthorizationRequest {
  return {
    requestId: 'REQ-TEST',
    deviceId: 'DEV-TEST',
    credentialId: 'CRED-TEST',
    requestedOperation: 'READ',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('DurableAuthorityService', () => {
  let dir: string;

  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'tdcp-auth-'));
  });

  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('durable revoke survives store restart', async () => {
    const svc1 = new DurableAuthorityService(dir);
    await svc1.initialize();
    const secret = await svc1.registerDocumentPolicy({
      documentId: 'DOC-REV-1',
      packageId: 'PKG-REV-1',
      policyLevel: 'STANDARD',
      allowExtraction: false,
      createdAt: Date.now(),
    });
    assert.equal(secret.byteLength, 32);

    const revoked = await svc1.revokeDocument('DOC-REV-1', 'test revoke', 'TEST');
    assert.equal(revoked.isRevoked, true);
    assert.ok(revoked.currentEpoch >= 2);
    svc1.flush();

    // New service instance = "restart" against same durable store
    const svc2 = new DurableAuthorityService(dir);
    await svc2.initialize();
    const state = await svc2.getDocumentRevocationState('DOC-REV-1');
    assert.equal(state.isRevoked, true);
    assert.equal(state.currentEpoch, revoked.currentEpoch);

    const policy = await svc2.getDocumentPolicy('DOC-REV-1');
    assert.ok(policy);
    assert.equal(policy!.packageId, 'PKG-REV-1');

    const challenge = await svc2.issueChallenge();
    const result = await svc2.processAuthorizationRequest(
      makeRequest({
        documentId: 'DOC-REV-1',
        packageId: 'PKG-REV-1',
        challenge,
        operationId: 'OP-AFTER-REVOKE',
      })
    );
    assert.equal(result.granted, false);
    assert.ok(
      result.rejectionCode === 'DOCUMENT_REVOKED' ||
        result.rejectionCode === 'EPOCH_REVOKED' ||
        String(result.rejectionCode || '').includes('REVOK') ||
        String(result.rejectionReason || '').toLowerCase().includes('revoc')
    );
  });

  it('rejects replay of consumed challenge/operation', async () => {
    const replayDir = mkdtempSync(join(tmpdir(), 'tdcp-replay-'));
    try {
      const svc = new DurableAuthorityService(replayDir);
      await svc.initialize();
      await svc.registerDocumentPolicy({
        documentId: 'DOC-RP-1',
        packageId: 'PKG-RP-1',
        policyLevel: 'STANDARD',
        allowExtraction: true,
        createdAt: Date.now(),
      });

      const challenge = await svc.issueChallenge();
      const opId = 'OP-RP-ONCE';
      const first = await svc.processAuthorizationRequest(
        makeRequest({
          documentId: 'DOC-RP-1',
          packageId: 'PKG-RP-1',
          challenge,
          operationId: opId,
        })
      );
      assert.equal(first.granted, true);
      assert.ok(first.grant);

      const second = await svc.processAuthorizationRequest(
        makeRequest({
          documentId: 'DOC-RP-1',
          packageId: 'PKG-RP-1',
          challenge,
          operationId: opId,
        })
      );
      assert.equal(second.granted, false);
      assert.equal(second.rejectionCode, 'REPLAY_ATTACK_DETECTED');
    } finally {
      rmSync(replayDir, { recursive: true, force: true });
    }
  });

  it('enforces one-time grant wrap-secret release', async () => {
    const onceDir = mkdtempSync(join(tmpdir(), 'tdcp-once-'));
    try {
      const svc = new DurableAuthorityService(onceDir);
      await svc.initialize();
      await svc.registerDocumentPolicy({
        documentId: 'DOC-OT-1',
        packageId: 'PKG-OT-1',
        policyLevel: 'STANDARD',
        allowExtraction: false,
        createdAt: Date.now(),
      });
      const challenge = await svc.issueChallenge();
      const auth = await svc.processAuthorizationRequest(
        makeRequest({
          documentId: 'DOC-OT-1',
          packageId: 'PKG-OT-1',
          challenge,
          operationId: 'OP-OT-1',
        })
      );
      assert.equal(auth.granted, true);
      const grant = auth.grant!;
      const first = await svc.releaseDocumentWrapSecretForGrant(grant);
      assert.ok(first);
      assert.equal(first!.byteLength, 32);
      const second = await svc.releaseDocumentWrapSecretForGrant(grant);
      assert.equal(second, null);
    } finally {
      rmSync(onceDir, { recursive: true, force: true });
    }
  });
});

describe('InProcessAuthority adapter', () => {
  it('mirrors Oracle challenge + policy surface', async () => {
    const oracle = new AuthorizationOracle();
    const authority = new InProcessAuthority(oracle);
    await authority.initialize();
    const challenge = await authority.issueChallenge();
    assert.ok(challenge.startsWith('CHALLENGE-'));
    assert.equal(await authority.isValidChallenge(challenge), true);
    const secret = await authority.registerDocumentPolicy({
      documentId: 'DOC-IP-1',
      packageId: 'PKG-IP-1',
      policyLevel: 'NORMAL',
      allowExtraction: false,
      createdAt: Date.now(),
    });
    assert.equal(secret.byteLength, 32);
    const policy = await authority.getDocumentPolicy('DOC-IP-1');
    assert.equal(policy?.packageId, 'PKG-IP-1');
  });
});

describe('HttpAuthorityClient against local server', () => {
  let server: Server;
  let baseUrl: string;
  let dataDir: string;

  before(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'tdcp-http-'));
    const started = await startAuthorityHttpServer({
      dataDir,
      host: '127.0.0.1',
      port: 0,
      adminToken: 'test-admin-token-http',
    });
    server = started.server;
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('registers, grants, and rejects replay over HTTP', async () => {
    const client = new HttpAuthorityClient({ baseUrl, adminToken: 'test-admin-token-http' });
    await client.initialize();
    assert.ok(client.getKeyId());

    await client.registerDocumentPolicy({
      documentId: 'DOC-HTTP-1',
      packageId: 'PKG-HTTP-1',
      policyLevel: 'STANDARD',
      allowExtraction: false,
      createdAt: Date.now(),
    });

    const challenge = await client.issueChallenge();
    const first = await client.processAuthorizationRequest(
      makeRequest({
        documentId: 'DOC-HTTP-1',
        packageId: 'PKG-HTTP-1',
        challenge,
        operationId: 'OP-HTTP-1',
      })
    );
    assert.equal(first.granted, true);
    assert.ok(first.grant);

    const wrap = await client.releaseDocumentWrapSecretForGrant(first.grant!);
    assert.ok(wrap);

    const replay = await client.processAuthorizationRequest(
      makeRequest({
        documentId: 'DOC-HTTP-1',
        packageId: 'PKG-HTTP-1',
        challenge,
        operationId: 'OP-HTTP-1',
      })
    );
    assert.equal(replay.granted, false);
    assert.equal(replay.rejectionCode, 'REPLAY_ATTACK_DETECTED');
  });
});


describe('Authority admin auth + ops endpoints', () => {
  let server: Server;
  let baseUrl: string;
  let dataDir: string;
  const adminToken = 'test-admin-token-ops';

  before(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'tdcp-admin-'));
    const started = await startAuthorityHttpServer({
      dataDir,
      host: '127.0.0.1',
      port: 0,
      adminToken,
      rateLimit: { windowMs: 60_000, maxHits: 1000 },
    });
    server = started.server;
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
    rmSync(dataDir, { recursive: true, force: true });
  });

  it('returns 401 on register without token', async () => {
    const res = await fetch(`${baseUrl}/v1/documents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        documentId: 'DOC-NOAUTH',
        packageId: 'PKG-NOAUTH',
        policyLevel: 'STANDARD',
        allowExtraction: false,
        createdAt: Date.now(),
      }),
    });
    assert.equal(res.status, 401);
    const body = (await res.json()) as { error?: string };
    assert.equal(body.error, 'UNAUTHORIZED');
  });

  it('registers successfully with Bearer admin token', async () => {
    const res = await fetch(`${baseUrl}/v1/documents/register`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        documentId: 'DOC-AUTH-OK',
        packageId: 'PKG-AUTH-OK',
        policyLevel: 'STANDARD',
        allowExtraction: false,
        createdAt: Date.now(),
      }),
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { wrapSecretBase64?: string };
    assert.ok(body.wrapSecretBase64);
  });

  it('returns 401 on revoke without token and succeeds with token', async () => {
    const deny = await fetch(`${baseUrl}/v1/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ documentId: 'DOC-AUTH-OK', reason: 'test' }),
    });
    assert.equal(deny.status, 401);

    const ok = await fetch(`${baseUrl}/v1/revoke`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ documentId: 'DOC-AUTH-OK', reason: 'test', revokedBy: 'TEST' }),
    });
    assert.equal(ok.status, 200);
    const state = (await ok.json()) as { isRevoked?: boolean };
    assert.equal(state.isRevoked, true);
  });

  it('exposes /health, /ready, and /metrics', async () => {
    const health = await fetch(`${baseUrl}/health`);
    assert.equal(health.status, 200);
    const healthBody = (await health.json()) as { ok?: boolean };
    assert.equal(healthBody.ok, true);

    const ready = await fetch(`${baseUrl}/ready`);
    assert.equal(ready.status, 200);
    const readyBody = (await ready.json()) as {
      ready?: boolean;
      storeWritable?: boolean;
      signingKeyLoaded?: boolean;
    };
    assert.equal(readyBody.ready, true);
    assert.equal(readyBody.storeWritable, true);
    assert.equal(readyBody.signingKeyLoaded, true);

    const metrics = await fetch(`${baseUrl}/metrics`);
    assert.equal(metrics.status, 200);
    const text = await metrics.text();
    assert.match(text, /tdcp_authority_grants_issued/);
    assert.match(text, /tdcp_authority_revokes/);
  });

  it('keeps public challenge endpoint available without admin token', async () => {
    const res = await fetch(`${baseUrl}/v1/challenge`, { method: 'POST' });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { challenge?: string };
    assert.ok(body.challenge);
  });
});

describe('KmsOracleKeyStore stub backend', () => {
  it('signs via signCanonical hook without AWS credentials', async () => {
    const { KmsOracleKeyStore } = await import('../oracle/oracle-key-store.ts');
    const store = new KmsOracleKeyStore({ mode: 'stub', keyId: 'TEST-KMS-STUB' });
    assert.equal(store.kind, 'KMS');
    assert.equal(store.isProductionGrade, false);
    assert.equal(store.developmentOnly, true);
    const sig = await store.signCanonical!('canonical-test');
    assert.ok(sig.byteLength > 0);
    const pub = await store.getPublicKey();
    assert.ok(pub);
  });
});
