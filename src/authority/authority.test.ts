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
    const client = new HttpAuthorityClient({ baseUrl });
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
