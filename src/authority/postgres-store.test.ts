/**
 * Postgres Authority store (P0-1) — integration tests against embedded PGLite.
 *
 * Same SQL as production (migrations/0005_authority_store.sql, applied by the
 * store's ensureSchema). The live Supabase database is verified separately
 * through the Management API — the sandbox blocks direct Postgres connections.
 *
 * These tests prove the Postgres store keeps the EXACT semantics of the file
 * store: same snapshot shape, same caps, same single-use / revoke / replay
 * behavior through DurableAuthorityService, surviving a service "restart".
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { PGlite } from '@electric-sql/pglite';
import {
  DurablePostgresAuthorityStore,
  createAuthorityStoreFromEnv,
  type AuthorityStoreQueryClient,
} from '../../server/authority/postgres-store.ts';
import {
  capSnapshotForPersist,
  emptyAuthoritySnapshot,
  type DurableAuthoritySnapshot,
} from '../../server/authority/durable-store.ts';
import { DurableAuthorityService } from '../../server/authority/service.ts';
import type { AuthorizationRequest } from '../core/authorization/types.ts';

function pgliteClient(pg: PGlite): AuthorityStoreQueryClient {
  return {
    query: async (text, params) => {
      const res = await pg.query(text, params as unknown[]);
      return { rows: res.rows as Record<string, unknown>[] };
    },
    exec: async (text) => {
      await pg.exec(text);
    },
  };
}

async function freshStore(): Promise<{ pg: PGlite; store: DurablePostgresAuthorityStore }> {
  const pg = new PGlite();
  const store = new DurablePostgresAuthorityStore({
    dataDir: '/tmp/tdcp-pg-test',
    client: pgliteClient(pg),
  });
  await store.ensureSchema();
  return { pg, store };
}

function fullSnapshot(): DurableAuthoritySnapshot {
  const snap = emptyAuthoritySnapshot();
  snap.keyId = 'AUTHORITY-KEY-P256-PG-TEST';
  snap.signingPrivateJwk = { kty: 'EC', crv: 'P-256', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', y: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', d: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC' };
  snap.signingPrivateJwkEnc = { v: 1, alg: 'AES-256-GCM', iv: 'aXY=', ct: 'Y3Q=', salt: 'c2FsdA==' };
  snap.signingPublicJwk = { kty: 'EC', crv: 'P-256', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', y: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' };
  snap.policies = [
    {
      documentId: 'DOC-PG-1',
      packageId: 'PKG-PG-1',
      policyLevel: 'STANDARD',
      allowExtraction: false,
      expirationDays: 30,
      viewOnce: true,
      createdAt: 1700000000000,
      ownerUserId: 'user-1',
      allowedUserIds: ['user-2', 'user-3'],
    },
    {
      documentId: 'DOC-PG-2',
      packageId: 'PKG-PG-2',
      policyLevel: 'CRITICAL',
      allowExtraction: false,
      createdAt: 1700000001000,
    },
  ];
  snap.wrapSecretsBase64 = { 'DOC-PG-1': 'd3JhcC1zZWNyZXQtMQ==', 'DOC-PG-2': 'd3JhcC1zZWNyZXQtMg==' };
  snap.revocation = [
    {
      documentId: 'DOC-PG-1',
      isRevoked: true,
      currentEpoch: 3,
      revokedAt: 1700000002000,
      revocationReason: 'test revoke',
      revokedBy: 'TEST',
      allowedOperations: ['READ'],
      viewOnceConsumed: true,
    },
    {
      documentId: 'DOC-PG-2',
      isRevoked: false,
      currentEpoch: 1,
      allowedOperations: ['READ', 'RENDER_RAM'],
      viewOnceConsumed: false,
    },
  ];
  snap.consumedOperations = [
    { operationId: 'OP-1', challenge: 'CH-1', grantId: 'GRANT-1', documentId: 'DOC-PG-1', deviceId: 'DEV-1', consumedAt: 1700000003000 },
    { operationId: 'OP-2', challenge: 'CH-2', grantId: 'GRANT-2', documentId: 'DOC-PG-2', deviceId: 'DEV-2', consumedAt: 1700000004000 },
  ];
  snap.consumedGrantIds = ['GRANT-1', 'GRANT-2'];
  snap.activeChallenges = [
    { challenge: 'CH-A', registeredAt: 1700000005000 },
    { challenge: 'CH-B', registeredAt: 1700000006000 },
  ];
  snap.challengeSubjects = [{ challenge: 'CH-A', subjectUserId: 'user-1' }];
  snap.usbHsmDevices = [
    {
      deviceId: 'USB-1',
      userId: 'user-1',
      credentialId: 'CRED-1',
      publicKeyB64u: 'cHVi',
      counter: 7,
      transports: ['usb'],
      aaguid: '00000000-0000-0000-0000-000000000000',
      label: 'YubiKey test',
      status: 'ACTIVE',
      createdAt: 1700000007000,
      lastUsedAt: 1700000008000,
    },
  ];
  return snap;
}

function makeRequest(
  overrides: Partial<AuthorizationRequest> &
    Pick<AuthorizationRequest, 'documentId' | 'packageId' | 'challenge' | 'operationId'>
): AuthorizationRequest {
  return {
    requestId: 'REQ-PG-TEST',
    deviceId: 'DEV-PG-TEST',
    credentialId: 'CRED-PG-TEST',
    requestedOperation: 'READ',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('DurablePostgresAuthorityStore (PGLite)', () => {
  it('load() on a fresh database returns the empty snapshot', async () => {
    const { pg, store } = await freshStore();
    try {
      const snap = await store.load();
      assert.equal(snap.version, 1);
      assert.equal(snap.keyId, 'AUTHORITY-KEY-P256-DURABLE-DEV');
      assert.deepEqual(snap.policies, []);
      assert.deepEqual(snap.revocation, []);
      assert.deepEqual(snap.consumedOperations, []);
      assert.deepEqual(snap.consumedGrantIds, []);
      assert.deepEqual(snap.activeChallenges, []);
      assert.equal(await store.probeWritable(), true);
      assert.equal(store.kind, 'postgres');
    } finally {
      await store.close();
      await pg.close();
    }
  });

  it('ensureSchema() is idempotent (second run is a no-op)', async () => {
    const { pg, store } = await freshStore();
    try {
      await store.ensureSchema();
      await store.ensureSchema();
      const tables = await pg.query(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'authority_%' ORDER BY tablename"
      );
      assert.deepEqual(
        tables.rows.map((r) => (r as { tablename: string }).tablename),
        [
          'authority_challenge_subjects',
          'authority_challenges',
          'authority_consumed_grants',
          'authority_consumed_operations',
          'authority_meta',
          'authority_policies',
          'authority_revocation',
          'authority_usb_hsm_devices',
          'authority_wrap_secrets',
        ]
      );
    } finally {
      await store.close();
      await pg.close();
    }
  });

  it('save() then load() round-trips the full snapshot', async () => {
    const { pg, store } = await freshStore();
    try {
      const written = fullSnapshot();
      await store.save(written);
      // A second store instance over the same database reads it back.
      const reader = new DurablePostgresAuthorityStore({
        dataDir: '/tmp/tdcp-pg-test',
        client: pgliteClient(pg),
      });
      const read = await reader.load();
      assert.deepEqual(read, written);
      await reader.close();
    } finally {
      await store.close();
      await pg.close();
    }
  });

  it('save() replaces (never merges) and an empty save clears state', async () => {
    const { pg, store } = await freshStore();
    try {
      await store.save(fullSnapshot());
      assert.equal((await store.load()).policies.length, 2);
      await store.save(emptyAuthoritySnapshot());
      const cleared = await store.load();
      assert.deepEqual(cleared.policies, []);
      assert.deepEqual(cleared.revocation, []);
      assert.deepEqual(cleared.consumedGrantIds, []);
      assert.equal(cleared.signingPrivateJwk, null);
    } finally {
      await store.close();
      await pg.close();
    }
  });

  it('caps match the file store: only the last 5,000 challenges persist', async () => {
    const { pg, store } = await freshStore();
    try {
      const snap = emptyAuthoritySnapshot();
      snap.activeChallenges = Array.from({ length: 5001 }, (_, i) => ({
        challenge: `CH-${i}`,
        registeredAt: 1700000000000 + i,
      }));
      snap.challengeSubjects = snap.activeChallenges.map((c) => ({
        challenge: c.challenge,
        subjectUserId: 'user-1',
      }));
      await store.save(snap);
      const read = await store.load();
      assert.equal(read.activeChallenges.length, 5000);
      assert.equal(read.activeChallenges[0].challenge, 'CH-1');
      assert.equal(read.activeChallenges[4999].challenge, 'CH-5000');
      assert.equal(read.challengeSubjects.length, 5000);
    } finally {
      await store.close();
      await pg.close();
    }
  });

  it('capSnapshotForPersist keeps the last 20,000 grants / consumed ops', () => {
    const snap = emptyAuthoritySnapshot();
    snap.consumedGrantIds = Array.from({ length: 20001 }, (_, i) => `G-${i}`);
    snap.consumedOperations = Array.from({ length: 20001 }, (_, i) => ({
      operationId: `OP-${i}`,
      challenge: `CH-${i}`,
      grantId: `G-${i}`,
      documentId: 'DOC',
      deviceId: 'DEV',
      consumedAt: i,
    }));
    const capped = capSnapshotForPersist(snap);
    assert.equal(capped.consumedGrantIds.length, 20000);
    assert.equal(capped.consumedGrantIds[0], 'G-1');
    assert.equal(capped.consumedOperations.length, 20000);
    assert.equal(capped.consumedOperations[0].operationId, 'OP-1');
  });
});

describe('DurableAuthorityService over the Postgres store', () => {
  let pg: PGlite;
  let store: DurablePostgresAuthorityStore;

  before(async () => {
    pg = new PGlite();
    store = new DurablePostgresAuthorityStore({
      dataDir: '/tmp/tdcp-pg-test',
      client: pgliteClient(pg),
    });
    await store.ensureSchema();
  });

  after(async () => {
    await store.close();
    await pg.close();
  });

  it('grant once, replay rejected, revoke survives restart — same as file store', async () => {
    const svc1 = new DurableAuthorityService({ dataDir: '/tmp/tdcp-pg-test', store });
    await svc1.initialize();
    assert.equal(svc1.getStoreKind(), 'postgres');
    const readiness = await svc1.getReadiness();
    assert.equal(readiness.ready, true);
    assert.equal(readiness.storeKind, 'postgres');

    const secret = await svc1.registerDocumentPolicy({
      documentId: 'DOC-PG-SVC',
      packageId: 'PKG-PG-SVC',
      policyLevel: 'STANDARD',
      allowExtraction: false,
      createdAt: Date.now(),
    });
    assert.equal(secret.byteLength, 32);

    const challenge = await svc1.issueChallenge();
    const first = await svc1.processAuthorizationRequest(
      makeRequest({
        documentId: 'DOC-PG-SVC',
        packageId: 'PKG-PG-SVC',
        challenge,
        operationId: 'OP-PG-1',
      })
    );
    assert.equal(first.granted, true);
    assert.ok(first.grant);

    // One-time wrap-secret release, then the same grant gives nothing.
    assert.equal((await svc1.releaseDocumentWrapSecretForGrant(first.grant!))?.byteLength, 32);
    assert.equal(await svc1.releaseDocumentWrapSecretForGrant(first.grant!), null);

    // Replay of the same challenge + operation is rejected.
    const replay = await svc1.processAuthorizationRequest(
      makeRequest({
        documentId: 'DOC-PG-SVC',
        packageId: 'PKG-PG-SVC',
        challenge,
        operationId: 'OP-PG-1',
      })
    );
    assert.equal(replay.granted, false);
    assert.equal(replay.rejectionCode, 'REPLAY_ATTACK_DETECTED');

    const revoked = await svc1.revokeDocument('DOC-PG-SVC', 'pg test revoke', 'TEST');
    assert.equal(revoked.isRevoked, true);
    await svc1.flush();

    // New service instance over the SAME Postgres database = "restart".
    const svc2 = new DurableAuthorityService({ dataDir: '/tmp/tdcp-pg-test', store });
    await svc2.initialize();
    const state = await svc2.getDocumentRevocationState('DOC-PG-SVC');
    assert.equal(state.isRevoked, true);
    assert.equal(state.currentEpoch, revoked.currentEpoch);
    const policy = await svc2.getDocumentPolicy('DOC-PG-SVC');
    assert.equal(policy?.packageId, 'PKG-PG-SVC');

    // A revoked document grants nothing after restart.
    const challenge2 = await svc2.issueChallenge();
    const denied = await svc2.processAuthorizationRequest(
      makeRequest({
        documentId: 'DOC-PG-SVC',
        packageId: 'PKG-PG-SVC',
        challenge: challenge2,
        operationId: 'OP-PG-2',
      })
    );
    assert.equal(denied.granted, false);

    // And the consumed grant from before the restart is still consumed.
    assert.equal(await svc2.releaseDocumentWrapSecretForGrant(first.grant!), null);
  });
});

describe('createAuthorityStoreFromEnv', () => {
  it('postgres without DATABASE_URL fails loudly instead of silently using the file', () => {
    assert.throws(
      () => createAuthorityStoreFromEnv('/tmp/tdcp-pg-test', { TDCP_AUTHORITY_STORE: 'postgres' }),
      /DATABASE_URL/
    );
  });

  it('an invalid TDCP_AUTHORITY_STORE value fails loudly', () => {
    assert.throws(
      () => createAuthorityStoreFromEnv('/tmp/tdcp-pg-test', { TDCP_AUTHORITY_STORE: 'mysql' }),
      /TDCP_AUTHORITY_STORE inválido/
    );
  });

  it('unset (or "file") selects the file store', () => {
    assert.equal(createAuthorityStoreFromEnv('/tmp/tdcp-pg-test', {}).kind, 'file');
    assert.equal(
      createAuthorityStoreFromEnv('/tmp/tdcp-pg-test', { TDCP_AUTHORITY_STORE: 'file' }).kind,
      'file'
    );
  });
});
