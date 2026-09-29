/**
 * A challenge issued to userA must still be rejected for userB after the
 * Authority process restarts (challengeSubjects is durable, not just in-RAM).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DurableAuthorityService } from '../../server/authority/service.ts';

describe('challengeSubjects survives Authority restart', () => {
  it('rejects a cross-user challenge after reload from disk', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'tdcp-challenge-subject-'));
    try {
      const svc1 = new DurableAuthorityService({ dataDir, requireSubject: true });
      await svc1.initialize();

      const challenge = await svc1.issueChallenge('user-A');

      // Simulate a process restart: a fresh service instance reading the same dataDir.
      const svc2 = new DurableAuthorityService({ dataDir, requireSubject: true });
      await svc2.initialize();

      const result = await svc2.processAuthorizationRequest({
        challenge,
        documentId: 'doc-does-not-matter',
        packageId: 'pkg',
        operationId: 'op-1',
        requestedOperation: 'READ',
        subjectUserId: 'user-B', // attacker/other user reusing the challenge string
      } as Parameters<DurableAuthorityService['processAuthorizationRequest']>[0]);

      assert.equal(result.granted, false);
      assert.equal(result.rejectionCode, 'CHALLENGE_SUBJECT_MISMATCH');
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });
});
