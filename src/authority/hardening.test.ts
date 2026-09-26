/**
 * Hardening tests: encrypted keys, bounded replay, client IP identity, file rate limit.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AntiReplayRegistry } from '../core/replay/replay-cache.ts';
import {
  encryptPrivateJwk,
  decryptPrivateJwk,
  isEncryptedPrivateKeyBlob,
} from '../../server/authority/encrypted-key-store.ts';
import {
  normalizeIp,
  clientKey,
  FileRateLimiter,
  InMemoryRateLimiter,
} from '../../server/authority/rate-limit.ts';

describe('AntiReplayRegistry bounds', () => {
  it('evicts when over maxConsumed and supports O(1) challenge replay', () => {
    const reg = new AntiReplayRegistry({
      maxConsumed: 5,
      maxActiveChallenges: 10,
      consumedTtlMs: 60_000,
      challengeTtlMs: 60_000,
    });
    const now = Date.now();
    for (let i = 0; i < 8; i++) {
      const challenge = `ch-${i}`;
      reg.registerFreshChallenge(challenge, now);
      const ok = reg.consumeOperation({
        operationId: `op-${i}`,
        challenge,
        grantId: `g-${i}`,
        documentId: 'doc',
        deviceId: 'dev',
        consumedAt: now + i,
      });
      assert.equal(ok, true);
    }
    assert.ok(reg.stats().consumed <= 5);
    assert.equal(reg.isReplayed('op-7', 'ch-7'), true);
  });

  it('exportConsumed is bounded after TTL prune', () => {
    const reg = new AntiReplayRegistry({ consumedTtlMs: 1, maxConsumed: 100 });
    const past = Date.now() - 10_000;
    reg.hydrateConsumed([
      {
        operationId: 'old',
        challenge: 'c',
        grantId: 'g',
        documentId: 'd',
        deviceId: 'x',
        consumedAt: past,
      },
    ]);
    assert.equal(reg.exportConsumed().length, 0);
  });
});

describe('encrypted private JWK at rest', () => {
  it('round-trips AES-GCM blob', () => {
    const jwk = { kty: 'EC', crv: 'P-256', d: 'abc', x: 'x', y: 'y' } as JsonWebKey;
    const blob = encryptPrivateJwk(jwk, 'test-passphrase-not-for-prod');
    assert.equal(isEncryptedPrivateKeyBlob(blob), true);
    const out = decryptPrivateJwk(blob, 'test-passphrase-not-for-prod');
    assert.equal(out.d, 'abc');
    assert.throws(() => decryptPrivateJwk(blob, 'wrong'));
  });
});

describe('client IP identity', () => {
  it('normalizeIp strips mapped IPv6 and ports', () => {
    assert.equal(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1');
    assert.equal(normalizeIp('192.168.1.10:443'), '192.168.1.10');
    assert.equal(normalizeIp('[fe80::1%lo0]'), 'fe80::1');
  });

  it('clientKey ignores X-Forwarded-For unless trustProxy', () => {
    const req = {
      socket: { remoteAddress: '10.0.0.5' },
      headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' },
    };
    assert.equal(clientKey(req, { trustProxy: false }), '10.0.0.5');
    assert.equal(clientKey(req, { trustProxy: true }), '1.2.3.4');
  });
});

describe('FileRateLimiter', () => {
  it('enforces window across checks', () => {
    const dir = mkdtempSync(join(tmpdir(), 'tdcp-rl-'));
    try {
      const lim = new FileRateLimiter({ dir, windowMs: 60_000, maxHits: 3 });
      assert.equal(lim.check('k').allowed, true);
      assert.equal(lim.check('k').allowed, true);
      assert.equal(lim.check('k').allowed, true);
      assert.equal(lim.check('k').allowed, false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('InMemoryRateLimiter key cap', () => {
  it('does not grow without bound', () => {
    const lim = new InMemoryRateLimiter({ windowMs: 60_000, maxHits: 5, maxKeys: 10 });
    for (let i = 0; i < 50; i++) lim.check(`client-${i}`);
    // Internal map not exposed; just ensure no throw and checks still work
    assert.equal(lim.check('client-0').allowed, true);
  });
});
