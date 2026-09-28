/**
 * ChannelBudget plane tests (Web Crypto / same path as grants).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  ChannelBudget,
  canonicalizePolicy,
  defaultOperationEdges,
  signPolicyBinding,
  validateChannelPolicy,
  verifyPolicyBinding,
} from './channel-budget.ts';

async function testKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
}

function policy(overrides: Record<string, unknown> = {}) {
  return {
    documentId: 'doc-1',
    grantId: 'GRANT-1',
    expiry: Date.now() + 60_000,
    edges: defaultOperationEdges(100),
    ...overrides,
  };
}

describe('ChannelBudget', () => {
  it('signs and verifies binding bound to grantId', async () => {
    const { publicKey, privateKey } = await testKeyPair();
    const p = policy();
    const binding = await signPolicyBinding(p, privateKey, 'kid-1');
    const parsed = await verifyPolicyBinding(binding, publicKey, p.grantId);
    assert.equal(parsed.grantId, 'GRANT-1');
    assert.equal(parsed.documentId, 'doc-1');
  });

  it('rejects grantId mismatch', async () => {
    const { publicKey, privateKey } = await testKeyPair();
    const binding = await signPolicyBinding(policy(), privateKey, 'kid-1');
    await assert.rejects(
      () => verifyPolicyBinding(binding, publicKey, 'OTHER-GRANT'),
      /grantId mismatch/,
    );
  });

  it('rejects duplicate edges', () => {
    assert.throws(
      () =>
        validateChannelPolicy(
          policy({
            edges: [
              { source: 'A', destination: 'B', expectedBytes: 1, allowed: true },
              { source: 'A', destination: 'B', expectedBytes: 2, allowed: true },
            ],
          }),
        ),
      /duplicate edge/,
    );
  });

  it('allows budgeted edges and blocks EXFIL', async () => {
    const { publicKey, privateKey } = await testKeyPair();
    const binding = await signPolicyBinding(policy(), privateKey, 'kid-1');
    const budget = await ChannelBudget.fromBinding(binding, publicKey, 'GRANT-1');
    const frame = new Uint8Array(50);
    assert.equal(budget.send('GATEKEEPER->RUNTIME', frame, 0).accepted, true);
    assert.equal(budget.send('RUNTIME->EXFIL', frame, 1).accepted, false);
    assert.ok(budget.hasBlockedTraffic());
  });

  it('rejects over-budget and unknown edges', async () => {
    const { publicKey, privateKey } = await testKeyPair();
    const binding = await signPolicyBinding(policy(), privateKey, 'kid-1');
    const budget = await ChannelBudget.fromBinding(binding, publicKey, 'GRANT-1');
    const big = new Uint8Array(200);
    assert.equal(budget.send('RUNTIME->VIEWER', big, 0).accepted, false);
    assert.equal(budget.send('A->Z', new Uint8Array(1), 1).accepted, false);
  });

  it('canonicalize is order-independent for edges', () => {
    const a = policy({
      edges: [
        { source: 'B', destination: 'C', expectedBytes: 1, allowed: true },
        { source: 'A', destination: 'B', expectedBytes: 1, allowed: true },
      ],
    });
    const b = policy({
      edges: [
        { source: 'A', destination: 'B', expectedBytes: 1, allowed: true },
        { source: 'B', destination: 'C', expectedBytes: 1, allowed: true },
      ],
    });
    assert.equal(canonicalizePolicy(a), canonicalizePolicy(b));
  });
});
