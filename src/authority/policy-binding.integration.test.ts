import assert from 'node:assert/strict';
import test from 'node:test';
import { AuthorizationOracle } from '../oracle/authorization-oracle.ts';
import { InProcessAuthority } from './in-process-authority.ts';
import { verifyPolicyBinding } from '../channel/policy-binding.ts';

test('Authority emits PolicyBinding cryptographically bound to Grant', async () => {
  const oracle = new AuthorizationOracle();
  const authority = new InProcessAuthority(oracle);
  await authority.initialize();
  await authority.registerDocumentPolicy({
    documentId: 'DOC-PB-1', packageId: 'PKG-PB-1', policyLevel: 'STANDARD',
    allowExtraction: false, createdAt: Date.now(),
    channelEdges: [{ source: 'A', destination: 'B', expectedBytes: 1024, allowed: true }],
  });
  const challenge = await authority.issueChallenge();
  const result = await authority.processAuthorizationRequest({
    requestId: 'REQ-PB-1', documentId: 'DOC-PB-1', packageId: 'PKG-PB-1', deviceId: 'DEV-1',
    credentialId: 'CRED-1', operationId: 'OP-PB-1', challenge, requestedOperation: 'READ', timestamp: Date.now(),
  });
  assert.equal(result.granted, true);
  assert.ok(result.grant);
  assert.ok(result.channelPolicyBinding);
  const policy = await verifyPolicyBinding(result.channelPolicyBinding!, await authority.getPublicKey(), {
    documentId: result.grant!.documentId, grantId: result.grant!.grantId,
    expiresAt: result.grant!.expiresAt, authorityKid: result.grant!.oracleKeyId,
  });
  assert.equal(policy.documentId, result.grant!.documentId);
  assert.equal(policy.grantId, result.grant!.grantId);
  assert.equal(policy.edges[0].expectedBytes, 1024);
});

test('PolicyBinding rejects grant substitution', async () => {
  const oracle = new AuthorizationOracle();
  const authority = new InProcessAuthority(oracle);
  await authority.initialize();
  await authority.registerDocumentPolicy({
    documentId: 'DOC-PB-2', packageId: 'PKG-PB-2', policyLevel: 'STANDARD',
    allowExtraction: false, createdAt: Date.now(),
    channelEdges: [{ source: 'A', destination: 'B', expectedBytes: 512, allowed: true }],
  });
  const challenge = await authority.issueChallenge();
  const result = await authority.processAuthorizationRequest({
    requestId: 'REQ-PB-2', documentId: 'DOC-PB-2', packageId: 'PKG-PB-2', deviceId: 'DEV-2',
    credentialId: 'CRED-2', operationId: 'OP-PB-2', challenge, requestedOperation: 'READ', timestamp: Date.now(),
  });
  assert.equal(result.granted, true);
  assert.ok(result.channelPolicyBinding);
  const pub = await authority.getPublicKey();
  // Same binding must not verify against a different grantId
  await assert.rejects(
    () =>
      verifyPolicyBinding(result.channelPolicyBinding!, pub, {
        documentId: result.grant!.documentId,
        grantId: 'GRANT-FORGED-OTHER',
        expiresAt: result.grant!.expiresAt,
        authorityKid: result.grant!.oracleKeyId,
      }),
    /POLICY_BINDING_GRANT_MISMATCH|grantId/i,
  );
  // Tampered canonical must fail signature
  const tampered = {
    ...result.channelPolicyBinding!,
    policyCanonical: result.channelPolicyBinding!.policyCanonical.replace(
      result.grant!.grantId,
      'GRANT-TAMPERED',
    ),
  };
  await assert.rejects(
    () => verifyPolicyBinding(tampered, pub, {
      documentId: result.grant!.documentId,
      grantId: result.grant!.grantId,
      expiresAt: result.grant!.expiresAt,
    }),
    /POLICY_BINDING|signature|hash/i,
  );
});
