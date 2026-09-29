/**
 * TDCP ↔ Channel Guardian contract and browser-safe PolicyBinding helpers.
 *
 * Authority signs the binding with the same ECDSA P-256 identity used for grants.
 * Gatekeeper verifies it before releasing the wrap secret.
 */
import { computeSHA256, signDataECDSA, verifySignatureECDSA } from '../core/crypto/primitives.ts';

export interface EdgeSpec {
  source: string;
  destination: string;
  expectedBytes: number;
  allowed: boolean;
}

export interface ChannelPolicy {
  documentId: string;
  grantId: string;
  expiry: number;
  edges: EdgeSpec[];
}

export interface PolicyBinding {
  policyCanonical: string;
  policyHash: string;
  signature: string;
  authorityKid: string;
  issuedAt: number;
}

export interface GrantWithChannelBinding {
  grantId: string;
  documentId: string;
  expiresAt: number;
  channelPolicyBinding?: PolicyBinding;
}

export function canonicalizeChannelPolicy(policy: ChannelPolicy): string {
  const edges = [...policy.edges]
    .map((e) => ({ source: e.source, destination: e.destination, expectedBytes: e.expectedBytes, allowed: e.allowed }))
    .sort((a, b) => `${a.source}->${a.destination}`.localeCompare(`${b.source}->${b.destination}`));
  return JSON.stringify({ documentId: policy.documentId, grantId: policy.grantId, expiry: policy.expiry, edges });
}

export function validateChannelPolicy(policy: ChannelPolicy): void {
  if (!policy || typeof policy !== 'object') throw new Error('POLICY_BINDING_INVALID_POLICY');
  if (!policy.documentId || !policy.grantId) throw new Error('POLICY_BINDING_MISSING_ID');
  if (!Number.isFinite(policy.expiry)) throw new Error('POLICY_BINDING_INVALID_EXPIRY');
  if (!Array.isArray(policy.edges) || policy.edges.length === 0) throw new Error('POLICY_BINDING_EMPTY_EDGES');
  const seen = new Set<string>();
  for (const e of policy.edges) {
    if (!e?.source || !e?.destination || !Number.isFinite(e.expectedBytes) || e.expectedBytes < 0 || typeof e.allowed !== 'boolean') {
      throw new Error('POLICY_BINDING_INVALID_EDGE');
    }
    const key = `${e.source}->${e.destination}`;
    if (seen.has(key)) throw new Error(`POLICY_BINDING_DUPLICATE_EDGE:${key}`);
    seen.add(key);
  }
}

export async function createPolicyBinding(
  policy: ChannelPolicy,
  privateKey: CryptoKey,
  authorityKid: string,
  issuedAt = Date.now(),
): Promise<PolicyBinding> {
  validateChannelPolicy(policy);
  const policyCanonical = canonicalizeChannelPolicy(policy);
  const policyHash = await computeSHA256(policyCanonical);
  const signature = await signDataECDSA(privateKey, policyCanonical);
  return { policyCanonical, policyHash, signature, authorityKid, issuedAt };
}

export async function verifyPolicyBinding(
  binding: PolicyBinding,
  authorityPublicKey: CryptoKey,
  expected?: { documentId?: string; grantId?: string; expiresAt?: number; authorityKid?: string },
): Promise<ChannelPolicy> {
  if (expected?.authorityKid && binding.authorityKid !== expected.authorityKid) throw new Error('POLICY_BINDING_AUTHORITY_KID_MISMATCH');
  const hash = await computeSHA256(binding.policyCanonical);
  if (hash !== binding.policyHash) throw new Error('POLICY_BINDING_HASH_MISMATCH');
  if (!(await verifySignatureECDSA(authorityPublicKey, binding.signature, binding.policyCanonical))) {
    throw new Error('POLICY_BINDING_SIGNATURE_INVALID');
  }
  let policy: ChannelPolicy;
  try { policy = JSON.parse(binding.policyCanonical) as ChannelPolicy; }
  catch { throw new Error('POLICY_BINDING_JSON_INVALID'); }
  validateChannelPolicy(policy);
  if (Date.now() > policy.expiry) throw new Error('POLICY_BINDING_EXPIRED');
  if (expected?.documentId && policy.documentId !== expected.documentId) throw new Error('POLICY_BINDING_DOCUMENT_MISMATCH');
  if (expected?.grantId && policy.grantId !== expected.grantId) throw new Error('POLICY_BINDING_GRANT_MISMATCH');
  if (expected?.expiresAt !== undefined && policy.expiry !== expected.expiresAt) throw new Error('POLICY_BINDING_EXPIRY_MISMATCH');
  return policy;
}
