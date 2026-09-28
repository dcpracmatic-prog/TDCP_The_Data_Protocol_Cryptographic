/**
 * TDCP Channel Budget — cooperative workflow-channel plane (in-process).
 *
 * Protects the *workflow channel* after a Gatekeeper grant: authorized edges,
 * byte budgets, quarantine. Does NOT encrypt documents, issue grants, or hold
 * wrap secrets. Uses the same ECDSA P-256 Web Crypto path as AuthorizationGrant.
 *
 * Honest scope: cooperative policy in the process that routes frames through
 * send(). Not a network egress proxy.
 */

import {
  computeSHA256,
  signDataECDSA,
  verifySignatureECDSA,
} from '../core/crypto/primitives.ts';

export type LinkState = 'OPEN' | 'QUARANTINED';

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

export interface AuditEvent {
  event:
    | 'unexpected_egress_blocked'
    | 'policy_binding_rejected'
    | 'link_quarantined';
  edge?: string;
  chunkIdx?: number;
  expectedByteBudget?: number;
  bytesAttempted?: number;
  bytesAlreadyDelivered?: number;
  previousState?: LinkState;
  reason?: string;
  timestamp: number;
}

export interface SendResult {
  accepted: boolean;
  droppedBytes: number;
}

export function edgeKey(e: EdgeSpec): string {
  return `${e.source}->${e.destination}`;
}

/** Deterministic canonical JSON for signing (edges sorted by key). */
export function canonicalizePolicy(policy: ChannelPolicy): string {
  const edges = [...policy.edges].sort((a, b) =>
    edgeKey(a).localeCompare(edgeKey(b)),
  );
  return JSON.stringify({
    documentId: policy.documentId,
    grantId: policy.grantId,
    expiry: policy.expiry,
    edges: edges.map((e) => ({
      source: e.source,
      destination: e.destination,
      expectedBytes: e.expectedBytes,
      allowed: e.allowed,
    })),
  });
}

export function validateChannelPolicy(policy: ChannelPolicy): void {
  if (!policy || typeof policy !== 'object') {
    throw new Error('policy_binding_rejected: invalid policy object');
  }
  if (typeof policy.documentId !== 'string' || !policy.documentId) {
    throw new Error('policy_binding_rejected: documentId required');
  }
  if (typeof policy.grantId !== 'string' || !policy.grantId) {
    throw new Error('policy_binding_rejected: grantId required');
  }
  if (typeof policy.expiry !== 'number' || !Number.isFinite(policy.expiry)) {
    throw new Error('policy_binding_rejected: expiry must be a finite number');
  }
  if (!Array.isArray(policy.edges) || policy.edges.length === 0) {
    throw new Error('policy_binding_rejected: empty edges');
  }
  const seen = new Set<string>();
  for (const e of policy.edges) {
    if (!e || typeof e.source !== 'string' || typeof e.destination !== 'string') {
      throw new Error('policy_binding_rejected: edge source/destination required');
    }
    if (
      typeof e.expectedBytes !== 'number' ||
      e.expectedBytes < 0 ||
      !Number.isFinite(e.expectedBytes)
    ) {
      throw new Error(
        'policy_binding_rejected: expectedBytes must be a non-negative finite number',
      );
    }
    if (typeof e.allowed !== 'boolean') {
      throw new Error('policy_binding_rejected: allowed must be boolean');
    }
    const k = edgeKey(e);
    if (seen.has(k)) {
      throw new Error(`policy_binding_rejected: duplicate edge ${k}`);
    }
    seen.add(k);
  }
}

/** Default edges for a single authorized operation (workflow stages). */
export function defaultOperationEdges(maxBytes: number): EdgeSpec[] {
  return [
    { source: 'GATEKEEPER', destination: 'RUNTIME', expectedBytes: maxBytes, allowed: true },
    { source: 'RUNTIME', destination: 'VIEWER', expectedBytes: maxBytes, allowed: true },
    { source: 'RUNTIME', destination: 'EXTRACT', expectedBytes: maxBytes, allowed: true },
    { source: 'RUNTIME', destination: 'EXFIL', expectedBytes: 0, allowed: false },
  ];
}

export async function signPolicyBinding(
  policy: ChannelPolicy,
  privateKey: CryptoKey,
  authorityKid: string,
): Promise<PolicyBinding> {
  validateChannelPolicy(policy);
  const policyCanonical = canonicalizePolicy(policy);
  const policyHash = await computeSHA256(policyCanonical);
  const signature = await signDataECDSA(privateKey, policyCanonical);
  return {
    policyCanonical,
    policyHash,
    signature,
    authorityKid,
    issuedAt: Date.now(),
  };
}

export async function verifyPolicyBinding(
  binding: PolicyBinding,
  publicKey: CryptoKey,
  expectedGrantId?: string,
): Promise<ChannelPolicy> {
  const expectedHash = await computeSHA256(binding.policyCanonical);
  if (expectedHash !== binding.policyHash) {
    throw new Error('policy_binding_rejected: hash mismatch');
  }
  const ok = await verifySignatureECDSA(
    publicKey,
    binding.signature,
    binding.policyCanonical,
  );
  if (!ok) {
    throw new Error('policy_binding_rejected: invalid signature');
  }
  let policy: ChannelPolicy;
  try {
    policy = JSON.parse(binding.policyCanonical) as ChannelPolicy;
  } catch {
    throw new Error('policy_binding_rejected: canonical JSON parse failed');
  }
  validateChannelPolicy(policy);
  if (policy.expiry < Date.now()) {
    throw new Error('policy_binding_rejected: expired');
  }
  if (expectedGrantId !== undefined && policy.grantId !== expectedGrantId) {
    throw new Error('policy_binding_rejected: grantId mismatch');
  }
  return policy;
}

class BudgetLink {
  private _state: LinkState = 'OPEN';
  private _delivered = 0;
  private readonly _audit: AuditEvent[] = [];
  readonly source: string;
  readonly destination: string;
  readonly expectedBytes: number;
  readonly allowed: boolean;

  constructor(
    source: string,
    destination: string,
    expectedBytes: number,
    allowed: boolean,
  ) {
    this.source = source;
    this.destination = destination;
    this.expectedBytes = expectedBytes;
    this.allowed = allowed;
  }

  get state(): LinkState {
    return this._state;
  }
  get deliveredBytes(): number {
    return this._delivered;
  }
  get auditEvents(): AuditEvent[] {
    return [...this._audit];
  }

  send(frame: Uint8Array, chunkIdx: number): SendResult {
    const n = frame.byteLength;
    if (this._state === 'QUARANTINED') {
      return { accepted: false, droppedBytes: n };
    }
    const wouldExceed = this._delivered + n > this.expectedBytes;
    if (!this.allowed || wouldExceed) {
      const prev = this._state;
      this._state = 'QUARANTINED';
      this._audit.push({
        event: 'unexpected_egress_blocked',
        edge: `${this.source}->${this.destination}`,
        chunkIdx,
        expectedByteBudget: this.expectedBytes,
        bytesAttempted: n,
        bytesAlreadyDelivered: this._delivered,
        previousState: prev,
        timestamp: Date.now(),
      });
      return { accepted: false, droppedBytes: n };
    }
    this._delivered += n;
    return { accepted: true, droppedBytes: 0 };
  }
}

/**
 * Cooperative channel budget bound to a verified PolicyBinding.
 * Materialize only via fromBinding (no mutable edges map from the app).
 */
export class ChannelBudget {
  private readonly policy: ChannelPolicy;
  private readonly links: Map<string, BudgetLink>;
  private readonly _audit: AuditEvent[] = [];

  private constructor(policy: ChannelPolicy) {
    this.policy = policy;
    this.links = new Map();
    for (const e of policy.edges) {
      this.links.set(
        edgeKey(e),
        new BudgetLink(e.source, e.destination, e.expectedBytes, e.allowed),
      );
    }
  }

  static async fromBinding(
    binding: PolicyBinding,
    publicKey: CryptoKey,
    expectedGrantId?: string,
  ): Promise<ChannelBudget> {
    const policy = await verifyPolicyBinding(binding, publicKey, expectedGrantId);
    return new ChannelBudget(policy);
  }

  get grantId(): string {
    return this.policy.grantId;
  }
  get documentId(): string {
    return this.policy.documentId;
  }
  get expiry(): number {
    return this.policy.expiry;
  }

  send(edge: string, frame: Uint8Array, chunkIdx: number): SendResult {
    const now = Date.now();
    if (now > this.policy.expiry) {
      this._audit.push({
        event: 'policy_binding_rejected',
        edge,
        chunkIdx,
        bytesAttempted: frame.byteLength,
        reason: 'binding_expired_at_send',
        timestamp: now,
      });
      return { accepted: false, droppedBytes: frame.byteLength };
    }
    const link = this.links.get(edge);
    if (!link) {
      this._audit.push({
        event: 'unexpected_egress_blocked',
        edge,
        chunkIdx,
        bytesAttempted: frame.byteLength,
        reason: 'edge_not_in_policy_binding',
        timestamp: now,
      });
      return { accepted: false, droppedBytes: frame.byteLength };
    }
    return link.send(frame, chunkIdx);
  }

  auditEvents(): AuditEvent[] {
    const fromLinks: AuditEvent[] = [];
    for (const link of this.links.values()) {
      fromLinks.push(...link.auditEvents);
    }
    return [...this._audit, ...fromLinks].sort((a, b) => a.timestamp - b.timestamp);
  }

  hasBlockedTraffic(): boolean {
    return this.auditEvents().some(
      (e) =>
        e.event === 'unexpected_egress_blocked' ||
        e.event === 'policy_binding_rejected',
    );
  }
}
