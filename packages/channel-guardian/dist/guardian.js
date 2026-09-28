/**
 * ChannelGuardian — factory and runtime protector.
 * Accepts only a verified PolicyBinding (closes D1/D1b/D2).
 */
import { EgressLink } from "./egress-link.js";
import { edgeKey, verifyPolicyBinding } from "./policy.js";

export class ChannelGuardian {
  /**
   * @param {import('../src/types.ts').ChannelPolicy} policy
   * @param {import('../src/types.ts').PolicyBinding} binding
   */
  constructor(policy, binding) {
    this.policy = policy;
    this.binding = binding;
    this.links = new Map();
    this._audit = [];

    for (const edge of policy.edges) {
      const key = edgeKey(edge);
      // Disallowed edges start OPEN so the first attempt transitions to
      // QUARANTINED (matches original PoC). UNKNOWN is reserved for
      // edges that were never in the policy (handled in send()).
      const link = new EgressLink(
        edge.source,
        edge.destination,
        edge.expectedBytes,
        edge.allowed,
        "OPEN",
      );
      this.links.set(key, link);
    }
  }

  /**
   * @param {import('../src/types.ts').PolicyBinding} binding
   * @param {import('node:crypto').KeyObject | string} authorityPublicKey
   */
  static fromBinding(binding, authorityPublicKey) {
    const policy = verifyPolicyBinding(binding, authorityPublicKey);
    return new ChannelGuardian(policy, binding);
  }

  get documentId() {
    return this.policy.documentId;
  }
  get grantId() {
    return this.policy.grantId;
  }
  get expiry() {
    return this.policy.expiry;
  }
  get policyHash() {
    return this.binding.policyHash;
  }

  edgeKeys() {
    return [...this.links.keys()];
  }

  hasEdge(key) {
    return this.links.has(key);
  }

  getLink(key) {
    return this.links.get(key);
  }

  /**
   * @param {string} edgeKeyName
   * @param {Buffer|Uint8Array} frame
   * @param {number} chunkIdx
   */
  send(edgeKeyName, frame, chunkIdx) {
    const now = Date.now();
    if (now > this.policy.expiry) {
      const dropped = Buffer.isBuffer(frame) ? frame.length : frame.length;
      this._audit.push({
        event: "policy_binding_rejected",
        edge: edgeKeyName,
        chunkIdx,
        bytesAttempted: dropped,
        reason: "binding_expired_at_send",
        timestamp: now,
      });
      return { accepted: false, droppedBytes: dropped };
    }
    const link = this.links.get(edgeKeyName);
    if (!link) {
      const dropped = Buffer.isBuffer(frame) ? frame.length : frame.length;
      this._audit.push({
        event: "unexpected_egress_blocked",
        edge: edgeKeyName,
        chunkIdx,
        bytesAttempted: dropped,
        reason: "edge_not_in_policy_binding",
        timestamp: Date.now(),
      });
      return { accepted: false, droppedBytes: dropped };
    }
    return link.send(frame, chunkIdx);
  }

  auditEvents() {
    const fromLinks = [];
    for (const link of this.links.values()) {
      fromLinks.push(...link.auditEvents);
    }
    return [...this._audit, ...fromLinks].sort(
      (a, b) => a.timestamp - b.timestamp,
    );
  }

  deliveredSnapshot() {
    const out = {};
    for (const [key, link] of this.links) {
      out[key] = link.deliveredBytes;
    }
    return out;
  }

  hasBlockedTraffic() {
    if (this._audit.some((e) => e.event === "unexpected_egress_blocked")) {
      return true;
    }
    for (const link of this.links.values()) {
      if (link.state === "QUARANTINED") return true;
    }
    return false;
  }
}
