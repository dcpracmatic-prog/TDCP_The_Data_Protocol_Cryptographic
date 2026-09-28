/**
 * ChannelGuardian — factory and runtime protector.
 *
 * - Accepts only a verified PolicyBinding (closes D1/D1b/D2).
 * - Materializes EgressLink instances from the signed policy; no mutable edges map.
 * - Exposes send() by edge key; blocks unauthorised or over-budget traffic.
 * - Emits audit events; never holds Authority private keys or wrap secrets.
 */

import type { KeyObject } from "node:crypto";
import { EgressLink } from "./egress-link.js";
import { edgeKey, verifyPolicyBinding } from "./policy.js";
import type {
  AuditEvent,
  ChannelPolicy,
  PolicyBinding,
  SendResult,
} from "./types.js";

export class ChannelGuardian {
  private readonly policy: ChannelPolicy;
  private readonly links: Map<string, EgressLink>;
  private readonly binding: PolicyBinding;
  private readonly _audit: AuditEvent[] = [];

  private constructor(policy: ChannelPolicy, binding: PolicyBinding) {
    this.policy = policy;
    this.binding = binding;
    this.links = new Map();

    for (const edge of policy.edges) {
      const key = edgeKey(edge);
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
   * Create a Guardian from an Authority-signed PolicyBinding.
   * This is the ONLY public constructor path — prevents D2 (policy/link mismatch).
   */
  static fromBinding(
    binding: PolicyBinding,
    authorityPublicKey: KeyObject | string,
  ): ChannelGuardian {
    const policy = verifyPolicyBinding(binding, authorityPublicKey);
    return new ChannelGuardian(policy, binding);
  }

  get documentId(): string {
    return this.policy.documentId;
  }

  get grantId(): string {
    return this.policy.grantId;
  }

  get expiry(): number {
    return this.policy.expiry;
  }

  get policyHash(): string {
    return this.binding.policyHash;
  }

  /** List of edge keys materialised from the binding. */
  edgeKeys(): string[] {
    return [...this.links.keys()];
  }

  hasEdge(key: string): boolean {
    return this.links.has(key);
  }

  getLink(key: string): EgressLink | undefined {
    return this.links.get(key);
  }

  /**
   * Send a frame on a named edge.
   * Unknown edges are rejected and audited (no silent drop without record).
   */
  send(edgeKey: string, frame: Buffer | Uint8Array, chunkIdx: number): SendResult {
    const link = this.links.get(edgeKey);
    if (!link) {
      const dropped = Buffer.isBuffer(frame) ? frame.length : frame.length;
      this._audit.push({
        event: "unexpected_egress_blocked",
        edge: edgeKey,
        chunkIdx,
        bytesAttempted: dropped,
        reason: "edge_not_in_policy_binding",
        timestamp: Date.now(),
      });
      return { accepted: false, droppedBytes: dropped };
    }
    return link.send(frame, chunkIdx);
  }

  /** Aggregate audit events from the guardian and all links. */
  auditEvents(): AuditEvent[] {
    const fromLinks: AuditEvent[] = [];
    for (const link of this.links.values()) {
      fromLinks.push(...link.auditEvents);
    }
    return [...this._audit, ...fromLinks].sort(
      (a, b) => a.timestamp - b.timestamp,
    );
  }

  /** Snapshot of delivered bytes per edge (for tests / monitoring). */
  deliveredSnapshot(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const [key, link] of this.links) {
      out[key] = link.deliveredBytes;
    }
    return out;
  }

  /** True if any link is quarantined or an unknown-edge attempt was recorded. */
  hasBlockedTraffic(): boolean {
    if (this._audit.some((e) => e.event === "unexpected_egress_blocked")) {
      return true;
    }
    for (const link of this.links.values()) {
      if (link.state === "QUARANTINED") return true;
    }
    return false;
  }
}
