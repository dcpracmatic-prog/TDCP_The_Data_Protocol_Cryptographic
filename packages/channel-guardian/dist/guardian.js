/**
 * ChannelGuardian — factory and runtime protector.
 *
 * - Accepts only a verified PolicyBinding (closes D1/D1b/D2).
 * - Materializes EgressLink instances from the signed policy; no mutable edges map.
 * - Exposes send() by edge key; blocks unauthorised or over-budget traffic.
 * - Emits audit events; never holds Authority private keys or wrap secrets.
 */
import { EgressLink } from "./egress-link.js";
import { edgeKey, verifyPolicyBinding } from "./policy.js";
export class ChannelGuardian {
    policy;
    links;
    binding;
    _audit = [];
    constructor(policy, binding) {
        this.policy = policy;
        this.binding = binding;
        this.links = new Map();
        for (const edge of policy.edges) {
            const key = edgeKey(edge);
            const link = new EgressLink(edge.source, edge.destination, edge.expectedBytes, edge.allowed, "OPEN");
            this.links.set(key, link);
        }
    }
    /**
     * Create a Guardian from an Authority-signed PolicyBinding.
     * This is the ONLY public constructor path — prevents D2 (policy/link mismatch).
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
    /** List of edge keys materialised from the binding. */
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
     * Send a frame on a named edge.
     * Unknown edges are rejected and audited (no silent drop without record).
     */
    send(edgeKey, frame, chunkIdx) {
        const now = Date.now();
        if (now > this.policy.expiry) {
            const dropped = Buffer.isBuffer(frame) ? frame.length : frame.length;
            this._audit.push({
                event: "policy_binding_rejected",
                edge: edgeKey,
                chunkIdx,
                bytesAttempted: dropped,
                reason: "binding_expired_at_send",
                timestamp: now,
            });
            return { accepted: false, droppedBytes: dropped };
        }
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
    auditEvents() {
        const fromLinks = [];
        for (const link of this.links.values()) {
            fromLinks.push(...link.auditEvents);
        }
        return [...this._audit, ...fromLinks].sort((a, b) => a.timestamp - b.timestamp);
    }
    /** Snapshot of delivered bytes per edge (for tests / monitoring). */
    deliveredSnapshot() {
        const out = {};
        for (const [key, link] of this.links) {
            out[key] = link.deliveredBytes;
        }
        return out;
    }
    /** True if any link is quarantined or an unknown-edge attempt was recorded. */
    hasBlockedTraffic() {
        if (this._audit.some((e) => e.event === "unexpected_egress_blocked")) {
            return true;
        }
        for (const link of this.links.values()) {
            if (link.state === "QUARANTINED")
                return true;
        }
        return false;
    }
}
