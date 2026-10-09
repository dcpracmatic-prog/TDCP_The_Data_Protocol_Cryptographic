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
import type { AuditEvent, PolicyBinding, SendResult } from "./types.js";
export declare class ChannelGuardian {
    private readonly policy;
    private readonly links;
    private readonly binding;
    private readonly _audit;
    private constructor();
    /**
     * Create a Guardian from an Authority-signed PolicyBinding.
     * This is the ONLY public constructor path — prevents D2 (policy/link mismatch).
     */
    static fromBinding(binding: PolicyBinding, authorityPublicKey: KeyObject | string): ChannelGuardian;
    get documentId(): string;
    get grantId(): string;
    get expiry(): number;
    get policyHash(): string;
    /** List of edge keys materialised from the binding. */
    edgeKeys(): string[];
    hasEdge(key: string): boolean;
    getLink(key: string): EgressLink | undefined;
    /**
     * Send a frame on a named edge.
     * Unknown edges are rejected and audited (no silent drop without record).
     */
    send(edgeKey: string, frame: Buffer | Uint8Array, chunkIdx: number): SendResult;
    /** Aggregate audit events from the guardian and all links. */
    auditEvents(): AuditEvent[];
    /** Snapshot of delivered bytes per edge (for tests / monitoring). */
    deliveredSnapshot(): Record<string, number>;
    /** True if any link is quarantined or an unknown-edge attempt was recorded. */
    hasBlockedTraffic(): boolean;
}
//# sourceMappingURL=guardian.d.ts.map