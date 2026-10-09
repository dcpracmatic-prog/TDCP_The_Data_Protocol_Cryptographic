/**
 * TDCP Channel Guardian — shared types.
 *
 * Scope: protect the communication channel between sensitive data and
 * encryption/authorization processes. Does NOT issue grants, evaluate
 * business policy, or hold wrap secrets.
 */
/** Link lifecycle states. */
export type LinkState = "OPEN" | "QUARANTINED" | "UNKNOWN";
/** Single authorized edge in a channel policy. */
export interface EdgeSpec {
    /** Source node identifier (e.g. "A", "B"). */
    source: string;
    /** Destination node identifier (e.g. "B", "C", "D"). */
    destination: string;
    /** Maximum bytes allowed on this edge for the operation. */
    expectedBytes: number;
    /** Whether traffic is permitted on this edge. */
    allowed: boolean;
}
/** Canonical channel policy signed by the TDCP Authority. */
export interface ChannelPolicy {
    /** Document / package identifier this policy applies to. */
    documentId: string;
    /** Grant identifier issued by Authority (one-time). */
    grantId: string;
    /** Unix timestamp (ms) after which the binding is invalid. */
    expiry: number;
    /** Authorized edges. */
    edges: EdgeSpec[];
}
/**
 * Cryptographic binding of a ChannelPolicy.
 * Produced by the TDCP Authority; verified by the Guardian before
 * materializing any EgressLink.
 */
export interface PolicyBinding {
    /** Canonical JSON of the ChannelPolicy (deterministic serialization). */
    policyCanonical: string;
    /** SHA-256 of policyCanonical (hex). */
    policyHash: string;
    /**
     * Signature over policyCanonical produced by the Authority.
     * In production this is ECDSA P-256 (same curve as TDCP grants).
     * The Guardian only verifies; it never holds the private key.
     */
    signature: string;
    /** Authority public key identifier / kid used for verification. */
    authorityKid: string;
    /** Wall-clock issuance time (ms). */
    issuedAt: number;
}
/** Audit event emitted when the Guardian blocks unexpected egress. */
export interface AuditEvent {
    event: "unexpected_egress_blocked" | "policy_binding_rejected" | "link_quarantined";
    edge?: string;
    chunkIdx?: number;
    expectedByteBudget?: number;
    bytesAttempted?: number;
    bytesAlreadyDelivered?: number;
    previousState?: LinkState;
    reason?: string;
    timestamp: number;
}
/** Result of a send attempt. */
export interface SendResult {
    accepted: boolean;
    droppedBytes: number;
}
//# sourceMappingURL=types.d.ts.map