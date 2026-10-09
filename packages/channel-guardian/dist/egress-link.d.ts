/**
 * EgressLink — single authorized edge with byte budget and state machine.
 *
 * Scope: transport protection only. No content inspection, no grant logic.
 */
import type { AuditEvent, LinkState, SendResult } from "./types.js";
export declare class EgressLink {
    readonly source: string;
    readonly destination: string;
    readonly expectedBytes: number;
    readonly allowed: boolean;
    private _state;
    private _attemptedBytes;
    private _deliveredBytes;
    private _droppedBytes;
    private _escapedBytes;
    private _firstBlockChunk;
    private _auditEvents;
    constructor(source: string, destination: string, expectedBytes: number, allowed: boolean, initialState?: LinkState);
    get state(): LinkState;
    get attemptedBytes(): number;
    get deliveredBytes(): number;
    get droppedBytes(): number;
    get escapedBytes(): number;
    get firstBlockChunk(): number | null;
    get auditEvents(): readonly AuditEvent[];
    /**
     * Attempt to send a frame on this edge.
     * Returns whether the frame was accepted into the delivered buffer.
     */
    send(frame: Buffer | Uint8Array, chunkIdx: number): SendResult;
}
//# sourceMappingURL=egress-link.d.ts.map