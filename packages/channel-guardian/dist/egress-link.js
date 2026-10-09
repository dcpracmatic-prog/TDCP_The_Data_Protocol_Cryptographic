/**
 * EgressLink — single authorized edge with byte budget and state machine.
 *
 * Scope: transport protection only. No content inspection, no grant logic.
 */
export class EgressLink {
    source;
    destination;
    expectedBytes;
    allowed;
    _state;
    _attemptedBytes = 0;
    _deliveredBytes = 0;
    _droppedBytes = 0;
    _escapedBytes = 0;
    _firstBlockChunk = null;
    _auditEvents = [];
    constructor(source, destination, expectedBytes, allowed, initialState = "OPEN") {
        this.source = source;
        this.destination = destination;
        this.expectedBytes = expectedBytes;
        this.allowed = allowed;
        this._state = initialState;
    }
    get state() {
        return this._state;
    }
    get attemptedBytes() {
        return this._attemptedBytes;
    }
    get deliveredBytes() {
        return this._deliveredBytes;
    }
    get droppedBytes() {
        return this._droppedBytes;
    }
    get escapedBytes() {
        return this._escapedBytes;
    }
    get firstBlockChunk() {
        return this._firstBlockChunk;
    }
    get auditEvents() {
        return this._auditEvents;
    }
    /**
     * Attempt to send a frame on this edge.
     * Returns whether the frame was accepted into the delivered buffer.
     */
    send(frame, chunkIdx) {
        const buf = Buffer.isBuffer(frame) ? frame : Buffer.from(frame);
        this._attemptedBytes += buf.length;
        if (this._state === "QUARANTINED" || this._state === "UNKNOWN") {
            this._droppedBytes += buf.length;
            return { accepted: false, droppedBytes: buf.length };
        }
        const wouldExceed = this.deliveredBytes + buf.length > this.expectedBytes;
        if (!this.allowed || wouldExceed) {
            const prev = this._state;
            this._state = "QUARANTINED";
            this._droppedBytes += buf.length;
            if (this._firstBlockChunk === null) {
                this._firstBlockChunk = chunkIdx;
            }
            this._auditEvents.push({
                event: "unexpected_egress_blocked",
                edge: `${this.source}->${this.destination}`,
                chunkIdx,
                expectedByteBudget: this.expectedBytes,
                bytesAttempted: buf.length,
                bytesAlreadyDelivered: this.deliveredBytes,
                previousState: prev,
                timestamp: Date.now(),
            });
            return { accepted: false, droppedBytes: buf.length };
        }
        // Deliberately do not retain plaintext/data-plane frames in memory.
        this._deliveredBytes += buf.length;
        this._escapedBytes += buf.length;
        return { accepted: true, droppedBytes: 0 };
    }
}
