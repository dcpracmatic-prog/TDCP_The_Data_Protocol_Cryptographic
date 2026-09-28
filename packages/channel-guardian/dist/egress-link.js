/**
 * EgressLink — single authorized edge with byte budget and state machine.
 */
export class EgressLink {
  /**
   * @param {string} source
   * @param {string} destination
   * @param {number} expectedBytes
   * @param {boolean} allowed
   * @param {"OPEN"|"QUARANTINED"|"UNKNOWN"} [initialState="OPEN"]
   */
  constructor(source, destination, expectedBytes, allowed, initialState = "OPEN") {
    this.source = source;
    this.destination = destination;
    this.expectedBytes = expectedBytes;
    this.allowed = allowed;
    this._state = initialState;
    this._attemptedBytes = 0;
    this._delivered = [];
    this._droppedBytes = 0;
    this._escapedBytes = 0;
    this._firstBlockChunk = null;
    this._auditEvents = [];
  }

  get state() {
    return this._state;
  }
  get attemptedBytes() {
    return this._attemptedBytes;
  }
  get deliveredBytes() {
    return this._delivered.reduce((n, b) => n + b.length, 0);
  }
  get delivered() {
    return Buffer.concat(this._delivered);
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
   * @param {Buffer|Uint8Array} frame
   * @param {number} chunkIdx
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

    this._delivered.push(buf);
    this._escapedBytes += buf.length;
    return { accepted: true, droppedBytes: 0 };
  }
}
