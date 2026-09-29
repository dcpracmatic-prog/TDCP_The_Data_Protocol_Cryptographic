/**
 * EgressLink — single authorized edge with byte budget and state machine.
 *
 * Scope: transport protection only. No content inspection, no grant logic.
 */

import type { AuditEvent, LinkState, SendResult } from "./types.js";

export class EgressLink {
  readonly source: string;
  readonly destination: string;
  readonly expectedBytes: number;
  readonly allowed: boolean;

  private _state: LinkState;
  private _attemptedBytes = 0;
  private _deliveredBytes = 0;
  private _droppedBytes = 0;
  private _escapedBytes = 0;
  private _firstBlockChunk: number | null = null;
  private _auditEvents: AuditEvent[] = [];

  constructor(
    source: string,
    destination: string,
    expectedBytes: number,
    allowed: boolean,
    initialState: LinkState = "OPEN",
  ) {
    this.source = source;
    this.destination = destination;
    this.expectedBytes = expectedBytes;
    this.allowed = allowed;
    this._state = initialState;
  }

  get state(): LinkState {
    return this._state;
  }

  get attemptedBytes(): number {
    return this._attemptedBytes;
  }

  get deliveredBytes(): number {
    return this._deliveredBytes;
  }

  get droppedBytes(): number {
    return this._droppedBytes;
  }

  get escapedBytes(): number {
    return this._escapedBytes;
  }

  get firstBlockChunk(): number | null {
    return this._firstBlockChunk;
  }

  get auditEvents(): readonly AuditEvent[] {
    return this._auditEvents;
  }

  /**
   * Attempt to send a frame on this edge.
   * Returns whether the frame was accepted into the delivered buffer.
   */
  send(frame: Buffer | Uint8Array, chunkIdx: number): SendResult {
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
