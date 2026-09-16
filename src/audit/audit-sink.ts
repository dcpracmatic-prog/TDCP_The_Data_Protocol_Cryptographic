/**
 * The Data Cryptographic Protocol (TDCP)
 * Audit Sink Abstraction (Local vs Remote Authoritative Ledger)
 *
 * Rules:
 * - LocalAuditSink: Browser-level tamper-evident verification.
 *   NEVER claim "immutable ledger" for this sink.
 * - RemoteAuditSink: PRODUCTION STUB. Not an immutable ledger in this build.
 */

import { createChainedAuditEvent, canonicalizeAuditEvent } from './audit-event.ts';
import type { AuditEvent } from './audit-event.ts';
import { computeSHA256, generateRandomId } from '../core/crypto/primitives.ts';

export const TDCP_AUDIT_UPDATED_EVENT = 'tdcp-audit-updated';

export interface AuditSink {
  sinkName: string;
  isAuthoritative: boolean;
  integrityClaim: string;
  recordEvent(
    eventParams: Omit<AuditEvent, 'eventId' | 'timestamp' | 'eventHash' | 'previousEventHash'>
  ): Promise<AuditEvent>;
  getEvents(): Promise<AuditEvent[]>;
  verifyIntegrity(): Promise<{ isValid: boolean; checkedCount: number; error?: string }>;
}

export const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function notifyAuditUpdated(): void {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(TDCP_AUDIT_UPDATED_EVENT));
  }
}

/**
 * Local in-memory tamper-evident audit sink.
 * DEVELOPMENT / DEMO. This is NOT an immutable ledger.
 */
export class LocalAuditSink implements AuditSink {
  public sinkName = 'LocalAuditSink (tamper-evident local audit)';
  public isAuthoritative = false;
  public integrityClaim = 'tamper-evident local audit';

  private events: AuditEvent[] = [];
  private genesisReady: Promise<void>;

  constructor() {
    this.genesisReady = this.initGenesis();
  }

  private async initGenesis(): Promise<void> {
    if (this.events.length === 0) {
      const genesisPartial = {
        eventId: 'AUDIT-GENESIS-0000',
        timestamp: 1700000000000,
        documentId: 'SYSTEM',
        packageId: 'SYSTEM',
        deviceId: 'ROOT',
        credentialId: 'ROOT',
        operationId: 'GENESIS',
        operation: 'LEDGER_INITIALIZED',
        policy: 'SYSTEM_ROOT',
        result: 'SUCCESS' as const,
        details: 'TDCP tamper-evident local audit initialized (DEVELOPMENT)',
      };
      const genesis = await createChainedAuditEvent(genesisPartial, GENESIS_HASH);
      this.events.push(genesis);
    }
  }

  public async recordEvent(
    eventParams: Omit<AuditEvent, 'eventId' | 'timestamp' | 'eventHash' | 'previousEventHash'>
  ): Promise<AuditEvent> {
    await this.genesisReady;
    const lastEvent = this.events[this.events.length - 1];
    const previousHash = lastEvent ? lastEvent.eventHash : GENESIS_HASH;

    const fullParams = {
      ...eventParams,
      eventId: generateRandomId('EVT'),
      timestamp: Date.now(),
    };

    const chainedEvent = await createChainedAuditEvent(fullParams, previousHash);
    this.events.push(chainedEvent);
    notifyAuditUpdated();
    return chainedEvent;
  }

  public async getEvents(): Promise<AuditEvent[]> {
    await this.genesisReady;
    return [...this.events];
  }

  public async verifyIntegrity(): Promise<{ isValid: boolean; checkedCount: number; error?: string }> {
    await this.genesisReady;
    if (this.events.length === 0) {
      return { isValid: true, checkedCount: 0 };
    }

    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < this.events.length; i++) {
      const current = this.events[i];

      if (current.previousEventHash !== expectedPrevHash) {
        return {
          isValid: false,
          checkedCount: i,
          error: `Ruptura en eslabón hash en evento índice ${i} (${current.eventId}). Hash previo no coincide.`,
        };
      }

      const { eventHash: _eventHash, ...unsigned } = current;
      const canonical = canonicalizeAuditEvent(unsigned);
      const computedHash = await computeSHA256(canonical);

      if (computedHash !== current.eventHash) {
        return {
          isValid: false,
          checkedCount: i,
          error: `Hash adulterado en evento ${current.eventId}. Hash almacenado ≠ Hash calculado.`,
        };
      }

      expectedPrevHash = current.eventHash;
    }

    return { isValid: true, checkedCount: this.events.length };
  }

  public tamperEventForTesting(index: number, newResult: 'SUCCESS' | 'DENIED'): void {
    if (this.events[index]) {
      this.events[index].result = newResult;
    }
  }
}

/**
 * [PRODUCTION SINK STUB]
 * RemoteAuditSink is NOT an immutable ledger in this build.
 * It currently mirrors LocalAuditSink and must not be advertised as one.
 */
export class RemoteAuditSink implements AuditSink {
  public sinkName = 'RemoteAuditSink (PRODUCTION STUB — not an immutable ledger)';
  public isAuthoritative = false;
  public integrityClaim = 'stub: not an immutable ledger';

  private localMirror: LocalAuditSink = new LocalAuditSink();

  public async recordEvent(
    eventParams: Omit<AuditEvent, 'eventId' | 'timestamp' | 'eventHash' | 'previousEventHash'>
  ): Promise<AuditEvent> {
    return await this.localMirror.recordEvent(eventParams);
  }

  public async getEvents(): Promise<AuditEvent[]> {
    return await this.localMirror.getEvents();
  }

  public async verifyIntegrity(): Promise<{ isValid: boolean; checkedCount: number; error?: string }> {
    return await this.localMirror.verifyIntegrity();
  }
}

export const globalAuditSink = new LocalAuditSink();
