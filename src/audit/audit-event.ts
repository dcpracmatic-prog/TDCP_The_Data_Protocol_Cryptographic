/**
 * The Data Cryptographic Protocol (TDCP)
 * Authoritative Audit Event & Tamper-Evident Hash Chain
 */

import { computeSHA256 } from '../core/crypto/primitives.ts';

export interface AuditEvent {
  eventId: string;
  timestamp: number;
  documentId: string;
  packageId: string;
  deviceId: string;
  credentialId: string;
  operationId: string;
  authorizationId?: string;
  operation: string;
  policy: string;
  result: 'SUCCESS' | 'DENIED' | 'TAMPER_DETECTED' | 'REPLAY_REJECTED';
  details: string;
  previousEventHash: string;
  eventHash: string;
}

export function canonicalizeAuditEvent(event: Omit<AuditEvent, 'eventHash'>): string {
  return [
    'TDCP_AUDIT_v2.5',
    `ID:${event.eventId}`,
    `TS:${event.timestamp}`,
    `DOC:${event.documentId}`,
    `DEV:${event.deviceId}`,
    `CRED:${event.credentialId}`,
    `OP_ID:${event.operationId}`,
    `AUTH_ID:${event.authorizationId || 'NONE'}`,
    `OP:${event.operation}`,
    `POL:${event.policy}`,
    `RES:${event.result}`,
    `PREV:${event.previousEventHash}`
  ].join('|');
}

export async function createChainedAuditEvent(
  params: Omit<AuditEvent, 'eventHash' | 'previousEventHash'>,
  previousHash: string
): Promise<AuditEvent> {
  const partial = {
    ...params,
    previousEventHash: previousHash
  };
  const canonical = canonicalizeAuditEvent(partial);
  const eventHash = await computeSHA256(canonical);

  return {
    ...partial,
    eventHash
  };
}
