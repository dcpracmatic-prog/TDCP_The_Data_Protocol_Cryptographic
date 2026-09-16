/**
 * The Data Cryptographic Protocol (TDCP)
 * Document Epoch & Revocation Manager
 *
 * Enforces:
 * - Centralized revocation via Authorization Oracle
 * - Epoch rotation (invalidates all past grants issued under prior epochs)
 * - View-Once consumed tracking
 *
 * localStorage is NOT an authority. This in-memory map is.
 */

import type { DocumentRevocationState } from '../authorization/types.ts';

export class EpochRevocationManager {
  private documentStates: Map<string, DocumentRevocationState> = new Map();

  public getOrCreateState(documentId: string): DocumentRevocationState {
    let state = this.documentStates.get(documentId);
    if (!state) {
      state = {
        documentId,
        isRevoked: false,
        currentEpoch: 1,
        allowedOperations: ['READ', 'RENDER_RAM', 'EXTRACT', 'AUDIT_EXPORT'],
        viewOnceConsumed: false,
      };
      this.documentStates.set(documentId, state);
    }
    return { ...state };
  }

  public listStates(): DocumentRevocationState[] {
    return Array.from(this.documentStates.values()).map((s) => ({ ...s }));
  }

  public listRevoked(): DocumentRevocationState[] {
    return this.listStates().filter((s) => s.isRevoked);
  }

  public revokeDocument(
    documentId: string,
    reason: string = 'Revocación por Oficial de Seguridad',
    revokedBy: string = 'SECURITY_OFFICER'
  ): DocumentRevocationState {
    const state = this.getOrCreateState(documentId);
    state.isRevoked = true;
    state.currentEpoch += 1;
    state.revokedAt = Date.now();
    state.revocationReason = reason;
    state.revokedBy = revokedBy;
    this.documentStates.set(documentId, state);
    return { ...state };
  }

  public restoreDocument(documentId: string): DocumentRevocationState {
    const state = this.getOrCreateState(documentId);
    state.isRevoked = false;
    state.currentEpoch += 1;
    state.revocationReason = undefined;
    state.revokedBy = undefined;
    this.documentStates.set(documentId, state);
    return { ...state };
  }

  /**
   * Marks view-once consumed. Does NOT rotate epoch so the grant that just
   * authorized this opening still verifies. Subsequent requests are denied
   * by the viewOnceConsumed flag, not by epoch mismatch.
   */
  public markViewOnceConsumed(documentId: string): void {
    const state = this.getOrCreateState(documentId);
    state.viewOnceConsumed = true;
    this.documentStates.set(documentId, state);
  }

  public clear(): void {
    this.documentStates.clear();
  }
}
