/**
 * In-process Authority adapter — wraps AuthorizationOracle for demo parity.
 * Not a production security boundary (same-process as the client).
 */

import type {
  AuthorizationGrant,
  AuthorizationRequest,
  DocumentRevocationState,
} from '../core/authorization/types.ts';
import {
  AuthorizationOracle,
  globalAuthorizationOracle,
  type RegisteredDocumentPolicy,
} from '../oracle/authorization-oracle.ts';
import type { AuthorityAuthResult, AuthorizationAuthority } from './types.ts';

export class InProcessAuthority implements AuthorizationAuthority {
  public readonly kind = 'IN_PROCESS' as const;
  private readonly oracle: AuthorizationOracle;

  constructor(oracle?: AuthorizationOracle) {
    this.oracle = oracle ?? globalAuthorizationOracle;
  }

  /** Escape hatch for tests / factory that still expect AuthorizationOracle. */
  public getOracle(): AuthorizationOracle {
    return this.oracle;
  }

  public async initialize(): Promise<void> {
    await this.oracle.initialize();
  }

  public async getPublicKey(): Promise<CryptoKey> {
    return this.oracle.getPublicKey();
  }

  public getKeyId(): string {
    return this.oracle.getKeyId();
  }

  public getKeyStoreKind(): string {
    return this.oracle.getKeyStoreKind();
  }

  public isDevelopmentKeyStore(): boolean {
    return this.oracle.isDevelopmentKeyStore();
  }

  public async issueChallenge(): Promise<string> {
    return this.oracle.issueChallenge();
  }

  public async isValidChallenge(challenge: string): Promise<boolean> {
    return this.oracle.getReplayRegistry().isValidChallenge(challenge);
  }

  public async registerDocumentPolicy(policy: RegisteredDocumentPolicy): Promise<Uint8Array> {
    return this.oracle.registerDocumentPolicy(policy);
  }

  public async getDocumentPolicy(
    documentId: string
  ): Promise<RegisteredDocumentPolicy | undefined> {
    return this.oracle.getDocumentPolicy(documentId);
  }

  public async listRegisteredPolicies(): Promise<RegisteredDocumentPolicy[]> {
    return this.oracle.listRegisteredPolicies();
  }

  public async processAuthorizationRequest(
    request: AuthorizationRequest
  ): Promise<AuthorityAuthResult> {
    return this.oracle.processAuthorizationRequest(request);
  }

  public async releaseDocumentWrapSecretForGrant(
    grant: AuthorizationGrant
  ): Promise<Uint8Array | null> {
    return this.oracle.releaseDocumentWrapSecretForGrant(grant);
  }

  public async commitViewOnce(documentId: string, grantId: string): Promise<boolean> {
    return this.oracle.commitViewOnce(documentId, grantId);
  }

  public async revokeDocument(
    documentId: string,
    reason?: string,
    revokedBy?: string
  ): Promise<DocumentRevocationState> {
    return this.oracle.getRevocationManager().revokeDocument(documentId, reason, revokedBy);
  }

  public async restoreDocument(documentId: string): Promise<DocumentRevocationState> {
    return this.oracle.getRevocationManager().restoreDocument(documentId);
  }

  public async getDocumentRevocationState(documentId: string): Promise<DocumentRevocationState> {
    return this.oracle.getRevocationManager().getOrCreateState(documentId);
  }

  public async listRevoked(): Promise<DocumentRevocationState[]> {
    return this.oracle.getRevocationManager().listRevoked();
  }
}
