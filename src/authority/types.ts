/**
 * TDCP Authorization Authority — remote control-plane boundary.
 *
 * The browser Oracle remains reference/demo. Production clients should target
 * a remote Authority that owns durable revoke/replay and signing keys.
 * See docs/AUTHORITY.md.
 */

import type {
  AuthorizationGrant,
  AuthorizationRequest,
  DocumentRevocationState,
} from '../core/authorization/types.ts';
import type { RegisteredDocumentPolicy } from '../oracle/authorization-oracle.ts';

export type AuthorityKind = 'IN_PROCESS' | 'HTTP_REMOTE';

export interface AuthorityAuthResult {
  granted: boolean;
  grant?: AuthorizationGrant;
  rejectionReason?: string;
  rejectionCode?: string;
}

/**
 * Minimum surface Gatekeeper / factory need from a control plane.
 * Additive: does not replace AuthorizationOracle; InProcessAuthority adapts it.
 */
export interface AuthorizationAuthority {
  readonly kind: AuthorityKind;

  initialize(): Promise<void>;
  getPublicKey(): Promise<CryptoKey>;
  /** SPKI base64 for remote clients that cannot hold CryptoKey across the wire. */
  getPublicKeySpkiBase64?(): Promise<string>;
  getKeyId(): string;
  getKeyStoreKind(): string;
  isDevelopmentKeyStore(): boolean;

  issueChallenge(): Promise<string>;
  isValidChallenge(challenge: string): Promise<boolean>;

  registerDocumentPolicy(policy: RegisteredDocumentPolicy): Promise<Uint8Array>;
  getDocumentPolicy(documentId: string): Promise<RegisteredDocumentPolicy | undefined>;
  listRegisteredPolicies(): Promise<RegisteredDocumentPolicy[]>;

  processAuthorizationRequest(request: AuthorizationRequest): Promise<AuthorityAuthResult>;
  releaseDocumentWrapSecretForGrant(grant: AuthorizationGrant): Promise<Uint8Array | null>;
  commitViewOnce(documentId: string, grantId: string): Promise<boolean>;

  revokeDocument(
    documentId: string,
    reason?: string,
    revokedBy?: string
  ): Promise<DocumentRevocationState>;
  restoreDocument(documentId: string): Promise<DocumentRevocationState>;
  getDocumentRevocationState(documentId: string): Promise<DocumentRevocationState>;
  listRevoked(): Promise<DocumentRevocationState[]>;
}

export interface AuthorityPublicInfo {
  keyId: string;
  keyStoreKind: string;
  developmentOnly: boolean;
  publicKeySpkiBase64: string;
}
