/**
 * The Data Cryptographic Protocol (TDCP)
 * Authorization & Control Plane Types
 * 
 * Fundamental principle:
 * "The document can be copied. The authorization to use it cannot."
 * The central oracle issues one-time signed grants without ever storing
 * the document, plaintext, or content decryption keys.
 */

export type TDCPRequestedOperation = 'READ' | 'RENDER_RAM' | 'EXTRACT' | 'AUDIT_EXPORT';

export type PolicyLevel = 'NORMAL' | 'STANDARD' | 'CRITICAL' | 'ULTRA_CRITICAL';

export interface DeviceIdentity {
  deviceId: string;
  hardwareBacked: boolean;
  platform: string;
  fingerprintDigest: string;
  attestationType: 'MOCK_DEVELOPMENT' | 'TPM_SIMULATION' | 'WEBAUTHN_AUTHENTICATOR';
}

export interface UserCredential {
  credentialId: string;
  holderName: string;
  credentialType: 'NFC_CARD' | 'SMART_CARD' | 'MOCK_TOKEN' | 'FIDO2_AUTHENTICATOR';
  assignedRole: 'OPERATOR' | 'SECURITY_OFFICER' | 'ANALYST' | 'AUDITOR';
  publicKey?: string;
  isSimulated: boolean;
}

export interface AuthorizationRequest {
  requestId: string;
  documentId: string;
  packageId: string;
  deviceId: string;
  credentialId: string;
  operationId: string;
  challenge: string; // Cryptographic random nonce from Gatekeeper
  requestedOperation: TDCPRequestedOperation;
  timestamp: number; // Client requested time (untrusted)
  policyContext?: {
    location?: string;
    biometricVerified?: boolean;
    anomalyScore?: number;
  };
}

export interface AuthorizationGrant {
  grantId: string;
  documentId: string;
  packageId: string;
  deviceId: string;
  credentialId: string;
  operationId: string;
  challenge: string;
  operation: TDCPRequestedOperation;
  policyLevel: PolicyLevel;
  authorizationEpoch: number; // Oracle's active epoch for this document
  issuedAt: number; // Signed epoch timestamp from Oracle authority
  expiresAt: number; // Signed epoch timestamp from Oracle authority
  oneTimeUse: boolean;
  allowExtraction: boolean;
  forensicWatermarkRequired: boolean;
  oracleKeyId: string;
  signature: string; // Base64 ECDSA P-256 signature
}

export interface DocumentRevocationState {
  documentId: string;
  isRevoked: boolean;
  currentEpoch: number;
  revokedAt?: number;
  revocationReason?: string;
  revokedBy?: string;
  allowedOperations: TDCPRequestedOperation[];
  viewOnceConsumed: boolean;
}

/**
 * Canonical payload serializer for signing and verifying AuthorizationGrants.
 * Guarantees zero ambiguity in ECDSA verification.
 */
export function canonicalizeGrant(grant: Omit<AuthorizationGrant, 'signature'>): string {
  return [
    'TDCP_AUTH_GRANT_v2.5',
    `GRANT_ID:${grant.grantId}`,
    `DOC:${grant.documentId}`,
    `PKG:${grant.packageId}`,
    `DEV:${grant.deviceId}`,
    `CRED:${grant.credentialId}`,
    `OP_ID:${grant.operationId}`,
    `CHALLENGE:${grant.challenge}`,
    `OP:${grant.operation}`,
    `POLICY:${grant.policyLevel}`,
    `EPOCH:${grant.authorizationEpoch}`,
    `IAT:${grant.issuedAt}`,
    `EXP:${grant.expiresAt}`,
    `ONE_TIME:${grant.oneTimeUse ? '1' : '0'}`,
    `EXTRACT:${grant.allowExtraction ? '1' : '0'}`,
    `WATERMARK:${grant.forensicWatermarkRequired ? '1' : '0'}`,
    `ORACLE:${grant.oracleKeyId}`
  ].join('\n');
}
