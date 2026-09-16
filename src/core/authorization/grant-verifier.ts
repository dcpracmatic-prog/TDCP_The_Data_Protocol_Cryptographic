/**
 * The Data Cryptographic Protocol (TDCP)
 * Authorization Grant Verifier
 * 
 * Verifies all cryptographic bindings and signatures before allowing
 * the Gatekeeper to derive ephemeral keys.
 */

import { canonicalizeGrant } from './types.ts';
import type { AuthorizationGrant, TDCPRequestedOperation } from './types.ts';
import { verifySignatureECDSA } from '../crypto/primitives.ts';

export interface VerificationContext {
  targetDocumentId: string;
  targetDeviceId: string;
  targetCredentialId: string;
  targetOperationId: string;
  expectedChallenge: string;
  requestedOperation: TDCPRequestedOperation;
  expectedEpoch: number;
}

export interface GrantVerificationResult {
  isValid: boolean;
  errorCode?: string;
  errorMessage?: string;
}

export async function verifyAuthorizationGrant(
  grant: AuthorizationGrant,
  oraclePublicKey: CryptoKey,
  context: VerificationContext
): Promise<GrantVerificationResult> {
  // 1. Verify ECDSA P-256 Signature
  const { signature, ...unsignedPayload } = grant;
  const canonicalString = canonicalizeGrant(unsignedPayload);
  const signatureValid = await verifySignatureECDSA(oraclePublicKey, signature, canonicalString);

  if (!signatureValid) {
    return {
      isValid: false,
      errorCode: 'INVALID_ORACLE_SIGNATURE',
      errorMessage: 'Firma criptográfica del Oracle no válida o grant manipulado.'
    };
  }

  // 2. Document Binding Check
  if (grant.documentId !== context.targetDocumentId) {
    return {
      isValid: false,
      errorCode: 'DOCUMENT_MISMATCH',
      errorMessage: `El grant fue emitido para el documento ${grant.documentId}, no para ${context.targetDocumentId}.`
    };
  }

  // 3. Device Binding Check
  if (grant.deviceId !== context.targetDeviceId) {
    return {
      isValid: false,
      errorCode: 'DEVICE_MISMATCH',
      errorMessage: `El grant fue emitido para el dispositivo ${grant.deviceId}, no para ${context.targetDeviceId}.`
    };
  }

  // 4. Credential Binding Check
  if (grant.credentialId !== context.targetCredentialId) {
    return {
      isValid: false,
      errorCode: 'CREDENTIAL_MISMATCH',
      errorMessage: `El grant fue emitido para la credencial ${grant.credentialId}, no para ${context.targetCredentialId}.`
    };
  }

  // 5. Operation Binding Check
  if (grant.operation !== context.requestedOperation) {
    return {
      isValid: false,
      errorCode: 'OPERATION_MISMATCH',
      errorMessage: `El grant autoriza '${grant.operation}', pero se solicitó '${context.requestedOperation}'.`
    };
  }

  // 6. Operation ID & Challenge Binding
  if (grant.operationId !== context.targetOperationId || grant.challenge !== context.expectedChallenge) {
    return {
      isValid: false,
      errorCode: 'CHALLENGE_MISMATCH',
      errorMessage: 'El challenge u operation_id del grant no coincide con la sesión actual.'
    };
  }

  // 7. Epoch Binding Check
  if (grant.authorizationEpoch !== context.expectedEpoch) {
    return {
      isValid: false,
      errorCode: 'EPOCH_OBSOLETE',
      errorMessage: `El grant pertenece al epoch ${grant.authorizationEpoch}, pero el epoch activo es ${context.expectedEpoch}.`
    };
  }

  // 8. Expiration Check
  const now = Date.now();
  if (now > grant.expiresAt) {
    return {
      isValid: false,
      errorCode: 'GRANT_EXPIRED',
      errorMessage: `La autorización ha expirado (Vigencia terminada a las ${new Date(grant.expiresAt).toLocaleTimeString()}).`
    };
  }

  return { isValid: true };
}
