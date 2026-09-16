/**
 * The Data Cryptographic Protocol (TDCP)
 * Deterministic Policy Engine
 *
 * Rules:
 * - Purely deterministic evaluation: policy + authorization + device + credential + state
 * - AI anomaly score can recommend block or higher verification, but can NEVER bypass cryptographic requirements.
 */

import type {
  AuthorizationRequest,
  DocumentRevocationState,
  PolicyLevel,
} from '../authorization/types.ts';

export interface PolicyEvaluationInput {
  request: AuthorizationRequest;
  revocationState: DocumentRevocationState;
  policyLevel: PolicyLevel;
  allowExtractionConfigured: boolean;
  expirationDaysConfigured?: number;
  packageCreatedAt: number;
  oracleCurrentTime: number;
  viewOnceConfigured?: boolean;
}

export interface PolicyDecision {
  allowed: boolean;
  rejectionCode?:
    | 'DOCUMENT_REVOKED'
    | 'DOCUMENT_EXPIRED'
    | 'VIEW_ONCE_ALREADY_CONSUMED'
    | 'OPERATION_FORBIDDEN'
    | 'ANOMALY_HIGH_RISK_BLOCK'
    | 'CREDENTIAL_UNAUTHORIZED'
    | 'BIOMETRIC_REQUIRED' | 'INVALID_CHALLENGE';
  rejectionReason?: string;
  allowExtraction: boolean;
  forensicWatermarkRequired: boolean;
  validityWindowSeconds: number;
}

export class DeterministicPolicyEngine {
  public evaluate(input: PolicyEvaluationInput): PolicyDecision {
    const {
      request,
      revocationState,
      policyLevel,
      allowExtractionConfigured,
      expirationDaysConfigured,
      packageCreatedAt,
      oracleCurrentTime,
      viewOnceConfigured,
    } = input;

    if (revocationState.isRevoked) {
      return {
        allowed: false,
        rejectionCode: 'DOCUMENT_REVOKED',
        rejectionReason: `Documento ${request.documentId} revocado activamente por la autoridad de control.`,
        allowExtraction: false,
        forensicWatermarkRequired: true,
        validityWindowSeconds: 0,
      };
    }

    if (viewOnceConfigured && revocationState.viewOnceConsumed) {
      return {
        allowed: false,
        rejectionCode: 'VIEW_ONCE_ALREADY_CONSUMED',
        rejectionReason: `El documento ${request.documentId} fue configurado con política 'Vista Única' y ya ha sido consumido.`,
        allowExtraction: false,
        forensicWatermarkRequired: true,
        validityWindowSeconds: 0,
      };
    }

    if (expirationDaysConfigured && expirationDaysConfigured > 0) {
      const msElapsed = oracleCurrentTime - packageCreatedAt;
      const daysElapsed = msElapsed / (1000 * 60 * 60 * 24);
      if (daysElapsed > expirationDaysConfigured) {
        return {
          allowed: false,
          rejectionCode: 'DOCUMENT_EXPIRED',
          rejectionReason: `El período de vigencia de ${expirationDaysConfigured} días ha expirado según el reloj de la autoridad.`,
          allowExtraction: false,
          forensicWatermarkRequired: true,
          validityWindowSeconds: 0,
        };
      }
    }

    if (request.requestedOperation === 'EXTRACT' && !allowExtractionConfigured) {
      return {
        allowed: false,
        rejectionCode: 'OPERATION_FORBIDDEN',
        rejectionReason:
          'La política del documento prohíbe la extracción física fuera del sandbox de memoria.',
        allowExtraction: false,
        forensicWatermarkRequired: true,
        validityWindowSeconds: 0,
      };
    }

    if (
      (policyLevel === 'CRITICAL' || policyLevel === 'ULTRA_CRITICAL') &&
      !request.policyContext?.biometricVerified
    ) {
      return {
        allowed: false,
        rejectionCode: 'BIOMETRIC_REQUIRED',
        rejectionReason:
          'La política CRITICAL / ULTRA_CRITICAL exige verificación biométrica de presencia antes de emitir un grant.',
        allowExtraction: false,
        forensicWatermarkRequired: true,
        validityWindowSeconds: 0,
      };
    }

    if (request.policyContext?.anomalyScore && request.policyContext.anomalyScore >= 0.9) {
      return {
        allowed: false,
        rejectionCode: 'ANOMALY_HIGH_RISK_BLOCK',
        rejectionReason: `Bloqueo de seguridad: Puntuación de anomalía crítica detectada (${request.policyContext.anomalyScore.toFixed(2)}).`,
        allowExtraction: false,
        forensicWatermarkRequired: true,
        validityWindowSeconds: 0,
      };
    }

    let validityWindowSeconds = 120;
    let forensicWatermarkRequired = true;

    switch (policyLevel) {
      case 'ULTRA_CRITICAL':
        validityWindowSeconds = 45;
        forensicWatermarkRequired = true;
        break;
      case 'CRITICAL':
        validityWindowSeconds = 60;
        forensicWatermarkRequired = true;
        break;
      case 'STANDARD':
        validityWindowSeconds = 180;
        forensicWatermarkRequired = false;
        break;
      case 'NORMAL':
        validityWindowSeconds = 300;
        forensicWatermarkRequired = false;
        break;
    }

    return {
      allowed: true,
      allowExtraction: allowExtractionConfigured && request.requestedOperation === 'EXTRACT',
      forensicWatermarkRequired,
      validityWindowSeconds,
    };
  }
}
