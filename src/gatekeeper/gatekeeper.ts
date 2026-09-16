/**
 * The Data Cryptographic Protocol (TDCP)
 * DCP Gatekeeper
 *
 * THE ONLY authorized decrypt path in the application.
 * UI components must not call AES-GCM, PBKDF2, or derive keys themselves.
 */

import {
  createAADBytes,
  deriveKeyWrappingKey,
  computePackageIntegrityHash,
  TDCP_ENVELOPE_WRAP_EPOCH,
} from '../core/package/package-format.ts';
import type { TDCPPackage } from '../core/package/package-format.ts';
import type { AuthorizationRequest, TDCPRequestedOperation } from '../core/authorization/types.ts';
import { verifyAuthorizationGrant } from '../core/authorization/grant-verifier.ts';
import {
  deriveRootKeyFromSecret,
  TDCP_DEFAULT_PBKDF2_ITERATIONS,
  decryptAESGCM,
  base64ToArrayBuffer,
  generateRandomId,
  wipeBuffer,
} from '../core/crypto/primitives.ts';
import { AuthorizationOracle, globalAuthorizationOracle } from '../oracle/authorization-oracle.ts';
import { ControlledRuntimeSession } from '../protection/apoptosis.ts';
import { generateForensicWatermark } from '../protection/watermark.ts';
import type { ForensicWatermarkData } from '../protection/watermark.ts';
import type { AuditSink } from '../audit/audit-sink.ts';
import { globalAuditSink } from '../audit/audit-sink.ts';
import type { NFCProvider } from '../identity/credential-provider.ts';
import type { DeviceIdentityProvider } from '../identity/device-identity-provider.ts';
import type { BiometricProvider } from '../identity/biometric-provider.ts';
import { verifyABCInterlockingIntegrity } from '../core/package/ultra-critical.ts';

export interface GatekeeperUnlockOptions {
  packageData: TDCPPackage;
  userPassword: string;
  requestedOperation: TDCPRequestedOperation;
  nfcProvider: NFCProvider;
  deviceProvider: DeviceIdentityProvider;
  biometricProvider?: BiometricProvider;
  oracle?: AuthorizationOracle;
  auditSink?: AuditSink;
  customChallenge?: string;
}

export interface GatekeeperUnlockResult {
  success: boolean;
  plaintextBuffer?: ArrayBuffer;
  session?: ControlledRuntimeSession;
  watermark?: ForensicWatermarkData;
  grant?: import('../core/authorization/types.ts').AuthorizationGrant;
  errorMessage?: string;
  errorCode?: string;
  auditEventId?: string;
}

function concatBuffers(a: ArrayBuffer, b: ArrayBuffer): ArrayBuffer {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(new Uint8Array(a), 0);
  out.set(new Uint8Array(b), a.byteLength);
  return out.buffer;
}

export class DCPGatekeeper {
  public static async executeUnlock(options: GatekeeperUnlockOptions): Promise<GatekeeperUnlockResult> {
    const {
      packageData,
      userPassword,
      requestedOperation,
      nfcProvider,
      deviceProvider,
      biometricProvider,
      oracle = globalAuthorizationOracle,
      auditSink = globalAuditSink,
      customChallenge,
    } = options;

    // Reject malformed/tampered envelopes before any authorization work.
    const computedIntegrity = await computePackageIntegrityHash(packageData);
    if (computedIntegrity !== packageData.integrityHash) {
      return {
        success: false,
        errorCode: 'PACKAGE_INTEGRITY_FAILED',
        errorMessage: 'Integridad del sobre TDCP inválida. El paquete fue alterado o está corrupto.',
      };
    }

    const operationId = generateRandomId('OP');
    // Test harnesses may inject a challenge, but the challenge must already be
    // registered. Production flow always obtains a fresh challenge from Oracle.
    const challenge = customChallenge || oracle.issueChallenge();

    let credential;
    try {
      credential = await nfcProvider.readCredential();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        errorCode: 'CREDENTIAL_READ_FAILURE',
        errorMessage: `Fallo al leer credencial NFC: ${message}`,
      };
    }

    let device;
    try {
      device = await deviceProvider.getDeviceIdentity();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        errorCode: 'DEVICE_IDENTITY_FAILURE',
        errorMessage: `Fallo al autenticar identidad del dispositivo: ${message}`,
      };
    }

    const registeredPolicy = oracle.getDocumentPolicy(packageData.documentId);
    if (!registeredPolicy || registeredPolicy.packageId !== packageData.packageId) {
      return {
        success: false,
        errorCode: 'DOCUMENT_NOT_REGISTERED',
        errorMessage: 'El paquete no coincide con una política registrada en el Oracle.',
      };
    }

    const policyLevel = packageData.metadata?.policyLevel || 'STANDARD';
    if (
      registeredPolicy.policyLevel !== policyLevel ||
      registeredPolicy.allowExtraction !== Boolean(packageData.metadata.allowExtraction) ||
      Boolean(registeredPolicy.viewOnce) !== Boolean(packageData.metadata.viewOnce) ||
      (registeredPolicy.expirationDays ?? undefined) !== (packageData.metadata.expirationDays ?? undefined)
    ) {
      return {
        success: false,
        errorCode: 'PACKAGE_POLICY_MISMATCH',
        errorMessage: 'La política del paquete no coincide con la política autoritativa del Oracle.',
      };
    }

    const expectedAAD = createAADBytes(
      packageData.documentId,
      packageData.packageId,
      packageData.version,
      {
        policyLevel,
        allowExtraction: Boolean(packageData.metadata.allowExtraction),
        expirationDays: packageData.metadata.expirationDays,
        viewOnce: packageData.metadata.viewOnce,
        kdfIterations: packageData.metadata.kdfIterations ?? TDCP_DEFAULT_PBKDF2_ITERATIONS,
      }
    );
    const actualAAD = new Uint8Array(base64ToArrayBuffer(packageData.aadBase64));
    if (new TextDecoder().decode(actualAAD) !== new TextDecoder().decode(expectedAAD)) {
      return {
        success: false,
        errorCode: 'AAD_CONTEXT_MISMATCH',
        errorMessage: 'El AAD del paquete no coincide con su contexto de seguridad.',
      };
    }

    let biometricVerified = false;
    if (policyLevel === 'CRITICAL' || policyLevel === 'ULTRA_CRITICAL') {
      if (!biometricProvider) {
        return {
          success: false,
          errorCode: 'BIOMETRIC_REQUIRED',
          errorMessage:
            'La política CRITICAL / ULTRA_CRITICAL exige un BiometricProvider. No se acepta un bypass.',
        };
      }
      try {
        const bio = await biometricProvider.verifyPresence(
          `TDCP ${policyLevel} presence check for ${packageData.documentId}`
        );
        biometricVerified = bio.verified === true;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          success: false,
          errorCode: 'BIOMETRIC_REQUIRED',
          errorMessage: `Verificación biométrica fallida: ${message}`,
        };
      }
      if (!biometricVerified) {
        await auditSink.recordEvent({
          documentId: packageData.documentId,
          packageId: packageData.packageId,
          deviceId: device.deviceId,
          credentialId: credential.credentialId,
          operationId,
          operation: requestedOperation,
          policy: policyLevel,
          result: 'DENIED',
          details: 'Presencia biométrica no verificada. No se emitió grant.',
        });
        return {
          success: false,
          errorCode: 'BIOMETRIC_REQUIRED',
          errorMessage: 'Presencia biométrica no verificada. Autorización denegada.',
        };
      }
    }

    if (customChallenge && !oracle.getReplayRegistry().isValidChallenge(challenge)) {
      return {
        success: false,
        errorCode: 'INVALID_CHALLENGE',
        errorMessage: 'El challenge inyectado no fue emitido/registrado por el Oracle. Solo se acepta para pruebas si fue pre-registrado.',
      };
    }

    const authRequest: AuthorizationRequest = {
      requestId: generateRandomId('REQ'),
      documentId: packageData.documentId,
      packageId: packageData.packageId,
      deviceId: device.deviceId,
      credentialId: credential.credentialId,
      operationId,
      challenge,
      requestedOperation,
      timestamp: Date.now(),
      policyContext: {
        biometricVerified,
      },
    };

    const authResponse = await oracle.processAuthorizationRequest(authRequest);

    if (!authResponse.granted || !authResponse.grant) {
      await auditSink.recordEvent({
        documentId: packageData.documentId,
        packageId: packageData.packageId,
        deviceId: device.deviceId,
        credentialId: credential.credentialId,
        operationId,
        operation: requestedOperation,
        policy: policyLevel,
        result: 'DENIED',
        details: `Autorización denegada por Oracle: ${authResponse.rejectionReason}`,
      });

      return {
        success: false,
        errorCode: authResponse.rejectionCode || 'AUTHORIZATION_DENIED',
        errorMessage: `Autorización denegada por el Oracle: ${authResponse.rejectionReason}`,
      };
    }

    const grant = authResponse.grant;
    const currentEpoch = oracle.getRevocationManager().getOrCreateState(packageData.documentId)
      .currentEpoch;

    const oraclePublicKey = await oracle.getPublicKey();
    const verification = await verifyAuthorizationGrant(grant, oraclePublicKey, {
      targetDocumentId: packageData.documentId,
      targetDeviceId: device.deviceId,
      targetCredentialId: credential.credentialId,
      targetOperationId: operationId,
      expectedChallenge: challenge,
      requestedOperation,
      expectedEpoch: currentEpoch,
    });

    if (!verification.isValid) {
      await auditSink.recordEvent({
        documentId: packageData.documentId,
        packageId: packageData.packageId,
        deviceId: device.deviceId,
        credentialId: credential.credentialId,
        operationId,
        authorizationId: grant.grantId,
        operation: requestedOperation,
        policy: grant.policyLevel,
        result: 'TAMPER_DETECTED',
        details: `Fallo en verificación de Grant: ${verification.errorMessage}`,
      });

      return {
        success: false,
        errorCode: verification.errorCode || 'GRANT_VERIFICATION_FAILED',
        errorMessage: verification.errorMessage,
      };
    }

    const wrapSecret = await oracle.releaseDocumentWrapSecretForGrant(grant);
    if (!wrapSecret) {
      await auditSink.recordEvent({
        documentId: packageData.documentId,
        packageId: packageData.packageId,
        deviceId: device.deviceId,
        credentialId: credential.credentialId,
        operationId,
        authorizationId: grant.grantId,
        operation: requestedOperation,
        policy: grant.policyLevel,
        result: 'REPLAY_REJECTED',
        details: 'El grant no pudo consumirse de forma única: expirado, revocado, inválido o ya utilizado.',
      });
      return {
        success: false,
        errorCode: 'REPLAY_ATTACK_REJECTED',
        errorMessage: 'Grant inválido, expirado, revocado o ya consumido.',
      };
    }



    let contentDecryptionKey: CryptoKey;
    const salt = new Uint8Array(base64ToArrayBuffer(packageData.saltBase64));

    try {
      const rootKeyMaterial = await deriveRootKeyFromSecret(
        userPassword,
        salt,
        packageData.metadata.kdfIterations ?? TDCP_DEFAULT_PBKDF2_ITERATIONS
      );
      const envelopeEpoch = packageData.envelopeEpoch ?? TDCP_ENVELOPE_WRAP_EPOCH;
      const kwk = await deriveKeyWrappingKey(
        rootKeyMaterial,
        salt,
        grant.documentId,
        envelopeEpoch,
        wrapSecret
      );

      if (!packageData.wrappedKeyBase64 || !packageData.ivKeyBase64) {
        wipeBuffer(wrapSecret);
        return {
          success: false,
          errorCode: 'KEY_DERIVATION_FAILURE',
          errorMessage: 'El paquete no contiene una CEK envuelta. Formato no autorizado.',
        };
      }

      const ivKey = new Uint8Array(base64ToArrayBuffer(packageData.ivKeyBase64));
      const wrappedCekBytes = base64ToArrayBuffer(packageData.wrappedKeyBase64);
      const rawCek = await decryptAESGCM(kwk, wrappedCekBytes, ivKey);
      contentDecryptionKey = await crypto.subtle.importKey(
        'raw',
        rawCek,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );
      wipeBuffer(rawCek);
      wipeBuffer(wrapSecret);
    } catch (err: unknown) {
      wipeBuffer(wrapSecret);
      return {
        success: false,
        errorCode: 'KEY_DERIVATION_FAILURE',
        errorMessage: `Error al desenvolver CEK: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    let decryptedBuffer: ArrayBuffer;
    try {
      if (policyLevel === 'ULTRA_CRITICAL') {
        const bundle = packageData.ultraCritical;
        if (!bundle?.fragmentA || !bundle?.fragmentB || !bundle?.manifestC) {
          return {
            success: false,
            errorCode: 'ULTRA_CRITICAL_INCOMPLETE',
            errorMessage: 'ULTRA_CRITICAL DENY: faltan fragmentos A, B o manifiesto C.',
          };
        }
        const interlocking = await verifyABCInterlockingIntegrity(
          bundle.fragmentA,
          bundle.fragmentB,
          bundle.manifestC
        );
        if (!interlocking.isValid) {
          return {
            success: false,
            errorCode: 'ULTRA_CRITICAL_INTERLOCK_FAILED',
            errorMessage: interlocking.reason || 'Interlocking A/B/C inválido.',
          };
        }
        const ivA = new Uint8Array(base64ToArrayBuffer(bundle.fragmentA.ivBase64));
        const ivB = new Uint8Array(base64ToArrayBuffer(bundle.fragmentB.ivBase64));
        const cipherA = base64ToArrayBuffer(bundle.fragmentA.ciphertextBase64);
        const cipherB = base64ToArrayBuffer(bundle.fragmentB.ciphertextBase64);
        const plainA = await decryptAESGCM(contentDecryptionKey, cipherA, ivA, expectedAAD);
        const plainB = await decryptAESGCM(contentDecryptionKey, cipherB, ivB, expectedAAD);
        decryptedBuffer = concatBuffers(plainA, plainB);
      } else {
        const iv = new Uint8Array(base64ToArrayBuffer(packageData.ivBase64));
        const ciphertext = base64ToArrayBuffer(packageData.ciphertextBase64);
        decryptedBuffer = await decryptAESGCM(contentDecryptionKey, ciphertext, iv, expectedAAD);
      }
    } catch {
      await auditSink.recordEvent({
        documentId: packageData.documentId,
        packageId: packageData.packageId,
        deviceId: device.deviceId,
        credentialId: credential.credentialId,
        operationId,
        authorizationId: grant.grantId,
        operation: requestedOperation,
        policy: grant.policyLevel,
        result: 'DENIED',
        details: 'Fallo de descifrado AES-GCM: Tag de autenticación inválido o clave incorrecta.',
      });

      return {
        success: false,
        errorCode: 'DECRYPTION_AUTH_TAG_FAILED',
        errorMessage:
          'Fallo de autenticación AES-GCM: Clave incorrecta, paquete corrupto o manipulado.',
      };
    }

    if (registeredPolicy.viewOnce) {
      oracle.commitViewOnce(packageData.documentId, grant.grantId);
    }

    const session = new ControlledRuntimeSession(generateRandomId('SESSION'), 300000);
    session.registerBuffer(decryptedBuffer);

    let watermark: ForensicWatermarkData | undefined;
    if (grant.forensicWatermarkRequired) {
      const sessionNonce = generateRandomId('NONCE');
      watermark = generateForensicWatermark(
        grant.documentId,
        grant.grantId,
        grant.deviceId,
        sessionNonce
      );
    }

    const auditEvent = await auditSink.recordEvent({
      documentId: packageData.documentId,
      packageId: packageData.packageId,
      deviceId: device.deviceId,
      credentialId: credential.credentialId,
      operationId,
      authorizationId: grant.grantId,
      operation: requestedOperation,
      policy: grant.policyLevel,
      result: 'SUCCESS',
      details: `Descifrado exitoso en runtime controlado (${packageData.metadata.originalFileName}, ${decryptedBuffer.byteLength} bytes).`,
    });

    return {
      success: true,
      plaintextBuffer: decryptedBuffer,
      session,
      watermark,
      grant,
      auditEventId: auditEvent.eventId,
    };
  }
}
