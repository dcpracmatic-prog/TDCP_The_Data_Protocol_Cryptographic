/**
 * The Data Cryptographic Protocol (TDCP)
 * Application security facade — the ONLY path UI components may use.
 *
 * Encrypt → createTDCPPackage + Oracle policy registration
 * Unlock  → DCPGatekeeper.executeUnlock
 *
 * There is no password → AES → plaintext function here.
 */

import { globalAuthorizationOracle } from '../oracle/authorization-oracle.ts';
import type { AuthorizationOracle } from '../oracle/authorization-oracle.ts';
import { globalAuditSink, TDCP_AUDIT_UPDATED_EVENT } from '../audit/audit-sink.ts';
import type { AuditSink } from '../audit/audit-sink.ts';
import { DCPGatekeeper } from '../gatekeeper/gatekeeper.ts';
import type { GatekeeperUnlockResult } from '../gatekeeper/gatekeeper.ts';
import { createTDCPPackage } from '../core/package/tdcp-factory.ts';
import {
  deserializeTDCPPackage,
  serializeTDCPPackage,
  type TDCPPackage,
} from '../core/package/package-format.ts';
import type { PolicyLevel, TDCPRequestedOperation } from '../core/authorization/types.ts';
import { MockNFCProvider, RealNFCProvider, type NFCProvider } from '../identity/credential-provider.ts';
import {
  MockDeviceIdentityProvider,
  WebAuthnDeviceIdentityProvider,
  type DeviceIdentityProvider,
} from '../identity/device-identity-provider.ts';
import {
  MockBiometricProvider,
  WebAuthnBiometricProvider,
  type BiometricProvider,
} from '../identity/biometric-provider.ts';
import { MemoryStorageProvider, type StorageProvider } from '../storage/storage-provider.ts';

export interface CreatePackageRequest {
  plaintext: ArrayBuffer;
  password: string;
  originalFileName: string;
  mimeType: string;
  policyLevel: PolicyLevel;
  allowExtraction: boolean;
  expirationDays?: number;
  viewOnce?: boolean;
  watermarkRequired?: boolean;
  blurMode?: boolean;
}

export class TdcpRuntime {
  public readonly oracle: AuthorizationOracle;
  public readonly auditSink: AuditSink;
  public readonly nfcProvider: NFCProvider;
  public readonly deviceProvider: DeviceIdentityProvider;
  public readonly biometricProvider: BiometricProvider;
  public readonly localStorageProvider: StorageProvider;

  constructor() {
    this.oracle = globalAuthorizationOracle;
    this.auditSink = globalAuditSink;
    this.nfcProvider = new MockNFCProvider();
    this.deviceProvider = new MockDeviceIdentityProvider();
    this.biometricProvider = new MockBiometricProvider();
    this.localStorageProvider = new MemoryStorageProvider();
  }

  public getProviderStatus() {
    return {
      oracleKeyStore: this.oracle.getKeyStoreKind(),
      oracleKeyStoreDevelopmentOnly: this.oracle.isDevelopmentKeyStore(),
      nfc: {
        name: this.nfcProvider.providerName,
        hardware: this.nfcProvider.isHardwareBacked,
        mock: this.nfcProvider instanceof MockNFCProvider,
      },
      device: {
        name: this.deviceProvider.providerName,
        hardware: this.deviceProvider.isHardwareBacked,
        mock: this.deviceProvider instanceof MockDeviceIdentityProvider,
      },
      biometric: {
        name: this.biometricProvider.providerName,
        hardware: this.biometricProvider.isHardwareBacked,
        mock: this.biometricProvider instanceof MockBiometricProvider,
      },
      webAuthnDeviceStub: WebAuthnDeviceIdentityProvider,
      realNfcStub: RealNFCProvider,
      webAuthnBiometric: WebAuthnBiometricProvider,
      auditClaim: this.auditSink.integrityClaim,
    };
  }

  public async createPackage(req: CreatePackageRequest): Promise<{
    pkg: TDCPPackage;
    blob: Blob;
    monitoringKey: string;
  }> {
    const pkg = await createTDCPPackage({
      ...req,
      oracle: this.oracle,
    });

    await this.auditSink.recordEvent({
      documentId: pkg.documentId,
      packageId: pkg.packageId,
      deviceId: 'ISSUER',
      credentialId: 'ISSUER',
      operationId: `CREATE-${pkg.packageId}`,
      operation: 'ENCRYPT_PACKAGE',
      policy: pkg.metadata.policyLevel,
      result: 'SUCCESS',
      details: `TDCPPackage sellado (${pkg.metadata.originalFileName}, ${pkg.metadata.originalSizeBytes} bytes). Política registrada en Oracle. Paquete ≠ autorización.`,
    });

    const blob = await serializeTDCPPackage(pkg);
    return {
      pkg,
      blob,
      monitoringKey: `MONITOR-${pkg.documentId}`,
    };
  }

  public async parsePackage(data: ArrayBuffer | string) {
    return deserializeTDCPPackage(data);
  }

  public async unlock(options: {
    pkg: TDCPPackage;
    password: string;
    requestedOperation: TDCPRequestedOperation;
  }): Promise<GatekeeperUnlockResult> {
    return DCPGatekeeper.executeUnlock({
      packageData: options.pkg,
      userPassword: options.password,
      requestedOperation: options.requestedOperation,
      nfcProvider: this.nfcProvider,
      deviceProvider: this.deviceProvider,
      biometricProvider: this.biometricProvider,
      oracle: this.oracle,
      auditSink: this.auditSink,
    });
  }

  public revokeDocument(documentId: string, reason?: string) {
    const state = this.oracle.getRevocationManager().revokeDocument(documentId, reason);
    void this.auditSink.recordEvent({
      documentId,
      packageId: this.oracle.getDocumentPolicy(documentId)?.packageId || 'UNKNOWN',
      deviceId: 'SECURITY_OFFICER',
      credentialId: 'SECURITY_OFFICER',
      operationId: `REVOKE-${documentId}`,
      operation: 'KILL_SWITCH_ENGAGED',
      policy: this.oracle.getDocumentPolicy(documentId)?.policyLevel || 'STANDARD',
      result: 'DENIED',
      details: `Documento revocado. epoch=${state.currentEpoch}. Grants anteriores inválidos.`,
    });
    return state;
  }

  public restoreDocument(documentId: string) {
    const state = this.oracle.getRevocationManager().restoreDocument(documentId);
    void this.auditSink.recordEvent({
      documentId,
      packageId: this.oracle.getDocumentPolicy(documentId)?.packageId || 'UNKNOWN',
      deviceId: 'SECURITY_OFFICER',
      credentialId: 'SECURITY_OFFICER',
      operationId: `RESTORE-${documentId}`,
      operation: 'KILL_SWITCH_RESTORED',
      policy: this.oracle.getDocumentPolicy(documentId)?.policyLevel || 'STANDARD',
      result: 'SUCCESS',
      details: `Documento restaurado. epoch=${state.currentEpoch}. Grants anteriores siguen inválidos.`,
    });
    return state;
  }

  public listRevoked() {
    return this.oracle.getRevocationManager().listRevoked();
  }

  public listPolicies() {
    return this.oracle.listRegisteredPolicies();
  }
}

export const tdcpRuntime = new TdcpRuntime();
export { TDCP_AUDIT_UPDATED_EVENT };

/**
 * Intentionally absent: there is no deriveSymmetricKey / decryptWithPassword
 * export. Tests that try to import one must fail.
 */
export function decryptPackageDirectlyWithPassword(): never {
  throw new Error(
    'DIRECT_DECRYPT_FORBIDDEN: TDCP does not expose password-only decryption. Use DCPGatekeeper.executeUnlock().'
  );
}
