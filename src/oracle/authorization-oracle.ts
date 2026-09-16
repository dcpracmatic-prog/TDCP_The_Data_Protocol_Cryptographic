/**
 * The Data Cryptographic Protocol (TDCP)
 * Centralized Authorization Oracle (Control Plane)
 *
 * Fundamental principle:
 * "The document can be copied. The authorization to use it cannot."
 *
 * Rules:
 * - The Oracle NEVER receives or stores the document, plaintext, or content key.
 * - Evaluates deterministic policy against revocation state and anti-replay records.
 * - Signs one-time AuthorizationGrants using ECDSA P-256.
 * - Holds a per-document wrap secret used as an HKDF factor. Copying the
 *   package does not copy this secret, so password + package is not enough.
 */

import {
  canonicalizeGrant,
  type AuthorizationGrant,
} from '../core/authorization/types.ts';
import type {
  AuthorizationRequest,
  PolicyLevel,
} from '../core/authorization/types.ts';
import {
  signDataECDSA,
  verifySignatureECDSA,
  generateRandomId,
  generateRandomBytes,
  arrayBufferToBase64,
} from '../core/crypto/primitives.ts';
import { DeterministicPolicyEngine } from '../core/policy/policy-engine.ts';
import { EpochRevocationManager } from '../core/revocation/epoch-manager.ts';
import { AntiReplayRegistry } from '../core/replay/replay-cache.ts';
import {
  DevelopmentInMemoryOracleKeyStore,
  type OracleKeyStore,
} from './oracle-key-store.ts';

export interface RegisteredDocumentPolicy {
  documentId: string;
  packageId: string;
  policyLevel: PolicyLevel;
  allowExtraction: boolean;
  expirationDays?: number;
  viewOnce?: boolean;
  createdAt: number;
}

export class AuthorizationOracle {
  private keyStore: OracleKeyStore;
  private policyEngine: DeterministicPolicyEngine;
  private revocationManager: EpochRevocationManager;
  private replayRegistry: AntiReplayRegistry;
  private documentPolicies: Map<string, RegisteredDocumentPolicy> = new Map();
  /** Per-document wrap secrets. DEVELOPMENT ONLY — RAM, never localStorage. */
  private documentWrapSecrets: Map<string, Uint8Array> = new Map();
  private consumedGrantIds: Set<string> = new Set();

  constructor(keyStore?: OracleKeyStore) {
    this.keyStore = keyStore ?? new DevelopmentInMemoryOracleKeyStore();
    this.policyEngine = new DeterministicPolicyEngine();
    this.revocationManager = new EpochRevocationManager();
    this.replayRegistry = new AntiReplayRegistry();
  }

  public async initialize(): Promise<void> {
    await this.keyStore.getOrCreateSigningKey();
  }

  public async getPublicKey(): Promise<CryptoKey> {
    return this.keyStore.getPublicKey();
  }

  public getKeyId(): string {
    return this.keyStore.getKeyId();
  }

  public getKeyStoreKind(): string {
    return this.keyStore.kind;
  }

  public isDevelopmentKeyStore(): boolean {
    return this.keyStore.developmentOnly;
  }

  public getRevocationManager(): EpochRevocationManager {
    return this.revocationManager;
  }

  public getReplayRegistry(): AntiReplayRegistry {
    return this.replayRegistry;
  }

  /** Issues an Oracle-tracked challenge. Production clients must obtain challenges through this boundary. */
  public issueChallenge(): string {
    return this.replayRegistry.issueFreshChallenge(() => generateRandomId('CHALLENGE'));
  }

  /**
   * Registers a newly encrypted document's policies and generates its wrap secret.
   * Returns the wrap secret so the factory can wrap the CEK. The secret is NOT
   * written into the package.
   */
  public registerDocumentPolicy(policy: RegisteredDocumentPolicy): Uint8Array {
    this.documentPolicies.set(policy.documentId, policy);
    this.revocationManager.getOrCreateState(policy.documentId);
    let secret = this.documentWrapSecrets.get(policy.documentId);
    if (!secret) {
      secret = generateRandomBytes(32);
      this.documentWrapSecrets.set(policy.documentId, secret);
    }
    return secret;
  }

  public getDocumentPolicy(documentId: string): RegisteredDocumentPolicy | undefined {
    return this.documentPolicies.get(documentId);
  }

  public listRegisteredPolicies(): RegisteredDocumentPolicy[] {
    return Array.from(this.documentPolicies.values());
  }

  /**
   * Releases the document wrap secret ONLY after a grant for that document has
   * been verified by the caller. Gatekeeper is the sole intended consumer.
   */
  /**
   * Releases the document wrap secret only for a valid, signed, current,
   * one-time grant. In this browser reference build the Oracle remains an
   * in-process control plane; production deployment MUST move this method
   * behind a remote authorization service/HSM boundary.
   */
  public async releaseDocumentWrapSecretForGrant(grant: AuthorizationGrant): Promise<Uint8Array | null> {
    if (grant.oneTimeUse !== true || this.consumedGrantIds.has(grant.grantId)) return null;

    const policy = this.documentPolicies.get(grant.documentId);
    if (!policy || policy.packageId !== grant.packageId) return null;

    const state = this.revocationManager.getOrCreateState(grant.documentId);
    if (state.isRevoked || grant.authorizationEpoch !== state.currentEpoch) return null;
    if (Date.now() > grant.expiresAt) return null;

    const publicKey = await this.keyStore.getPublicKey();
    const { signature, ...unsignedPayload } = grant;
    const validSignature = await verifySignatureECDSA(
      publicKey,
      signature,
      canonicalizeGrant(unsignedPayload)
    );
    if (!validSignature) return null;

    const secret = this.documentWrapSecrets.get(grant.documentId);
    if (!secret) return null;

    this.consumedGrantIds.add(grant.grantId);
    return new Uint8Array(secret);
  }

  /**
   * Commits View-Once only after the authorized operation has actually
   * decrypted successfully. A failed decryption therefore does not consume
   * the document.
   */
  public commitViewOnce(documentId: string, grantId: string): boolean {
    if (this.consumedGrantIds.has(grantId)) {
      const policy = this.documentPolicies.get(documentId);
      if (policy?.viewOnce) {
        this.revocationManager.markViewOnceConsumed(documentId);
        return true;
      }
    }
    return false;
  }


  public async processAuthorizationRequest(request: AuthorizationRequest): Promise<{
    granted: boolean;
    grant?: AuthorizationGrant;
    rejectionReason?: string;
    rejectionCode?: string;
  }> {
    await this.initialize();

    if (this.replayRegistry.isReplayed(request.operationId, request.challenge)) {
      return {
        granted: false,
        rejectionCode: 'REPLAY_ATTACK_DETECTED',
        rejectionReason:
          'REPLAY_ATTACK_DETECTED: El challenge u operation_id ya fue consumido previamente.',
      };
    }

    if (!this.replayRegistry.isValidChallenge(request.challenge)) {
      return {
        granted: false,
        rejectionCode: 'INVALID_CHALLENGE',
        rejectionReason:
          'INVALID_CHALLENGE: El challenge no fue emitido por el Gatekeeper o ya expiró.',
      };
    }

    const docPolicy = this.documentPolicies.get(request.documentId);
    if (!docPolicy) {
      return {
        granted: false,
        rejectionCode: 'DOCUMENT_NOT_REGISTERED',
        rejectionReason:
          'DOCUMENT_NOT_REGISTERED: El paquete no tiene política de autorización en este Oracle. Copiar el archivo no concede autorización.',
      };
    }

    const revocationState = this.revocationManager.getOrCreateState(request.documentId);

    const decision = this.policyEngine.evaluate({
      request,
      revocationState,
      policyLevel: docPolicy.policyLevel,
      allowExtractionConfigured: docPolicy.allowExtraction,
      expirationDaysConfigured: docPolicy.expirationDays,
      packageCreatedAt: docPolicy.createdAt,
      oracleCurrentTime: Date.now(),
      viewOnceConfigured: docPolicy.viewOnce === true,
    });

    if (!decision.allowed) {
      return {
        granted: false,
        rejectionCode: decision.rejectionCode,
        rejectionReason: decision.rejectionReason || 'POLÍTICA_DENEGADA',
      };
    }

    const now = Date.now();
    const expiresAt = now + decision.validityWindowSeconds * 1000;
        const unsignedGrantPayload: Omit<AuthorizationGrant, 'signature'> = {
      grantId: generateRandomId('GRANT'),
      documentId: request.documentId,
      packageId: request.packageId,
      deviceId: request.deviceId,
      credentialId: request.credentialId,
      operationId: request.operationId,
      challenge: request.challenge,
      operation: request.requestedOperation,
      policyLevel: docPolicy.policyLevel,
      authorizationEpoch: revocationState.currentEpoch,
      issuedAt: now,
      expiresAt,
      oneTimeUse: true,
      allowExtraction: decision.allowExtraction,
      forensicWatermarkRequired: decision.forensicWatermarkRequired,
      oracleKeyId: this.keyStore.getKeyId(),
    };

    const canonicalString = canonicalizeGrant(unsignedGrantPayload);
    let signature: string;
    if (typeof this.keyStore.signCanonical === 'function') {
      const sigBuf = await this.keyStore.signCanonical(canonicalString);
      signature = arrayBufferToBase64(sigBuf);
    } else {
      const keyPair = await this.keyStore.getOrCreateSigningKey();
      signature = await signDataECDSA(keyPair.privateKey, canonicalString);
    }

    const fullGrant: AuthorizationGrant = {
      ...unsignedGrantPayload,
      signature,
    };

    // Consume the challenge + operation atomically when the one-time grant is issued.
    // This closes the window where the same challenge could mint multiple grants.
    const consumed = this.replayRegistry.consumeOperation({
      operationId: fullGrant.operationId,
      challenge: fullGrant.challenge,
      grantId: fullGrant.grantId,
      documentId: fullGrant.documentId,
      deviceId: fullGrant.deviceId,
      consumedAt: now,
    });
    if (!consumed) {
      return {
        granted: false,
        rejectionCode: 'REPLAY_ATTACK_DETECTED',
        rejectionReason: 'REPLAY_ATTACK_DETECTED: el challenge u operation_id no pudo consumirse de forma única.',
      };
    }

    return {
      granted: true,
      grant: fullGrant,
    };
  }
}

export const globalAuthorizationOracle = new AuthorizationOracle();
