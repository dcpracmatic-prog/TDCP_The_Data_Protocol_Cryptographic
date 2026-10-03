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

import { policyRequiresUsbHsm } from '../core/authorization/usb-hsm.ts';
import { createPolicyBinding, type EdgeSpec, type PolicyBinding } from '../channel/policy-binding.ts';
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
  /** Verified user who registered the document (set by the issuer backend). */
  ownerUserId?: string;
  /** Users allowed to request grants, in addition to the owner. */
  allowedUserIds?: string[];
  /** Opening requires a verified USB-HSM assertion (implicit for CRITICAL/ULTRA_CRITICAL). */
  requireUsbHsm?: boolean;
  /** Authority-signed channel edges enforced after grant issuance. */
  channelEdges?: EdgeSpec[];
}

export interface AuthorizationOracleOptions {
  /**
   * Production mode: every challenge/authorization must carry a verified
   * `subjectUserId`, and documents must have an owner/ACL.
   */
  requireSubject?: boolean;
}

/** True when `userId` is the owner or on the document ACL. */
export function isUserAllowedForPolicy(policy: RegisteredDocumentPolicy, userId: string | undefined): boolean {
  if (!userId) return false;
  if (policy.ownerUserId === userId) return true;
  return Array.isArray(policy.allowedUserIds) && policy.allowedUserIds.includes(userId);
}

function policyHasAcl(policy: RegisteredDocumentPolicy): boolean {
  return Boolean(policy.ownerUserId) || (Array.isArray(policy.allowedUserIds) && policy.allowedUserIds.length > 0);
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
  /** challenge → verified user it was issued to. */
  private challengeSubjects: Map<string, string> = new Map();
  /** grantId → verified user (for view-once commit binding). */
  private grantSubjects: Map<string, string> = new Map();
  private requireSubject: boolean;

  constructor(keyStore?: OracleKeyStore, options: AuthorizationOracleOptions = {}) {
    this.requireSubject = options.requireSubject === true;
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

  private async signPolicyBinding(policy: import('../channel/policy-binding.ts').ChannelPolicy): Promise<PolicyBinding> {
    const canonical = JSON.stringify({
      documentId: policy.documentId,
      grantId: policy.grantId,
      expiry: policy.expiry,
      edges: [...policy.edges].map((e) => ({ source: e.source, destination: e.destination, expectedBytes: e.expectedBytes, allowed: e.allowed }))
        .sort((a, b) => `${a.source}->${a.destination}`.localeCompare(`${b.source}->${b.destination}`)),
    });
    const hash = await (await import('../core/crypto/primitives.ts')).computeSHA256(canonical);
    const signature = typeof this.keyStore.signCanonical === 'function'
      ? arrayBufferToBase64(await this.keyStore.signCanonical(canonical))
      : await signDataECDSA((await this.keyStore.getOrCreateSigningKey()).privateKey, canonical);
    return { policyCanonical: canonical, policyHash: hash, signature, authorityKid: this.keyStore.getKeyId(), issuedAt: Date.now() };
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
  public issueChallenge(subjectUserId?: string): string {
    if (this.requireSubject && !subjectUserId) throw new Error('USER_AUTH_REQUIRED');
    const challenge = this.replayRegistry.issueFreshChallenge(() => generateRandomId('CHALLENGE'));
    if (subjectUserId) {
      this.challengeSubjects.set(challenge, subjectUserId);
      if (this.challengeSubjects.size > 20_000) {
        const oldest = this.challengeSubjects.keys().next().value;
        if (oldest !== undefined) this.challengeSubjects.delete(oldest);
      }
    }
    return challenge;
  }

  public isSubjectRequired(): boolean {
    return this.requireSubject;
  }

  /** Snapshot of (challenge -> subjectUserId) bindings, for durable persistence. */
  public exportChallengeSubjects(): Array<{ challenge: string; subjectUserId: string }> {
    return Array.from(this.challengeSubjects.entries()).map(([challenge, subjectUserId]) => ({
      challenge,
      subjectUserId,
    }));
  }

  /**
   * Restore (challenge -> subjectUserId) bindings after a restart. Only
   * entries for challenges the replay registry still considers active are
   * kept — the registry's own snapshot is the source of truth for validity.
   */
  public importChallengeSubjects(entries: Array<{ challenge: string; subjectUserId: string }>): void {
    for (const { challenge, subjectUserId } of entries) {
      if (this.replayRegistry.isValidChallenge(challenge)) {
        this.challengeSubjects.set(challenge, subjectUserId);
      }
    }
  }

  /** Replace the ACL (owner stays). Returns the updated policy or undefined. */
  public updateDocumentAcl(documentId: string, allowedUserIds: string[]): RegisteredDocumentPolicy | undefined {
    const policy = this.documentPolicies.get(documentId);
    if (!policy) return undefined;
    const unique = Array.from(new Set(allowedUserIds.filter((u) => typeof u === 'string' && u.length > 0)));
    const updated = { ...policy, allowedUserIds: unique };
    this.documentPolicies.set(documentId, updated);
    return updated;
  }

  /**
   * Registers a newly encrypted document's policies and generates its wrap secret.
   * Returns the wrap secret so the factory can wrap the CEK. The secret is NOT
   * written into the package.
   */
  public registerDocumentPolicy(policy: RegisteredDocumentPolicy): Uint8Array {
    if (this.documentPolicies.has(policy.documentId)) {
      throw new Error('DOCUMENT_ALREADY_REGISTERED');
    }
    this.documentPolicies.set(policy.documentId, policy);
    this.revocationManager.getOrCreateState(policy.documentId);
    const secret = generateRandomBytes(32);
    this.documentWrapSecrets.set(policy.documentId, secret);
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
  public async releaseDocumentWrapSecretForGrant(
    grant: AuthorizationGrant,
    subjectUserId?: string
  ): Promise<Uint8Array | null> {
    if (grant.oneTimeUse !== true || this.consumedGrantIds.has(grant.grantId)) return null;
    // A user-bound grant can only be redeemed by that same verified user.
    if (grant.subjectUserId && grant.subjectUserId !== subjectUserId) return null;
    if (this.requireSubject && !grant.subjectUserId) return null;

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

    // Re-check the ACL at redemption time (it may have changed since issuance).
    if (policyHasAcl(policy) && !isUserAllowedForPolicy(policy, grant.subjectUserId)) return null;

    this.consumedGrantIds.add(grant.grantId);
    if (grant.subjectUserId) this.grantSubjects.set(grant.grantId, grant.subjectUserId);
    // Production mode: View-Once is consumed atomically with the secret release,
    // so a modified client cannot skip the commit and reopen the document.
    if (this.requireSubject && policy.viewOnce) {
      this.revocationManager.markViewOnceConsumed(grant.documentId);
    }
    return new Uint8Array(secret);
  }

  /**
   * Commits View-Once only after the authorized operation has actually
   * decrypted successfully. A failed decryption therefore does not consume
   * the document.
   */
  public commitViewOnce(documentId: string, grantId: string, subjectUserId?: string): boolean {
    const boundTo = this.grantSubjects.get(grantId);
    if (boundTo && boundTo !== subjectUserId) return false;
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
    channelPolicyBinding?: PolicyBinding;
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

    if (this.requireSubject && !request.subjectUserId) {
      return {
        granted: false,
        rejectionCode: 'USER_AUTH_REQUIRED',
        rejectionReason: 'USER_AUTH_REQUIRED: se requiere una sesión de usuario verificada.',
      };
    }

    const challengeOwner = this.challengeSubjects.get(request.challenge);
    if (challengeOwner && challengeOwner !== request.subjectUserId) {
      return {
        granted: false,
        rejectionCode: 'CHALLENGE_SUBJECT_MISMATCH',
        rejectionReason: 'CHALLENGE_SUBJECT_MISMATCH: el challenge fue emitido para otro usuario.',
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

    if (this.requireSubject && !policyHasAcl(docPolicy)) {
      return {
        granted: false,
        rejectionCode: 'DOCUMENT_HAS_NO_ACL',
        rejectionReason: 'DOCUMENT_HAS_NO_ACL: el documento no tiene propietario ni lista de acceso.',
      };
    }

    if (policyHasAcl(docPolicy) && !isUserAllowedForPolicy(docPolicy, request.subjectUserId)) {
      return {
        granted: false,
        rejectionCode: 'CREDENTIAL_UNAUTHORIZED',
        rejectionReason: 'CREDENTIAL_UNAUTHORIZED: tu usuario no tiene acceso a este documento.',
      };
    }

    // USB-HSM: in production mode the Authority must have verified an
    // assertion from an ACTIVE key of this user (see server/authority/usb-hsm.ts).
    if (this.requireSubject && policyRequiresUsbHsm(docPolicy)) {
      const hsm = request.verifiedUsbHsm;
      if (!hsm || hsm.deviceId !== request.deviceId) {
        return {
          granted: false,
          rejectionCode: 'USB_HSM_REQUIRED',
          rejectionReason:
            'USB_HSM_REQUIRED: este documento solo se abre con tu USB-HSM registrado.',
        };
      }
      // CRITICAL tiers: the "biometric" signal is the USB-HSM user-verification
      // flag (PIN/fingerprint on the key) — never the client's self-declaration.
      request = {
        ...request,
        policyContext: { ...(request.policyContext ?? {}), biometricVerified: hsm.userVerified },
      };
    } else if (this.requireSubject) {
      request = {
        ...request,
        policyContext: { ...(request.policyContext ?? {}), biometricVerified: false },
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
      ...(request.subjectUserId ? { subjectUserId: request.subjectUserId } : {}),
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
    this.challengeSubjects.delete(fullGrant.challenge);
    if (!consumed) {
      return {
        granted: false,
        rejectionCode: 'REPLAY_ATTACK_DETECTED',
        rejectionReason: 'REPLAY_ATTACK_DETECTED: el challenge u operation_id no pudo consumirse de forma única.',
      };
    }

    const channelEdges = docPolicy.channelEdges && docPolicy.channelEdges.length > 0
      ? docPolicy.channelEdges
      : [{ source: 'A', destination: 'B', expectedBytes: 0, allowed: true }];
    const channelPolicy = {
      documentId: fullGrant.documentId,
      grantId: fullGrant.grantId,
      expiry: fullGrant.expiresAt,
      edges: channelEdges,
    };
    const channelPolicyBinding = await this.signPolicyBinding(channelPolicy);

    return {
      granted: true,
      grant: fullGrant,
      channelPolicyBinding,
    };
  }
}

export const globalAuthorizationOracle = new AuthorizationOracle();
