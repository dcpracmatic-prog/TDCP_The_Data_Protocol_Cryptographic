/**
 * Authority service: AuthorizationOracle + durable JSON persistence.
 * Survives process restart for revoke / replay / policies / wrap secrets.
 */

import { AuthorizationOracle } from '../../src/oracle/authorization-oracle.ts';
import type { RegisteredDocumentPolicy } from '../../src/oracle/authorization-oracle.ts';
import type {
  AuthorizationGrant,
  AuthorizationRequest,
  DocumentRevocationState,
} from '../../src/core/authorization/types.ts';
import { arrayBufferToBase64, base64ToArrayBuffer } from '../../src/core/crypto/primitives.ts';
import { InProcessAuthority } from '../../src/authority/in-process-authority.ts';
import type { AuthorityPublicInfo } from '../../src/authority/types.ts';
import { DurableJsonAuthorityStore, type DurableAuthoritySnapshot } from './durable-store.ts';
import { UsbHsmRegistry, loadUsbHsmConfigFromEnv, type UsbHsmConfig } from './usb-hsm.ts';
import {
  createAuthoritySigningKeyStore,
  readSigningBackendFromEnv,
  type SigningBackendKind,
} from './signing-backend.ts';

function bytesToBase64(bytes: Uint8Array): string {
  return arrayBufferToBase64(bytes);
}

function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(base64ToArrayBuffer(b64));
}

export interface DurableAuthorityServiceOptions {
  dataDir: string;
  signingBackend?: SigningBackendKind;
  /** Require a verified user on every challenge/grant (set when user auth is on). */
  requireSubject?: boolean;
  /** WebAuthn relying-party config for USB-HSM (env when omitted). */
  usbHsm?: UsbHsmConfig;
}

export class DocumentAlreadyRegisteredError extends Error {
  constructor(documentId: string) {
    super(`DOCUMENT_ALREADY_REGISTERED:${documentId}`);
  }
}

const MAX_ACL_ENTRIES = 50;

function sanitizeUserIds(ids: unknown): string[] {
  if (!Array.isArray(ids)) return [];
  const out = new Set<string>();
  for (const id of ids) {
    if (typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(id)) out.add(id);
    if (out.size >= MAX_ACL_ENTRIES) break;
  }
  return Array.from(out);
}

export class DurableAuthorityService {
  private readonly store: DurableJsonAuthorityStore;
  private snapshot: DurableAuthoritySnapshot;
  private oracle!: AuthorizationOracle;
  private authority!: InProcessAuthority;
  private readonly signingBackend: SigningBackendKind;
  private signingKeyLoaded = false;
  private initialized = false;
  private readonly requireSubject: boolean;
  private readonly usbHsmConfig: UsbHsmConfig;
  private usbHsmRegistry!: UsbHsmRegistry;

  constructor(dataDirOrOptions: string | DurableAuthorityServiceOptions) {
    const options: DurableAuthorityServiceOptions =
      typeof dataDirOrOptions === 'string'
        ? { dataDir: dataDirOrOptions }
        : dataDirOrOptions;
    this.store = new DurableJsonAuthorityStore(options.dataDir);
    this.snapshot = this.store.load();
    this.signingBackend = options.signingBackend ?? readSigningBackendFromEnv();
    this.requireSubject = options.requireSubject === true;
    this.usbHsmConfig = options.usbHsm ?? loadUsbHsmConfigFromEnv();
  }

  public getUsbHsm(): UsbHsmRegistry {
    return this.usbHsmRegistry;
  }

  public async initialize(): Promise<void> {
    const keyStore = createAuthoritySigningKeyStore({
      backend: this.signingBackend,
      snapshot: this.snapshot,
      store: this.store,
      onPersist: (priv, pub) => {
        this.snapshot = this.store.sealPrivateJwk(this.snapshot, priv, pub);
        this.persist();
      },
    });

    this.oracle = new AuthorizationOracle(keyStore, { requireSubject: this.requireSubject });
    await this.oracle.initialize();
    this.signingKeyLoaded = true;
    this.authority = new InProcessAuthority(this.oracle);

    // Hydrate policies + wrap secrets
    for (const policy of this.snapshot.policies) {
      const existing = this.oracle.getDocumentPolicy(policy.documentId);
      if (!existing) {
        // registerDocumentPolicy generates a new secret if missing — inject via map after
        this.oracle.registerDocumentPolicy(policy);
      }
    }
    // Overwrite wrap secrets from durable store (authoritative)
    const wrapMap = (this.oracle as unknown as { documentWrapSecrets: Map<string, Uint8Array> })
      .documentWrapSecrets;
    for (const [docId, b64] of Object.entries(this.snapshot.wrapSecretsBase64)) {
      wrapMap.set(docId, base64ToBytes(b64));
    }

    // Hydrate revocation
    const revMgr = this.oracle.getRevocationManager();
    const revInternal = revMgr as unknown as {
      documentStates: Map<string, DocumentRevocationState>;
    };
    for (const state of this.snapshot.revocation) {
      revInternal.documentStates.set(state.documentId, { ...state });
    }

    // Hydrate replay + grants (bounded)
    const replay = this.oracle.getReplayRegistry();
    replay.hydrateConsumed(this.snapshot.consumedOperations);
    replay.hydrateActiveChallenges(this.snapshot.activeChallenges);
    this.oracle.importChallengeSubjects(this.snapshot.challengeSubjects ?? []);
    const consumed = (this.oracle as unknown as { consumedGrantIds: Set<string> }).consumedGrantIds;
    for (const id of this.snapshot.consumedGrantIds) {
      consumed.add(id);
    }

    this.usbHsmRegistry = new UsbHsmRegistry(
      this.usbHsmConfig,
      this.snapshot.usbHsmDevices ?? [],
      () => this.persist()
    );

    this.initialized = true;
  }

  private captureSnapshot(): void {
    const wrapMap = (this.oracle as unknown as { documentWrapSecrets: Map<string, Uint8Array> })
      .documentWrapSecrets;
    const wrapSecretsBase64: Record<string, string> = {};
    for (const [k, v] of wrapMap.entries()) {
      wrapSecretsBase64[k] = bytesToBase64(v);
    }

    const replay = this.oracle.getReplayRegistry();
    const consumed = (this.oracle as unknown as { consumedGrantIds: Set<string> }).consumedGrantIds;

    this.snapshot = {
      version: 1,
      keyId: this.oracle.getKeyId(),
      signingPrivateJwk: this.snapshot.signingPrivateJwk,
      signingPrivateJwkEnc: this.snapshot.signingPrivateJwkEnc,
      signingPublicJwk: this.snapshot.signingPublicJwk,
      policies: this.oracle.listRegisteredPolicies(),
      wrapSecretsBase64,
      revocation: this.oracle.getRevocationManager().listStates(),
      consumedOperations: replay.exportConsumed(),
      consumedGrantIds: Array.from(consumed),
      activeChallenges: replay.exportActiveChallenges(),
      challengeSubjects: this.oracle.exportChallengeSubjects(),
      usbHsmDevices: this.usbHsmRegistry
        ? this.usbHsmRegistry.exportRecords()
        : (this.snapshot.usbHsmDevices ?? []),
    };
  }

  private persist(): void {
    this.captureSnapshot();
    this.store.save(this.snapshot);
  }


  /** Readiness: durable store writable + signing key loaded. */
  public getReadiness(): {
    ready: boolean;
    storeWritable: boolean;
    signingKeyLoaded: boolean;
    signingBackend: SigningBackendKind;
    developmentOnly: boolean;
  } {
    let storeWritable = false;
    try {
      storeWritable = this.store.probeWritable();
    } catch {
      storeWritable = false;
    }
    return {
      ready: storeWritable && this.signingKeyLoaded,
      storeWritable,
      signingKeyLoaded: this.signingKeyLoaded,
      signingBackend: this.signingBackend,
      developmentOnly: this.initialized ? this.oracle.isDevelopmentKeyStore() : true,
    };
  }

  public getDataDir(): string {
    return this.store.dataDir;
  }

  public getAuthority(): InProcessAuthority {
    return this.authority;
  }

  public getOracle(): AuthorizationOracle {
    return this.oracle;
  }

  public async getPublicInfo(): Promise<AuthorityPublicInfo> {
    const publicKey = await this.oracle.getPublicKey();
    const spki = await crypto.subtle.exportKey('spki', publicKey);
    return {
      keyId: this.oracle.getKeyId(),
      keyStoreKind: this.oracle.getKeyStoreKind(),
      developmentOnly: this.oracle.isDevelopmentKeyStore(),
      publicKeySpkiBase64: arrayBufferToBase64(spki),
    };
  }

  public async issueChallenge(subjectUserId?: string): Promise<string> {
    const c = await this.authority.issueChallenge(subjectUserId);
    this.persist();
    return c;
  }

  public async isValidChallenge(challenge: string): Promise<boolean> {
    return this.authority.isValidChallenge(challenge);
  }

  /**
   * Admin/issuer registration. Refuses to overwrite an existing document
   * (overwriting would reset revocation/view-once and rotate the wrap secret).
   */
  public async registerDocumentPolicy(policy: RegisteredDocumentPolicy): Promise<Uint8Array> {
    if (!policy || typeof policy.documentId !== 'string' || !policy.documentId) {
      throw new Error('INVALID_POLICY');
    }
    if (this.oracle.getDocumentPolicy(policy.documentId)) {
      throw new DocumentAlreadyRegisteredError(policy.documentId);
    }
    const clean: RegisteredDocumentPolicy = {
      ...policy,
      ...(policy.ownerUserId ? { ownerUserId: String(policy.ownerUserId) } : {}),
      allowedUserIds: sanitizeUserIds(policy.allowedUserIds),
    };
    const secret = await this.authority.registerDocumentPolicy(clean);
    this.persist();
    return secret;
  }

  /** User registration: owner is always the verified caller, never the body. */
  public async registerOwnedDocument(
    policy: RegisteredDocumentPolicy,
    ownerUserId: string
  ): Promise<Uint8Array> {
    const { ownerUserId: _ignored, ...rest } = policy ?? ({} as RegisteredDocumentPolicy);
    void _ignored;
    return this.registerDocumentPolicy({
      ...rest,
      ownerUserId,
      allowedUserIds: sanitizeUserIds(rest.allowedUserIds).filter((id) => id !== ownerUserId),
      createdAt: Date.now(),
    });
  }

  public async updateDocumentAcl(documentId: string, allowedUserIds: unknown) {
    const policy = this.oracle.getDocumentPolicy(documentId);
    const owner = policy?.ownerUserId;
    const updated = this.oracle.updateDocumentAcl(
      documentId,
      sanitizeUserIds(allowedUserIds).filter((id) => id !== owner)
    );
    this.persist();
    return updated;
  }

  public async listPoliciesForUser(userId: string) {
    const all = await this.authority.listRegisteredPolicies();
    return all.filter(
      (p) => p.ownerUserId === userId || (p.allowedUserIds ?? []).includes(userId)
    );
  }

  public isSubjectRequired(): boolean {
    return this.requireSubject;
  }

  public async processAuthorizationRequest(request: AuthorizationRequest) {
    const result = await this.authority.processAuthorizationRequest(request);
    this.persist();
    return result;
  }

  public async releaseDocumentWrapSecretForGrant(grant: AuthorizationGrant, subjectUserId?: string) {
    const secret = await this.authority.releaseDocumentWrapSecretForGrant(grant, subjectUserId);
    this.persist();
    return secret;
  }

  public async commitViewOnce(documentId: string, grantId: string, subjectUserId?: string) {
    const ok = await this.authority.commitViewOnce(documentId, grantId, subjectUserId);
    this.persist();
    return ok;
  }

  public async revokeDocument(documentId: string, reason?: string, revokedBy?: string) {
    const state = await this.authority.revokeDocument(documentId, reason, revokedBy);
    this.persist();
    return state;
  }

  public async restoreDocument(documentId: string) {
    const state = await this.authority.restoreDocument(documentId);
    this.persist();
    return state;
  }

  public async getDocumentPolicy(documentId: string) {
    return this.authority.getDocumentPolicy(documentId);
  }

  public async listRegisteredPolicies() {
    return this.authority.listRegisteredPolicies();
  }

  public async getDocumentRevocationState(documentId: string) {
    return this.authority.getDocumentRevocationState(documentId);
  }

  public async listRevoked() {
    return this.authority.listRevoked();
  }

  /** Test helper: force flush current in-memory state to disk. */
  public flush(): void {
    this.persist();
  }
}
