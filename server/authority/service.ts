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
}

export class DurableAuthorityService {
  private readonly store: DurableJsonAuthorityStore;
  private snapshot: DurableAuthoritySnapshot;
  private oracle!: AuthorizationOracle;
  private authority!: InProcessAuthority;
  private readonly signingBackend: SigningBackendKind;
  private signingKeyLoaded = false;
  private initialized = false;

  constructor(dataDirOrOptions: string | DurableAuthorityServiceOptions) {
    const options: DurableAuthorityServiceOptions =
      typeof dataDirOrOptions === 'string'
        ? { dataDir: dataDirOrOptions }
        : dataDirOrOptions;
    this.store = new DurableJsonAuthorityStore(options.dataDir);
    this.snapshot = this.store.load();
    this.signingBackend = options.signingBackend ?? readSigningBackendFromEnv();
  }

  public async initialize(): Promise<void> {
    const keyStore = createAuthoritySigningKeyStore({
      backend: this.signingBackend,
      snapshot: this.snapshot,
      onPersist: (priv, pub) => {
        this.snapshot.signingPrivateJwk = priv;
        this.snapshot.signingPublicJwk = pub;
        this.persist();
      },
    });

    this.oracle = new AuthorizationOracle(keyStore);
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

    // Hydrate replay + grants
    const replay = this.oracle.getReplayRegistry();
    const replayInternal = replay as unknown as {
      consumedOperations: Map<string, unknown>;
      activeChallenges: Map<string, number>;
    };
    for (const rec of this.snapshot.consumedOperations) {
      replayInternal.consumedOperations.set(rec.operationId, rec);
    }
    for (const ch of this.snapshot.activeChallenges) {
      replayInternal.activeChallenges.set(ch.challenge, ch.registeredAt);
    }
    const consumed = (this.oracle as unknown as { consumedGrantIds: Set<string> }).consumedGrantIds;
    for (const id of this.snapshot.consumedGrantIds) {
      consumed.add(id);
    }

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
    const replayInternal = replay as unknown as {
      consumedOperations: Map<string, DurableAuthoritySnapshot['consumedOperations'][number]>;
      activeChallenges: Map<string, number>;
    };
    const consumed = (this.oracle as unknown as { consumedGrantIds: Set<string> }).consumedGrantIds;

    this.snapshot = {
      version: 1,
      keyId: this.oracle.getKeyId(),
      signingPrivateJwk: this.snapshot.signingPrivateJwk,
      signingPublicJwk: this.snapshot.signingPublicJwk,
      policies: this.oracle.listRegisteredPolicies(),
      wrapSecretsBase64,
      revocation: this.oracle.getRevocationManager().listStates(),
      consumedOperations: Array.from(replayInternal.consumedOperations.values()),
      consumedGrantIds: Array.from(consumed),
      activeChallenges: Array.from(replayInternal.activeChallenges.entries()).map(
        ([challenge, registeredAt]) => ({ challenge, registeredAt })
      ),
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

  public async issueChallenge(): Promise<string> {
    const c = await this.authority.issueChallenge();
    this.persist();
    return c;
  }

  public async isValidChallenge(challenge: string): Promise<boolean> {
    return this.authority.isValidChallenge(challenge);
  }

  public async registerDocumentPolicy(policy: RegisteredDocumentPolicy): Promise<Uint8Array> {
    const secret = await this.authority.registerDocumentPolicy(policy);
    this.persist();
    return secret;
  }

  public async processAuthorizationRequest(request: AuthorizationRequest) {
    const result = await this.authority.processAuthorizationRequest(request);
    this.persist();
    return result;
  }

  public async releaseDocumentWrapSecretForGrant(grant: AuthorizationGrant) {
    const secret = await this.authority.releaseDocumentWrapSecretForGrant(grant);
    this.persist();
    return secret;
  }

  public async commitViewOnce(documentId: string, grantId: string) {
    const ok = await this.authority.commitViewOnce(documentId, grantId);
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
