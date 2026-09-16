/**
 * HTTP client for a remote Authorization Authority.
 * Gatekeeper uses this when TDCP_AUTHORITY_URL is set.
 *
 * Client receives minimum material only (grants, ephemeral wrap secret bytes
 * after verified grant). Signing keys never leave the Authority.
 */

import type {
  AuthorizationGrant,
  AuthorizationRequest,
  DocumentRevocationState,
} from '../core/authorization/types.ts';
import type { RegisteredDocumentPolicy } from '../oracle/authorization-oracle.ts';
import { base64ToArrayBuffer, arrayBufferToBase64 } from '../core/crypto/primitives.ts';
import type {
  AuthorityAuthResult,
  AuthorizationAuthority,
  AuthorityPublicInfo,
} from './types.ts';

export interface HttpAuthorityClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
}

async function importSpkiPublicKey(spkiBase64: string): Promise<CryptoKey> {
  const spki = base64ToArrayBuffer(spkiBase64);
  return crypto.subtle.importKey(
    'spki',
    spki,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}

export class HttpAuthorityClient implements AuthorizationAuthority {
  public readonly kind = 'HTTP_REMOTE' as const;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private cachedInfo: AuthorityPublicInfo | null = null;
  private cachedPublicKey: CryptoKey | null = null;

  constructor(options: HttpAuthorityClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(`AUTHORITY_BAD_JSON: ${res.status} ${path}`);
    }
    if (!res.ok) {
      const err = parsed as { error?: string; rejectionCode?: string } | null;
      throw new Error(
        err?.rejectionCode || err?.error || `AUTHORITY_HTTP_${res.status}:${path}`
      );
    }
    return parsed as T;
  }

  public async initialize(): Promise<void> {
    await this.refreshPublicInfo();
  }

  private async refreshPublicInfo(): Promise<AuthorityPublicInfo> {
    const info = await this.request<AuthorityPublicInfo>('GET', '/v1/public-key');
    this.cachedInfo = info;
    this.cachedPublicKey = await importSpkiPublicKey(info.publicKeySpkiBase64);
    return info;
  }

  public async getPublicKey(): Promise<CryptoKey> {
    if (!this.cachedPublicKey) await this.refreshPublicInfo();
    return this.cachedPublicKey!;
  }

  public async getPublicKeySpkiBase64(): Promise<string> {
    if (!this.cachedInfo) await this.refreshPublicInfo();
    return this.cachedInfo!.publicKeySpkiBase64;
  }

  public getKeyId(): string {
    return this.cachedInfo?.keyId ?? 'AUTHORITY-KEY-UNKNOWN';
  }

  public getKeyStoreKind(): string {
    return this.cachedInfo?.keyStoreKind ?? 'REMOTE_AUTHORITY';
  }

  public isDevelopmentKeyStore(): boolean {
    return this.cachedInfo?.developmentOnly ?? true;
  }

  public async issueChallenge(): Promise<string> {
    const res = await this.request<{ challenge: string }>('POST', '/v1/challenge');
    return res.challenge;
  }

  public async isValidChallenge(challenge: string): Promise<boolean> {
    const res = await this.request<{ valid: boolean }>('POST', '/v1/challenge/validate', {
      challenge,
    });
    return res.valid === true;
  }

  public async registerDocumentPolicy(policy: RegisteredDocumentPolicy): Promise<Uint8Array> {
    const res = await this.request<{ wrapSecretBase64: string }>(
      'POST',
      '/v1/documents/register',
      policy
    );
    return new Uint8Array(base64ToArrayBuffer(res.wrapSecretBase64));
  }

  public async getDocumentPolicy(
    documentId: string
  ): Promise<RegisteredDocumentPolicy | undefined> {
    try {
      return await this.request<RegisteredDocumentPolicy>(
        'GET',
        `/v1/documents/${encodeURIComponent(documentId)}/policy`
      );
    } catch (err) {
      if (String(err).includes('DOCUMENT_NOT_REGISTERED') || String(err).includes('404')) {
        return undefined;
      }
      throw err;
    }
  }

  public async listRegisteredPolicies(): Promise<RegisteredDocumentPolicy[]> {
    const res = await this.request<{ policies: RegisteredDocumentPolicy[] }>(
      'GET',
      '/v1/documents'
    );
    return res.policies;
  }

  public async processAuthorizationRequest(
    request: AuthorizationRequest
  ): Promise<AuthorityAuthResult> {
    return this.request<AuthorityAuthResult>('POST', '/v1/authorize', request);
  }

  public async releaseDocumentWrapSecretForGrant(
    grant: AuthorizationGrant
  ): Promise<Uint8Array | null> {
    try {
      const res = await this.request<{ wrapSecretBase64: string | null }>(
        'POST',
        '/v1/wrap-secret/release',
        { grant }
      );
      if (!res.wrapSecretBase64) return null;
      return new Uint8Array(base64ToArrayBuffer(res.wrapSecretBase64));
    } catch {
      return null;
    }
  }

  public async commitViewOnce(documentId: string, grantId: string): Promise<boolean> {
    const res = await this.request<{ committed: boolean }>('POST', '/v1/view-once/commit', {
      documentId,
      grantId,
    });
    return res.committed === true;
  }

  public async revokeDocument(
    documentId: string,
    reason?: string,
    revokedBy?: string
  ): Promise<DocumentRevocationState> {
    return this.request<DocumentRevocationState>('POST', '/v1/revoke', {
      documentId,
      reason,
      revokedBy,
    });
  }

  public async restoreDocument(documentId: string): Promise<DocumentRevocationState> {
    return this.request<DocumentRevocationState>('POST', '/v1/restore', { documentId });
  }

  public async getDocumentRevocationState(
    documentId: string
  ): Promise<DocumentRevocationState> {
    return this.request<DocumentRevocationState>(
      'GET',
      `/v1/documents/${encodeURIComponent(documentId)}/revocation`
    );
  }

  public async listRevoked(): Promise<DocumentRevocationState[]> {
    const res = await this.request<{ revoked: DocumentRevocationState[] }>('GET', '/v1/revoked');
    return res.revoked;
  }
}

/** Helper for encoding wrap secrets in HTTP JSON (server-side). */
export function encodeWrapSecretBase64(secret: Uint8Array): string {
  return arrayBufferToBase64(secret);
}
