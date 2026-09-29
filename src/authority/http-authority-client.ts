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
import type { UsbHsmDeviceInfo } from '../core/authorization/usb-hsm.ts';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';
import { base64ToArrayBuffer, arrayBufferToBase64 } from '../core/crypto/primitives.ts';
import type {
  AuthorityAuthResult,
  AuthorizationAuthority,
  AuthorityPublicInfo,
} from './types.ts';

export interface HttpAuthorityClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  /**
   * Bearer token for admin endpoints (register / revoke / restore / lists).
   * Prefer process env TDCP_AUTHORITY_ADMIN_TOKEN on issuer tooling — do NOT
   * ship this token in public browser builds for production.
   */
  adminToken?: string;
  /**
   * Short-lived end-user JWT (Better Auth `/api/auth/token`). When set, it is
   * sent on every Gatekeeper call as `x-tdcp-user-token`, and document
   * registration / revoke / restore use the owner-scoped endpoints instead of
   * the admin ones — no admin token in the browser.
   */
  getUserToken?: () => Promise<string | null>;
  /** Whether owner-scoped endpoints should be used right now (default: getUserToken set). */
  isUserBound?: () => boolean;
}

export const USER_TOKEN_HEADER = 'x-tdcp-user-token';

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
  private readonly adminToken?: string;
  private readonly getUserToken?: () => Promise<string | null>;
  private readonly userBound: () => boolean;
  private cachedInfo: AuthorityPublicInfo | null = null;
  private cachedPublicKey: CryptoKey | null = null;

  constructor(options: HttpAuthorityClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    // Bind to globalThis — unbound fetch throws Illegal invocation in some browsers/bundles
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.adminToken = options.adminToken;
    this.getUserToken = options.getUserToken;
    const hasFetcher = Boolean(options.getUserToken);
    this.userBound = options.isUserBound ?? (() => hasFetcher);
  }

  /** True when this client acts for a signed-in user (owner-scoped endpoints). */
  public isUserBound(): boolean {
    return this.userBound();
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    opts?: { admin?: boolean }
  ): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (opts?.admin && this.adminToken) {
      headers['authorization'] = `Bearer ${this.adminToken}`;
    }
    if (!opts?.admin && this.getUserToken) {
      const token = await this.getUserToken();
      if (token) headers[USER_TOKEN_HEADER] = token;
    }
    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: Object.keys(headers).length ? headers : undefined,
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

  /** Subject is derived server-side from the user token; the argument is ignored. */
  public async issueChallenge(_subjectUserId?: string): Promise<string> {
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
    const res = this.isUserBound()
      ? await this.request<{ wrapSecretBase64: string }>('POST', '/v1/documents', policy)
      : await this.request<{ wrapSecretBase64: string }>(
          'POST',
          '/v1/documents/register',
          policy,
          { admin: true }
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
      '/v1/documents',
      undefined,
      { admin: true }
    );
    return res.policies;
  }

  public async processAuthorizationRequest(
    request: AuthorizationRequest
  ): Promise<AuthorityAuthResult> {
    return this.request<AuthorityAuthResult>('POST', '/v1/authorize', request);
  }

  public async releaseDocumentWrapSecretForGrant(
    grant: AuthorizationGrant,
    _subjectUserId?: string
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

  public async commitViewOnce(
    documentId: string,
    grantId: string,
    _subjectUserId?: string
  ): Promise<boolean> {
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
    if (this.isUserBound()) {
      return this.request<DocumentRevocationState>(
        'POST',
        `/v1/documents/${encodeURIComponent(documentId)}/revoke`,
        { reason }
      );
    }
    return this.request<DocumentRevocationState>(
      'POST',
      '/v1/revoke',
      { documentId, reason, revokedBy },
      { admin: true }
    );
  }

  public async restoreDocument(documentId: string): Promise<DocumentRevocationState> {
    if (this.isUserBound()) {
      return this.request<DocumentRevocationState>(
        'POST',
        `/v1/documents/${encodeURIComponent(documentId)}/restore`,
        {}
      );
    }
    return this.request<DocumentRevocationState>(
      'POST',
      '/v1/restore',
      { documentId },
      { admin: true }
    );
  }

  public async getDocumentRevocationState(
    documentId: string
  ): Promise<DocumentRevocationState> {
    return this.request<DocumentRevocationState>(
      'GET',
      `/v1/documents/${encodeURIComponent(documentId)}/revocation`
    );
  }

  /** Documents the signed-in user owns or can open. */
  public async listMyDocuments(): Promise<RegisteredDocumentPolicy[]> {
    const res = await this.request<{ policies: RegisteredDocumentPolicy[] }>('GET', '/v1/me/documents');
    return res.policies;
  }

  /** Owner-only: replace the list of users allowed to open the document. */
  public async updateDocumentAcl(
    documentId: string,
    allowedUserIds: string[]
  ): Promise<RegisteredDocumentPolicy> {
    return this.request<RegisteredDocumentPolicy>(
      'POST',
      `/v1/documents/${encodeURIComponent(documentId)}/acl`,
      { allowedUserIds }
    );
  }

  // ── USB-HSM (the user's hardware ID) ────────────────────────────────────
  public async listUsbHsm(): Promise<UsbHsmDeviceInfo[]> {
    const res = await this.request<{ devices: UsbHsmDeviceInfo[] }>('GET', '/v1/me/usb-hsm');
    return res.devices;
  }

  public async usbHsmRegistrationOptions(opts: {
    label?: string;
    replaceDeviceId?: string;
  }): Promise<PublicKeyCredentialCreationOptionsJSON> {
    return this.request('POST', '/v1/me/usb-hsm/registration-options', opts);
  }

  public async registerUsbHsm(response: RegistrationResponseJSON): Promise<UsbHsmDeviceInfo> {
    return this.request('POST', '/v1/me/usb-hsm/register', { response });
  }

  public async usbHsmAuthenticationOptions(): Promise<{
    rpId: string;
    allowCredentials: Array<{ id: string; transports: string[] }>;
  }> {
    return this.request('POST', '/v1/me/usb-hsm/authentication-options', {});
  }

  public async changeUsbHsmStatus(
    deviceId: string,
    action: 'revoke' | 'suspend' | 'reactivate'
  ): Promise<UsbHsmDeviceInfo> {
    return this.request('POST', `/v1/me/usb-hsm/${encodeURIComponent(deviceId)}/${action}`, {});
  }

  public async listRevoked(): Promise<DocumentRevocationState[]> {
    const res = await this.request<{ revoked: DocumentRevocationState[] }>(
      'GET',
      '/v1/revoked',
      undefined,
      { admin: true }
    );
    return res.revoked;
  }
}

/** Helper for encoding wrap secrets in HTTP JSON (server-side). */
export function encodeWrapSecretBase64(secret: Uint8Array): string {
  return arrayBufferToBase64(secret);
}
