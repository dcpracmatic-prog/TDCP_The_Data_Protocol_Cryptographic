/**
 * Admin authentication for Authority admin endpoints
 * (register / revoke / restore / lists).
 *
 * Modes via TDCP_AUTHORITY_ADMIN_AUTH:
 *   token      — Bearer TDCP_AUTHORITY_ADMIN_TOKEN (default; local/dev fallback)
 *   oidc       — OAuth2/OIDC JWT (preferred for hosted)
 *   mtls       — client certificate (preferred for self-host / high assurance)
 *   oidc+mtls  — both OIDC JWT and client cert required
 *
 * When mode is oidc|mtls|oidc+mtls, the static Bearer admin token is disabled
 * (not accepted even if TDCP_AUTHORITY_ADMIN_TOKEN is set).
 *
 * Honesty: production-hardening of the admin surface — not a full enterprise IdP.
 */

import { createRemoteJWKSet, createLocalJWKSet, jwtVerify, type JWTPayload, type JSONWebKeySet } from 'jose';
import type { IncomingMessage } from 'node:http';
import type { TLSSocket } from 'node:tls';

export type AdminAuthMode = 'token' | 'oidc' | 'mtls' | 'oidc+mtls';

export type AdminAuthResult =
  | { ok: true; method: AdminAuthMode | 'token' }
  | { ok: false; status: 401 | 403 | 503; error: string };

export interface OidcAdminConfig {
  issuer: string;
  audience: string;
  /** Explicit JWKS URL; if omitted, discovered from issuer/.well-known/openid-configuration */
  jwksUrl?: string;
  /**
   * Claim that must authorize admin access.
   * - If payload[claim] === true or === 'true' → ok
   * - If payload[claim] is string === claim value expected via TDCP_OIDC_ADMIN_CLAIM_VALUE
   * - If payload[claim] is array containing adminClaim value (or 'tdcp_admin') → ok
   * - Also checks payload.roles / payload.scope / payload.scp for the claim string
   */
  adminClaim: string;
  /** Optional exact value required when adminClaim holds a string (default: treat claim name as role/scope token) */
  adminClaimValue?: string;
  /** Inject JWKS for tests (skips remote fetch) */
  localJwks?: JSONWebKeySet;
}

export interface MtlsAdminConfig {
  /** PEM CA used by HTTPS server (documented; check uses socket.authorized) */
  caFile?: string;
  /** Optional allowlist of certificate CNs (comma-separated env). Empty = any verified client cert. */
  allowedCns?: string[];
}

export interface AdminAuthConfig {
  mode: AdminAuthMode;
  /** Static Bearer token — only used when mode === 'token' */
  token?: string;
  oidc?: OidcAdminConfig;
  mtls?: MtlsAdminConfig;
}

const remoteJwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export function readAdminAuthModeFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): AdminAuthMode {
  const raw = (env.TDCP_AUTHORITY_ADMIN_AUTH || 'token').trim().toLowerCase();
  if (raw === 'token' || raw === 'oidc' || raw === 'mtls' || raw === 'oidc+mtls') {
    return raw;
  }
  throw new Error(
    `Invalid TDCP_AUTHORITY_ADMIN_AUTH="${raw}". Expected token|oidc|mtls|oidc+mtls`
  );
}

export function readAdminTokenFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): string | undefined {
  const t = env.TDCP_AUTHORITY_ADMIN_TOKEN;
  if (!t || !String(t).trim()) return undefined;
  return String(t).trim();
}

export function readOidcConfigFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): OidcAdminConfig | undefined {
  const issuer = env.TDCP_OIDC_ISSUER?.trim();
  const audience = env.TDCP_OIDC_AUDIENCE?.trim();
  if (!issuer || !audience) return undefined;
  return {
    issuer: issuer.replace(/\/$/, ''),
    audience,
    jwksUrl: env.TDCP_OIDC_JWKS_URL?.trim() || undefined,
    adminClaim: (env.TDCP_OIDC_ADMIN_CLAIM || 'tdcp_admin').trim(),
    adminClaimValue: env.TDCP_OIDC_ADMIN_CLAIM_VALUE?.trim() || undefined,
  };
}

export function readMtlsConfigFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): MtlsAdminConfig {
  const cns = env.TDCP_MTLS_ALLOWED_CNS?.trim();
  return {
    caFile: env.TDCP_MTLS_CA_FILE?.trim() || undefined,
    allowedCns: cns
      ? cns
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : undefined,
  };
}

export function loadAdminAuthConfigFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): AdminAuthConfig {
  const mode = readAdminAuthModeFromEnv(env);
  return {
    mode,
    token: mode === 'token' ? readAdminTokenFromEnv(env) : undefined,
    oidc: mode === 'oidc' || mode === 'oidc+mtls' ? readOidcConfigFromEnv(env) : undefined,
    mtls: mode === 'mtls' || mode === 'oidc+mtls' ? readMtlsConfigFromEnv(env) : undefined,
  };
}

export function extractBearerToken(req: IncomingMessage): string | undefined {
  const header = req.headers.authorization;
  if (!header || typeof header !== 'string') return undefined;
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) return undefined;
  return m[1].trim();
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}

export function isAdminPath(method: string, path: string): boolean {
  const p = path.split('?')[0] || '/';
  if (method === 'POST' && /^\/v1\/documents\/register\/?$/.test(p)) return true;
  if (method === 'GET' && /^\/v1\/documents\/?$/.test(p)) return true;
  if (method === 'POST' && /^\/v1\/revoke\/?$/.test(p)) return true;
  if (method === 'POST' && /^\/v1\/restore\/?$/.test(p)) return true;
  if (method === 'GET' && /^\/v1\/revoked\/?$/.test(p)) return true;
  return false;
}

/** Peer cert summary used by mTLS checks (unit-testable). */
export interface ClientCertInfo {
  authorized: boolean;
  authorizationError?: string;
  cn?: string;
  subjectAltNames?: string[];
  fingerprint256?: string;
  rawPresent: boolean;
}

export function extractClientCertInfo(req: IncomingMessage): ClientCertInfo | null {
  const sock = req.socket as TLSSocket;
  if (!sock || typeof sock.getPeerCertificate !== 'function') {
    return null;
  }
  // Plain HTTP sockets have no encrypted flag / getPeerCertificate may return {}
  const encrypted = Boolean((sock as TLSSocket).encrypted);
  if (!encrypted) {
    return null;
  }
  const authorized = Boolean(sock.authorized);
  const authorizationError =
    sock.authorizationError != null ? String(sock.authorizationError) : undefined;
  const cert = sock.getPeerCertificate(true);
  if (!cert || !cert.raw) {
    return {
      authorized,
      authorizationError,
      rawPresent: false,
    };
  }
  const cn =
    typeof cert.subject === 'object' && cert.subject && 'CN' in cert.subject
      ? String((cert.subject as { CN?: string }).CN || '')
      : undefined;
  const sanRaw = cert.subjectaltname;
  const subjectAltNames = sanRaw
    ? String(sanRaw)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : undefined;
  return {
    authorized,
    authorizationError,
    cn: cn || undefined,
    subjectAltNames,
    fingerprint256: cert.fingerprint256 ? String(cert.fingerprint256) : undefined,
    rawPresent: true,
  };
}

/**
 * Pure helper: verify client cert against policy (socket already did CA verify).
 * Exported for unit tests without spinning HTTPS.
 */
export function checkMtlsClientCert(
  info: ClientCertInfo | null,
  config: MtlsAdminConfig = {}
): AdminAuthResult {
  if (!info) {
    return { ok: false, status: 401, error: 'MTLS_CLIENT_CERT_REQUIRED' };
  }
  if (!info.rawPresent) {
    return { ok: false, status: 401, error: 'MTLS_CLIENT_CERT_REQUIRED' };
  }
  if (!info.authorized) {
    return {
      ok: false,
      status: 401,
      error: info.authorizationError
        ? `MTLS_UNAUTHORIZED:${info.authorizationError}`
        : 'MTLS_UNAUTHORIZED',
    };
  }
  const allowed = config.allowedCns;
  if (allowed && allowed.length > 0) {
    const cn = info.cn || '';
    const sanDns = (info.subjectAltNames || [])
      .filter((s) => s.toLowerCase().startsWith('dns:'))
      .map((s) => s.slice(4).trim());
    const candidates = [cn, ...sanDns].filter(Boolean);
    const match = candidates.some((c) => allowed.includes(c));
    if (!match) {
      return { ok: false, status: 403, error: 'MTLS_CN_NOT_ALLOWED' };
    }
  }
  return { ok: true, method: 'mtls' };
}

function hasAdminClaim(payload: JWTPayload, claim: string, claimValue?: string): boolean {
  const expected = claimValue ?? claim;
  const direct = payload[claim];
  if (direct === true || direct === 'true') return true;
  if (typeof direct === 'string' && direct === expected) return true;
  if (Array.isArray(direct) && direct.map(String).includes(expected)) return true;

  // Common role/scope containers
  for (const key of ['roles', 'role', 'permissions', 'groups'] as const) {
    const v = payload[key];
    if (typeof v === 'string' && (v === expected || v === claim)) return true;
    if (Array.isArray(v) && v.map(String).some((x) => x === expected || x === claim)) return true;
  }
  const scope = payload.scope ?? payload.scp;
  if (typeof scope === 'string') {
    const parts = scope.split(/\s+/);
    if (parts.includes(expected) || parts.includes(claim)) return true;
  }
  if (Array.isArray(scope) && scope.map(String).some((x) => x === expected || x === claim)) {
    return true;
  }
  return false;
}

async function resolveJwksUrl(oidc: OidcAdminConfig): Promise<string> {
  if (oidc.jwksUrl) return oidc.jwksUrl;
  const discoveryUrl = `${oidc.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
  const res = await fetch(discoveryUrl);
  if (!res.ok) {
    throw new Error(`OIDC_DISCOVERY_FAILED:${res.status}`);
  }
  const doc = (await res.json()) as { jwks_uri?: string };
  if (!doc.jwks_uri) {
    throw new Error('OIDC_DISCOVERY_MISSING_JWKS_URI');
  }
  return doc.jwks_uri;
}

async function getJwksVerifier(oidc: OidcAdminConfig) {
  if (oidc.localJwks) {
    return createLocalJWKSet(oidc.localJwks);
  }
  const jwksUrl = await resolveJwksUrl(oidc);
  let cached = remoteJwksCache.get(jwksUrl);
  if (!cached) {
    cached = createRemoteJWKSet(new URL(jwksUrl));
    remoteJwksCache.set(jwksUrl, cached);
  }
  return cached;
}

export async function verifyOidcAdminJwt(
  bearerToken: string | undefined,
  oidc: OidcAdminConfig
): Promise<AdminAuthResult> {
  if (!bearerToken) {
    return { ok: false, status: 401, error: 'OIDC_TOKEN_REQUIRED' };
  }
  try {
    const jwks = await getJwksVerifier(oidc);
    const { payload } = await jwtVerify(bearerToken, jwks, {
      issuer: oidc.issuer,
      audience: oidc.audience,
    });
    if (!hasAdminClaim(payload, oidc.adminClaim, oidc.adminClaimValue)) {
      return { ok: false, status: 403, error: 'OIDC_ADMIN_CLAIM_MISSING' };
    }
    return { ok: true, method: 'oidc' };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // jose throws for expired/invalid — map to 401
    if (msg.includes('OIDC_DISCOVERY')) {
      return { ok: false, status: 503, error: msg };
    }
    return { ok: false, status: 401, error: 'OIDC_TOKEN_INVALID' };
  }
}

function requireTokenAuth(
  req: IncomingMessage,
  configuredToken: string | undefined
): AdminAuthResult {
  if (!configuredToken) {
    return { ok: false, status: 503, error: 'ADMIN_TOKEN_NOT_CONFIGURED' };
  }
  const presented = extractBearerToken(req);
  if (!presented || !safeEqual(presented, configuredToken)) {
    return { ok: false, status: 401, error: 'UNAUTHORIZED' };
  }
  return { ok: true, method: 'token' };
}

/**
 * Primary admin gate. Async because OIDC JWKS verification may fetch keys.
 *
 * Backward-compatible overload: requireAdminAuth(req, tokenString) still works
 * as token-mode (used by older tests / callers).
 */
export async function requireAdminAuth(
  req: IncomingMessage,
  configOrToken?: AdminAuthConfig | string
): Promise<AdminAuthResult> {
  let config: AdminAuthConfig;
  if (typeof configOrToken === 'string' || configOrToken === undefined) {
    // Legacy: second arg is the bearer token (token mode only)
    config = {
      mode: 'token',
      token:
        typeof configOrToken === 'string'
          ? configOrToken
          : readAdminTokenFromEnv(),
    };
  } else {
    config = configOrToken;
  }

  const mode = config.mode;

  if (mode === 'token') {
    return requireTokenAuth(req, config.token);
  }

  if (mode === 'oidc') {
    if (!config.oidc?.issuer || !config.oidc?.audience) {
      return { ok: false, status: 503, error: 'OIDC_NOT_CONFIGURED' };
    }
    return verifyOidcAdminJwt(extractBearerToken(req), config.oidc);
  }

  if (mode === 'mtls') {
    return checkMtlsClientCert(extractClientCertInfo(req), config.mtls || {});
  }

  // oidc+mtls — both required
  if (!config.oidc?.issuer || !config.oidc?.audience) {
    return { ok: false, status: 503, error: 'OIDC_NOT_CONFIGURED' };
  }
  const mtls = checkMtlsClientCert(extractClientCertInfo(req), config.mtls || {});
  if (!mtls.ok) return mtls;
  const oidc = await verifyOidcAdminJwt(extractBearerToken(req), config.oidc);
  if (!oidc.ok) return oidc;
  return { ok: true, method: 'oidc+mtls' };
}

/** Sync legacy helper used only when callers pass a plain token string. */
export function requireAdminAuthSync(
  req: IncomingMessage,
  configuredToken: string | undefined = readAdminTokenFromEnv()
): AdminAuthResult {
  return requireTokenAuth(req, configuredToken);
}

/** Clear remote JWKS cache (tests). */
export function clearOidcJwksCache(): void {
  remoteJwksCache.clear();
}
