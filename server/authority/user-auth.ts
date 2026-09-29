/**
 * End-user authentication for the Authority's Gatekeeper endpoints.
 *
 * The web app (Better Auth `jwt` plugin) issues short-lived JWTs for the
 * signed-in user. The Authority verifies them against the app's JWKS and uses
 * the verified `sub` as `subjectUserId` — the client can never choose it.
 *
 * Env:
 *   TDCP_USER_AUTH=off|required          (default off → legacy anonymous Gatekeeper)
 *   TDCP_USER_JWKS_URL=https://app/api/auth/jwks
 *   TDCP_USER_ISSUER=https://app          (must match BETTER_AUTH_URL)
 *   TDCP_USER_AUDIENCE=tdcp-authority
 */

import type { IncomingMessage } from 'node:http';
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  jwtVerify,
  type JSONWebKeySet,
  type JWTVerifyGetKey,
} from 'jose';

export const USER_TOKEN_HEADER = 'x-tdcp-user-token';
export const DEFAULT_USER_AUDIENCE = 'tdcp-authority';

export type UserAuthMode = 'off' | 'required';

export interface UserAuthConfig {
  mode: UserAuthMode;
  issuer?: string;
  audience?: string;
  jwksUrl?: string;
  /** Inline JWKS (tests / pinned keys). Takes precedence over jwksUrl. */
  jwks?: JSONWebKeySet;
  /** Max clock skew in seconds. */
  clockToleranceSec?: number;
}

export interface VerifiedUser {
  userId: string;
  email?: string;
  emailVerified?: boolean;
}

export type UserAuthResult =
  | { ok: true; user: VerifiedUser | null }
  | { ok: false; status: 401; error: 'USER_AUTH_REQUIRED' | 'USER_TOKEN_INVALID' };

export function loadUserAuthConfigFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): UserAuthConfig {
  const raw = (env.TDCP_USER_AUTH || 'off').trim().toLowerCase();
  const mode: UserAuthMode = raw === 'required' ? 'required' : 'off';
  return {
    mode,
    issuer: env.TDCP_USER_ISSUER?.trim() || undefined,
    audience: env.TDCP_USER_AUDIENCE?.trim() || DEFAULT_USER_AUDIENCE,
    jwksUrl: env.TDCP_USER_JWKS_URL?.trim() || undefined,
  };
}

export function assertUserAuthConfig(config: UserAuthConfig): void {
  if (config.mode !== 'required') return;
  if (!config.jwks && !config.jwksUrl) {
    throw new Error('TDCP_USER_AUTH=required needs TDCP_USER_JWKS_URL');
  }
  if (!config.issuer) {
    throw new Error('TDCP_USER_AUTH=required needs TDCP_USER_ISSUER');
  }
  if (config.jwksUrl) {
    const u = new URL(config.jwksUrl);
    const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '::1';
    if (u.protocol !== 'https:' && !local) {
      throw new Error('TDCP_USER_JWKS_URL must use https outside localhost');
    }
  }
}

export function createUserTokenVerifier(config: UserAuthConfig) {
  assertUserAuthConfig(config);
  let keySet: JWTVerifyGetKey | null = null;
  if (config.mode === 'required') {
    keySet = config.jwks
      ? createLocalJWKSet(config.jwks)
      : createRemoteJWKSet(new URL(config.jwksUrl!), {
          cooldownDuration: 30_000,
          cacheMaxAge: 10 * 60_000,
        });
  }

  async function verifyToken(token: string): Promise<VerifiedUser | null> {
    if (!keySet) return null;
    try {
      const { payload } = await jwtVerify(token, keySet, {
        issuer: config.issuer,
        audience: config.audience ?? DEFAULT_USER_AUDIENCE,
        algorithms: ['EdDSA', 'ES256', 'RS256', 'PS256'],
        clockTolerance: config.clockToleranceSec ?? 30,
        requiredClaims: ['sub', 'exp', 'iat'],
      });
      if (typeof payload.sub !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(payload.sub)) {
        return null;
      }
      // Reject long-lived tokens even if the issuer is misconfigured.
      if (typeof payload.exp === 'number' && typeof payload.iat === 'number') {
        if (payload.exp - payload.iat > 60 * 60) return null;
      }
      return {
        userId: payload.sub,
        email: typeof payload.email === 'string' ? payload.email : undefined,
        emailVerified: payload.email_verified === true,
      };
    } catch {
      return null;
    }
  }

  /**
   * Resolve the caller. In `required` mode a valid token is mandatory; in
   * `off` mode tokens are ignored and the Gatekeeper stays anonymous.
   */
  async function authenticate(req: IncomingMessage): Promise<UserAuthResult> {
    if (config.mode !== 'required') return { ok: true, user: null };
    const header = req.headers[USER_TOKEN_HEADER];
    const token = Array.isArray(header) ? header[0] : header;
    if (!token) return { ok: false, status: 401, error: 'USER_AUTH_REQUIRED' };
    const user = await verifyToken(token.trim());
    if (!user) return { ok: false, status: 401, error: 'USER_TOKEN_INVALID' };
    return { ok: true, user };
  }

  return { mode: config.mode, authenticate, verifyToken };
}

export type UserTokenVerifier = ReturnType<typeof createUserTokenVerifier>;
