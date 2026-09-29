/**
 * Resolve which Authorization Authority the runtime should use.
 *
 * - TDCP_AUTHORITY_URL / VITE_TDCP_AUTHORITY_URL → HttpAuthorityClient
 * - otherwise → InProcessAuthority (browser Oracle parity / current demo)
 */

import { AuthorizationOracle, globalAuthorizationOracle } from '../oracle/authorization-oracle.ts';
import { HttpAuthorityClient } from './http-authority-client.ts';
import { InProcessAuthority } from './in-process-authority.ts';
import type { AuthorizationAuthority } from './types.ts';
import { getUserToken, hasUserTokenSource } from './user-token.ts';

export function readAuthorityUrlFromEnv(
  env: Record<string, string | undefined> = typeof process !== 'undefined'
    ? (process.env as Record<string, string | undefined>)
    : {}
): string | undefined {
  const url =
    env.TDCP_AUTHORITY_URL ||
    env.VITE_TDCP_AUTHORITY_URL ||
    (typeof import.meta !== 'undefined'
      ? (import.meta as ImportMeta & { env?: Record<string, string> }).env?.VITE_TDCP_AUTHORITY_URL
      : undefined);
  if (!url || !String(url).trim()) return undefined;
  return String(url).trim().replace(/\/$/, '');
}

function readAdminTokenFromEnv(
  env: Record<string, string | undefined> = typeof process !== 'undefined'
    ? (process.env as Record<string, string | undefined>)
    : {}
): string | undefined {
  // Server/issuer tooling: TDCP_AUTHORITY_ADMIN_TOKEN.
  // Browser: with accounts on (VITE_AUTH_ENABLED != "false") the admin token is
  // NEVER read — users register/revoke their own documents with their session.
  // The VITE_ fallback survives only for the anonymous local demo.
  const viteEnv =
    typeof import.meta !== 'undefined'
      ? (import.meta as ImportMeta & { env?: Record<string, string> }).env
      : undefined;
  const accountsOn = viteEnv ? viteEnv.VITE_AUTH_ENABLED !== 'false' : false;
  const t =
    env.TDCP_AUTHORITY_ADMIN_TOKEN ||
    (!accountsOn ? viteEnv?.VITE_TDCP_AUTHORITY_ADMIN_TOKEN : undefined);
  if (!t || !String(t).trim()) return undefined;
  return String(t).trim();
}

export function resolveAuthorizationAuthority(options?: {
  authorityUrl?: string;
  oracle?: AuthorizationOracle;
  fetchImpl?: typeof fetch;
  adminToken?: string;
}): AuthorizationAuthority {
  const url = options?.authorityUrl ?? readAuthorityUrlFromEnv();
  if (url) {
    return new HttpAuthorityClient({
      baseUrl: url,
      fetchImpl: options?.fetchImpl,
      adminToken: options?.adminToken ?? readAdminTokenFromEnv(),
      // Signed-in user's identity (installed by authContext). No-op when absent.
      getUserToken,
      isUserBound: hasUserTokenSource,
    });
  }
  return new InProcessAuthority(options?.oracle ?? globalAuthorizationOracle);
}

let cachedDefault: AuthorizationAuthority | null = null;

/** Lazily resolved default for the process (tests may call resetDefaultAuthority). */
export function getDefaultAuthority(): AuthorizationAuthority {
  if (!cachedDefault) {
    cachedDefault = resolveAuthorizationAuthority();
  }
  return cachedDefault;
}

export function resetDefaultAuthority(): void {
  cachedDefault = null;
}

export function setDefaultAuthority(authority: AuthorizationAuthority): void {
  cachedDefault = authority;
}
