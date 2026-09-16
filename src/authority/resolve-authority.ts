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

export function resolveAuthorizationAuthority(options?: {
  authorityUrl?: string;
  oracle?: AuthorizationOracle;
  fetchImpl?: typeof fetch;
}): AuthorizationAuthority {
  const url = options?.authorityUrl ?? readAuthorityUrlFromEnv();
  if (url) {
    return new HttpAuthorityClient({
      baseUrl: url,
      fetchImpl: options?.fetchImpl,
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
