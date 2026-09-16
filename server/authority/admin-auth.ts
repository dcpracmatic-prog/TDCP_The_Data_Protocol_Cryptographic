/**
 * Bearer-token gate for Authority admin endpoints (register / revoke / restore / lists).
 *
 * Env: TDCP_AUTHORITY_ADMIN_TOKEN — required value for Authorization: Bearer <token>
 * Fail closed: missing/mismatched token → 401. Unconfigured token → 503.
 */

import type { IncomingMessage } from 'node:http';

export type AdminAuthResult =
  | { ok: true }
  | { ok: false; status: 401 | 503; error: string };

export function readAdminTokenFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): string | undefined {
  const t = env.TDCP_AUTHORITY_ADMIN_TOKEN;
  if (!t || !String(t).trim()) return undefined;
  return String(t).trim();
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

export function requireAdminAuth(
  req: IncomingMessage,
  configuredToken: string | undefined = readAdminTokenFromEnv()
): AdminAuthResult {
  if (!configuredToken) {
    return { ok: false, status: 503, error: 'ADMIN_TOKEN_NOT_CONFIGURED' };
  }
  const presented = extractBearerToken(req);
  if (!presented || !safeEqual(presented, configuredToken)) {
    return { ok: false, status: 401, error: 'UNAUTHORIZED' };
  }
  return { ok: true };
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
