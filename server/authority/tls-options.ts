/**
 * Optional TLS / mTLS options for the Authority HTTP server.
 *
 * When TDCP_AUTHORITY_TLS_CERT_FILE + TDCP_AUTHORITY_TLS_KEY_FILE are set,
 * the server listens with HTTPS. For admin auth modes mtls|oidc+mtls, also set
 * TDCP_MTLS_CA_FILE and enable requestCert + rejectUnauthorized.
 *
 * See docs/ADMIN_AUTH.md and scripts/gen-dev-mtls.sh.
 */

import { readFileSync, existsSync } from 'node:fs';
import type { SecureContextOptions, TlsOptions } from 'node:tls';
import type { AdminAuthMode } from './admin-auth.ts';

export interface AuthorityTlsEnv {
  certFile?: string;
  keyFile?: string;
  caFile?: string;
  /** When true (mtls modes), require and verify client certificates */
  requestClientCert?: boolean;
}

export function readTlsEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>,
  mode?: AdminAuthMode
): AuthorityTlsEnv {
  const certFile = env.TDCP_AUTHORITY_TLS_CERT_FILE?.trim();
  const keyFile = env.TDCP_AUTHORITY_TLS_KEY_FILE?.trim();
  const caFile = env.TDCP_MTLS_CA_FILE?.trim();
  const requestClientCert =
    mode === 'mtls' ||
    mode === 'oidc+mtls' ||
    env.TDCP_MTLS_REQUEST_CERT === '1' ||
    env.TDCP_MTLS_REQUEST_CERT === 'true';
  return { certFile, keyFile, caFile, requestClientCert };
}

export function buildTlsOptions(tls: AuthorityTlsEnv): TlsOptions | null {
  if (!tls.certFile || !tls.keyFile) {
    return null;
  }
  if (!existsSync(tls.certFile)) {
    throw new Error(`TDCP_AUTHORITY_TLS_CERT_FILE not found: ${tls.certFile}`);
  }
  if (!existsSync(tls.keyFile)) {
    throw new Error(`TDCP_AUTHORITY_TLS_KEY_FILE not found: ${tls.keyFile}`);
  }
  const opts: SecureContextOptions & TlsOptions = {
    cert: readFileSync(tls.certFile),
    key: readFileSync(tls.keyFile),
  };
  if (tls.caFile) {
    if (!existsSync(tls.caFile)) {
      throw new Error(`TDCP_MTLS_CA_FILE not found: ${tls.caFile}`);
    }
    opts.ca = readFileSync(tls.caFile);
  }
  if (tls.requestClientCert) {
    if (!tls.caFile) {
      throw new Error(
        'mTLS admin auth requires TDCP_MTLS_CA_FILE (client CA) when requesting client certs'
      );
    }
    opts.requestCert = true;
    opts.rejectUnauthorized = true;
  }
  return opts;
}
