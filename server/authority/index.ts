/**
 * TDCP Authorization Authority — HTTP(S) entrypoint.
 *
 *   node --experimental-strip-types server/authority/index.ts
 *
 * Env (core):
 *   TDCP_AUTHORITY_PORT (default 8787)
 *   TDCP_AUTHORITY_DATA_DIR (default ./data/authority)
 *   TDCP_SIGNING_BACKEND=file|kms-stub (default file — NOT production-grade)
 *
 * Admin auth (see docs/ADMIN_AUTH.md):
 *   TDCP_AUTHORITY_ADMIN_AUTH=token|oidc|mtls|oidc+mtls (default token)
 *   TDCP_AUTHORITY_ADMIN_TOKEN — Bearer fallback when mode=token only
 *   TDCP_OIDC_ISSUER / TDCP_OIDC_AUDIENCE / TDCP_OIDC_JWKS_URL / TDCP_OIDC_ADMIN_CLAIM
 *   TDCP_MTLS_CA_FILE / TDCP_MTLS_ALLOWED_CNS
 *   TDCP_AUTHORITY_TLS_CERT_FILE / TDCP_AUTHORITY_TLS_KEY_FILE — enable HTTPS
 */

import { join } from 'node:path';
import { startAuthorityHttpServer } from './http-server.ts';
import { readSigningBackendFromEnv } from './signing-backend.ts';
import { loadAdminAuthConfigFromEnv } from './admin-auth.ts';

const dataDir =
  process.env.TDCP_AUTHORITY_DATA_DIR || join(process.cwd(), 'data', 'authority');

const adminAuth = loadAdminAuthConfigFromEnv();
const { port, host, adminTokenConfigured, adminAuthMode, tlsEnabled } =
  await startAuthorityHttpServer({ dataDir, adminAuth });

const backend = readSigningBackendFromEnv();
const scheme = tlsEnabled ? 'https' : 'http';
console.log(
  `[tdcp-authority] listening on ${scheme}://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/`
);
console.log(`[tdcp-authority] data dir: ${dataDir}`);
console.log(`[tdcp-authority] signing backend: ${backend}`);
console.log(`[tdcp-authority] admin auth mode: ${adminAuthMode}`);
if (adminAuthMode === 'token') {
  console.log(
    `[tdcp-authority] admin token: ${adminTokenConfigured ? 'configured' : 'NOT configured (admin APIs return 503)'}`
  );
} else {
  console.log(
    '[tdcp-authority] static Bearer admin token DISABLED (mode is not token)'
  );
}
if (tlsEnabled) {
  console.log('[tdcp-authority] TLS enabled' + (adminAuthMode.includes('mtls') ? ' (mTLS client certs required for admin)' : ''));
}
if (backend === 'file') {
  console.log(
    '[tdcp-authority] WARNING: file JWK signing is NOT production-grade. See docs/AUTHORITY.md'
  );
} else {
  console.log(
    '[tdcp-authority] kms-stub documents the KMS hook — still NOT a real AWS KMS. See docs/AUTHORITY.md'
  );
}
