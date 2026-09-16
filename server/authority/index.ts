/**
 * TDCP Authorization Authority — HTTP entrypoint.
 *
 *   node --experimental-strip-types server/authority/index.ts
 *
 * Env:
 *   TDCP_AUTHORITY_PORT (default 8787)
 *   TDCP_AUTHORITY_DATA_DIR (default ./data/authority)
 *   TDCP_AUTHORITY_ADMIN_TOKEN (required for register/revoke admin APIs)
 *   TDCP_SIGNING_BACKEND=file|kms-stub (default file — NOT production-grade)
 */

import { join } from 'node:path';
import { startAuthorityHttpServer } from './http-server.ts';
import { readSigningBackendFromEnv } from './signing-backend.ts';

const dataDir =
  process.env.TDCP_AUTHORITY_DATA_DIR || join(process.cwd(), 'data', 'authority');

const { port, host, adminTokenConfigured } = await startAuthorityHttpServer({ dataDir });

const backend = readSigningBackendFromEnv();
console.log(
  `[tdcp-authority] listening on http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/`
);
console.log(`[tdcp-authority] data dir: ${dataDir}`);
console.log(`[tdcp-authority] signing backend: ${backend}`);
console.log(
  `[tdcp-authority] admin token: ${adminTokenConfigured ? 'configured' : 'NOT configured (admin APIs return 503)'}`
);
if (backend === 'file') {
  console.log(
    '[tdcp-authority] WARNING: file JWK signing is NOT production-grade. See docs/AUTHORITY.md'
  );
} else {
  console.log(
    '[tdcp-authority] kms-stub documents the KMS hook — still NOT a real AWS KMS. See docs/AUTHORITY.md'
  );
}
