/**
 * TDCP Authorization Authority — HTTP entrypoint.
 *
 *   node --experimental-strip-types server/authority/index.ts
 *
 * Env:
 *   TDCP_AUTHORITY_PORT (default 8787)
 *   TDCP_AUTHORITY_DATA_DIR (default ./data/authority)
 */

import { join } from 'node:path';
import { startAuthorityHttpServer } from './http-server.ts';

const dataDir =
  process.env.TDCP_AUTHORITY_DATA_DIR || join(process.cwd(), 'data', 'authority');

const { port, host } = await startAuthorityHttpServer({ dataDir });

console.log(
  `[tdcp-authority] listening on http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/`
);
console.log(`[tdcp-authority] data dir: ${dataDir}`);
console.log(
  '[tdcp-authority] DEVELOPMENT durable file store — NOT an HSM/KMS. See docs/AUTHORITY.md'
);
