import { readFileSync } from 'node:fs';
import type { PoolConfig } from 'pg';

/** TLS policy shared by Better Auth's production pool and the migration tool. */
export function pgPoolConfig(connectionString: string): PoolConfig {
  const isLocal = /@(localhost|127\.0\.0\.1|\[::1\])[:/]/.test(connectionString);
  if (isLocal || process.env.DATABASE_SSL === 'disable') return { connectionString };
  const caPath = process.env.DATABASE_CA_CERT?.trim();
  return {
    connectionString: connectionString.replace(/([?&])sslmode=[^&]*&?/, '$1').replace(/[?&]$/, ''),
    max: Number(process.env.DATABASE_POOL_MAX || 5),
    ssl: caPath
      ? { ca: readFileSync(caPath, 'utf8'), rejectUnauthorized: true }
      // Use the platform trust store when no private CA is supplied; never
      // silently downgrade certificate verification on a hosted database.
      : { rejectUnauthorized: true },
  };
}
