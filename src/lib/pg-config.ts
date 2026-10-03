import type { PoolConfig } from 'pg';

/**
 * Shared node-postgres configuration for Neon/Postgres deployments.
 * The connection string remains the only credential; pool sizing is kept small
 * for serverless instances so idle connections do not accumulate.
 */
export function pgPoolConfig(connectionString: string): PoolConfig {
  if (!connectionString.trim()) throw new Error('DATABASE_URL is empty.');
  const max = Math.max(1, Number(process.env.PG_POOL_MAX || 5));
  return {
    connectionString,
    max: Number.isFinite(max) ? max : 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    allowExitOnIdle: true,
  };
}
