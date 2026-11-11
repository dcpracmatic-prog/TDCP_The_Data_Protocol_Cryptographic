/**
 * Durable Authority state in Postgres (P0-1).
 *
 * Implements EXACTLY the same interface as DurableJsonAuthorityStore
 * (see ./durable-store.ts) over the same snapshot shape, so the Authority
 * service cannot tell which backend it is talking to. Select it with:
 *
 *   TDCP_AUTHORITY_STORE=postgres  +  DATABASE_URL=postgres://...
 *
 * The file store stays as the local-dev fallback (TDCP_AUTHORITY_STORE=file,
 * the default).
 *
 * Schema: migrations/0005_authority_store.sql — one row per policy / wrap
 * secret / revocation state / consumed operation / consumed grant / active
 * challenge / challenge subject / USB-HSM device, plus a singleton
 * authority_meta row for the key id + signing key material. save() replaces
 * the whole snapshot inside ONE transaction (same whole-snapshot semantics
 * as the atomic JSON rewrite of the file store), so a crash can never leave
 * half a snapshot behind. Primary keys make single-use grants and consumed
 * operations collide instead of duplicating at the storage layer too.
 *
 * SECURITY SEMANTICS ARE UNCHANGED: Gatekeeper is still the only unlock path;
 * this file only moves WHERE the state lives. No crypto primitive changes.
 * Signing private JWK at rest follows the file store exactly (plaintext only
 * in dev, AES-256-GCM blob when TDCP_AUTHORITY_KEY_PASSPHRASE is set).
 * This is still NOT HSM-grade.
 *
 * NOTE: the sandbox blocks direct Postgres connections on port 5432, so this
 * store cannot be live-tested from the sandbox. Its integration tests run
 * against an embedded PGLite instance (same SQL), and the real Supabase
 * database is verified through the Management API (see docs/AUTHORITY.md).
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pg from 'pg';
import type {
  AuthorityStoreKind,
  DurableAuthoritySnapshot,
  DurableAuthorityStore,
} from './durable-store.ts';
import {
  capSnapshotForPersist,
  emptyAuthoritySnapshot,
  readAuthorityStoreKindFromEnv,
  resolveSnapshotPrivateJwk,
  sealSnapshotPrivateJwk,
  DurableJsonAuthorityStore,
} from './durable-store.ts';

/** Minimal SQL surface the store needs — satisfied by pg.Pool and by PGlite. */
export interface AuthorityStoreQueryClient {
  query(
    text: string,
    params?: unknown[]
  ): Promise<{ rows: Record<string, unknown>[] }>;
  /** Multi-statement executor (PGlite `.exec`); pg runs multi-statement text via query(). */
  exec?(text: string): Promise<unknown>;
  /** Pooled client for one transaction (pg); absent on single-connection clients. */
  connect?(): Promise<{
    query(
      text: string,
      params?: unknown[]
    ): Promise<{ rows: Record<string, unknown>[] }>;
    release(): void;
  }>;
}

export interface DurablePostgresAuthorityStoreOptions {
  dataDir: string;
  /** Defaults to process.env.DATABASE_URL. */
  connectionString?: string;
  /** Inject a client (tests use a PGLite instance). When set, no pool is created. */
  client?: AuthorityStoreQueryClient;
}

/** Mirrors scripts/migrate.mjs (TLS for Supabase; CA-verified when set). */
function poolOptions(connectionString: string): pg.PoolConfig {
  const isLocal = /@(localhost|127\.0\.0\.1|\[::1\])[:/]/.test(connectionString);
  if (isLocal || process.env.DATABASE_SSL === 'disable') {
    return { connectionString };
  }
  const caPath = process.env.DATABASE_CA_CERT?.trim();
  const clean = connectionString
    .replace(/([?&])sslmode=[^&]*&?/, '$1')
    .replace(/[?&]$/, '');
  return {
    connectionString: clean,
    ssl: caPath
      ? { ca: readFileSync(caPath, 'utf8'), rejectUnauthorized: true }
      : { rejectUnauthorized: false },
  };
}

function migrationSql(): string {
  const path = join(
    dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
    'migrations',
    '0005_authority_store.sql'
  );
  return readFileSync(path, 'utf8');
}

/** pg returns int8 as string, PGlite as BigInt — both become a plain number. */
function toNumber(value: unknown): number {
  return typeof value === 'bigint' ? Number(value) : Number(value);
}

/** pg/PGlite parse JSONB into objects; be tolerant if a driver returns text. */
function asJson<T>(value: unknown): T {
  if (typeof value === 'string') return JSON.parse(value) as T;
  return value as T;
}

function jsonParam(value: unknown): string {
  return JSON.stringify(value ?? null);
}

const META_ID = 1;

export class DurablePostgresAuthorityStore implements DurableAuthorityStore {
  public readonly kind: AuthorityStoreKind = 'postgres';
  public readonly dataDir: string;
  private readonly client: AuthorityStoreQueryClient;
  private readonly pool: pg.Pool | null;
  private schemaEnsured = false;

  constructor(options: DurablePostgresAuthorityStoreOptions) {
    this.dataDir = options.dataDir;
    if (options.client) {
      this.client = options.client;
      this.pool = null;
    } else {
      const connectionString = (options.connectionString ??
        process.env.DATABASE_URL ??
        '').trim();
      if (!connectionString) {
        throw new Error(
          'TDCP_AUTHORITY_STORE=postgres requiere DATABASE_URL (o un cliente inyectado)'
        );
      }
      this.pool = new pg.Pool({ ...poolOptions(connectionString), max: 5 });
      this.client = this.pool;
    }
  }

  /**
   * Apply migrations/0005_authority_store.sql if the tables are missing.
   * Idempotent (every statement is IF NOT EXISTS); safe to call on every
   * startup. Deploy-time `scripts/migrate.mjs` applies the same file and
   * records it in _migrations — this is only the standalone-Authority path.
   */
  public async ensureSchema(): Promise<void> {
    if (this.schemaEnsured) return;
    const sql = migrationSql();
    if (this.client.exec) {
      await this.client.exec(sql);
    } else {
      await this.client.query(sql);
    }
    this.schemaEnsured = true;
  }

  public async load(): Promise<DurableAuthoritySnapshot> {
    await this.ensureSchema();
    // Sequential reads: PGLite is single-connection, and a snapshot load at
    // startup has no need for parallelism.
    const meta = await this.client.query('SELECT * FROM authority_meta WHERE id = $1', [META_ID]);
    const policies = await this.client.query(
      'SELECT document_id, policy FROM authority_policies ORDER BY document_id'
    );
    const wraps = await this.client.query(
      'SELECT document_id, wrap_secret_b64 FROM authority_wrap_secrets'
    );
    const revocation = await this.client.query(
      'SELECT state FROM authority_revocation ORDER BY document_id'
    );
    const consumed = await this.client.query(
      'SELECT operation_id, challenge, grant_id, document_id, device_id, consumed_at ' +
        'FROM authority_consumed_operations ORDER BY consumed_at, operation_id'
    );
    const grants = await this.client.query(
      'SELECT grant_id FROM authority_consumed_grants ORDER BY grant_id'
    );
    const challenges = await this.client.query(
      'SELECT challenge, registered_at FROM authority_challenges ORDER BY registered_at'
    );
    const subjects = await this.client.query(
      'SELECT challenge, subject_user_id FROM authority_challenge_subjects'
    );
    const devices = await this.client.query(
      'SELECT record FROM authority_usb_hsm_devices ORDER BY device_id'
    );

    const snapshot = emptyAuthoritySnapshot();
    const metaRow = meta.rows[0];
    if (!metaRow) return snapshot;
    snapshot.keyId = String(metaRow.key_id ?? snapshot.keyId);
    snapshot.signingPrivateJwk = asJson<JsonWebKey | null>(metaRow.signing_private_jwk);
    snapshot.signingPrivateJwkEnc = asJson(metaRow.signing_private_jwk_enc);
    snapshot.signingPublicJwk = asJson<JsonWebKey | null>(metaRow.signing_public_jwk);
    snapshot.policies = policies.rows.map((r) => asJson(r.policy));
    snapshot.wrapSecretsBase64 = Object.fromEntries(
      wraps.rows.map((r) => [String(r.document_id), String(r.wrap_secret_b64)])
    );
    snapshot.revocation = revocation.rows.map((r) => asJson(r.state));
    snapshot.consumedOperations = consumed.rows.map((r) => ({
      operationId: String(r.operation_id),
      challenge: String(r.challenge),
      grantId: String(r.grant_id),
      documentId: String(r.document_id),
      deviceId: String(r.device_id),
      consumedAt: toNumber(r.consumed_at),
    }));
    snapshot.consumedGrantIds = grants.rows.map((r) => String(r.grant_id));
    snapshot.activeChallenges = challenges.rows.map((r) => ({
      challenge: String(r.challenge),
      registeredAt: toNumber(r.registered_at),
    }));
    snapshot.challengeSubjects = subjects.rows.map((r) => ({
      challenge: String(r.challenge),
      subjectUserId: String(r.subject_user_id),
    }));
    snapshot.usbHsmDevices = devices.rows.map((r) => asJson(r.record));
    return snapshot;
  }

  public async save(input: DurableAuthoritySnapshot): Promise<void> {
    await this.ensureSchema();
    const snapshot = capSnapshotForPersist(input);
    await this.withTransaction(async (q) => {
      // Whole-snapshot replace, like the atomic JSON rewrite of the file
      // store: a crash mid-save can never leave half a snapshot behind.
      await q('DELETE FROM authority_policies');
      await q('DELETE FROM authority_wrap_secrets');
      await q('DELETE FROM authority_revocation');
      await q('DELETE FROM authority_consumed_operations');
      await q('DELETE FROM authority_consumed_grants');
      await q('DELETE FROM authority_challenges');
      await q('DELETE FROM authority_challenge_subjects');
      await q('DELETE FROM authority_usb_hsm_devices');
      await q(
        'INSERT INTO authority_meta (id, key_id, signing_private_jwk, signing_private_jwk_enc, signing_public_jwk, updated_at) ' +
          'VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, now()) ' +
          'ON CONFLICT (id) DO UPDATE SET key_id = EXCLUDED.key_id, ' +
          'signing_private_jwk = EXCLUDED.signing_private_jwk, ' +
          'signing_private_jwk_enc = EXCLUDED.signing_private_jwk_enc, ' +
          'signing_public_jwk = EXCLUDED.signing_public_jwk, updated_at = now()',
        [
          META_ID,
          snapshot.keyId,
          jsonParam(snapshot.signingPrivateJwk),
          jsonParam(snapshot.signingPrivateJwkEnc),
          jsonParam(snapshot.signingPublicJwk),
        ]
      );
      for (const policy of snapshot.policies) {
        await q(
          'INSERT INTO authority_policies (document_id, policy, updated_at) VALUES ($1, $2::jsonb, now())',
          [policy.documentId, jsonParam(policy)]
        );
      }
      for (const [documentId, b64] of Object.entries(snapshot.wrapSecretsBase64)) {
        await q(
          'INSERT INTO authority_wrap_secrets (document_id, wrap_secret_b64, updated_at) VALUES ($1, $2, now())',
          [documentId, b64]
        );
      }
      for (const state of snapshot.revocation) {
        await q(
          'INSERT INTO authority_revocation (document_id, is_revoked, current_epoch, state, updated_at) ' +
            'VALUES ($1, $2, $3, $4::jsonb, now())',
          [state.documentId, state.isRevoked, state.currentEpoch, jsonParam(state)]
        );
      }
      for (const op of snapshot.consumedOperations) {
        await q(
          'INSERT INTO authority_consumed_operations (operation_id, challenge, grant_id, document_id, device_id, consumed_at) ' +
            'VALUES ($1, $2, $3, $4, $5, $6)',
          [op.operationId, op.challenge, op.grantId, op.documentId, op.deviceId, op.consumedAt]
        );
      }
      for (const grantId of snapshot.consumedGrantIds) {
        await q('INSERT INTO authority_consumed_grants (grant_id) VALUES ($1)', [grantId]);
      }
      for (const c of snapshot.activeChallenges) {
        await q('INSERT INTO authority_challenges (challenge, registered_at) VALUES ($1, $2)', [
          c.challenge,
          c.registeredAt,
        ]);
      }
      for (const s of snapshot.challengeSubjects) {
        await q(
          'INSERT INTO authority_challenge_subjects (challenge, subject_user_id) VALUES ($1, $2)',
          [s.challenge, s.subjectUserId]
        );
      }
      for (const device of snapshot.usbHsmDevices) {
        await q(
          'INSERT INTO authority_usb_hsm_devices (device_id, record, updated_at) VALUES ($1, $2::jsonb, now())',
          [device.deviceId, jsonParam(device)]
        );
      }
    });
  }

  public resolvePrivateJwk(snapshot: DurableAuthoritySnapshot): JsonWebKey | null {
    return resolveSnapshotPrivateJwk(snapshot);
  }

  public sealPrivateJwk(
    snapshot: DurableAuthoritySnapshot,
    privateJwk: JsonWebKey,
    publicJwk: JsonWebKey
  ): DurableAuthoritySnapshot {
    return sealSnapshotPrivateJwk(snapshot, privateJwk, publicJwk);
  }

  /** Liveness probe: the database answers. */
  public async probeWritable(): Promise<boolean> {
    try {
      await this.ensureSchema();
      await this.client.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  public async close(): Promise<void> {
    if (this.pool) await this.pool.end();
  }

  private async withTransaction(
    fn: (
      q: (text: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }>
    ) => Promise<void>
  ): Promise<void> {
    const connected = this.client.connect
      ? await this.client.connect()
      : null;
    const q = connected
      ? (text: string, params?: unknown[]) => connected.query(text, params)
      : (text: string, params?: unknown[]) => this.client.query(text, params);
    try {
      await q('BEGIN');
      await fn(q);
      await q('COMMIT');
    } catch (err) {
      try {
        await q('ROLLBACK');
      } catch {
        // ROLLBACK fails when the connection died — keep the original error.
      }
      throw err;
    } finally {
      connected?.release();
    }
  }
}

/**
 * Select the Authority store from the environment (called by the service).
 * TDCP_AUTHORITY_STORE=postgres + DATABASE_URL → Postgres; anything else
 * (unset, "file") → the file store. An invalid value fails loudly instead
 * of silently falling back.
 */
export function createAuthorityStoreFromEnv(
  dataDir: string,
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): DurableAuthorityStore {
  if (readAuthorityStoreKindFromEnv(env) === 'postgres') {
    return new DurablePostgresAuthorityStore({ dataDir });
  }
  return new DurableJsonAuthorityStore(dataDir);
}
