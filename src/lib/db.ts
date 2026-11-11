import { pendingMigrations } from "../../scripts/migration-plan.mjs";

/** Which database backend is active. */
export type DbSource = "neon" | "pglite";

/** Backend name shown in logs and `/api/db-status` (never a URL or secret). */
export type DbBackend = "postgres" | "pglite";

// An empty/whitespace DATABASE_URL (an easy misconfig in deploy UIs) must mean
// "unset" — otherwise production would silently run on the PGLite fallback.
const rawDatabaseUrl =
  typeof process !== "undefined" ? process.env.DATABASE_URL : undefined;
const databaseUrl =
  rawDatabaseUrl && rawDatabaseUrl.trim() ? rawDatabaseUrl : undefined;

/**
 * Exact error thrown when production starts without DATABASE_URL. Kept as one
 * constant so the message in the log, the docs and the tests can never drift
 * apart. It says what is missing and what to do — in plain language, because
 * this is the error the deployer will read at 2 a.m.
 */
export const PRODUCTION_DATABASE_ERROR =
  "[db] FALTA DATABASE_URL en producción: la app no arranca sin base de datos real. " +
  "Sin DATABASE_URL caería en silencio a PGLite (base en memoria) y las cuentas creadas se perderían al reiniciar el despliegue. " +
  "En Vercel: Project Settings → Environment Variables → añade DATABASE_URL (Supabase → Connect → Session pooler) en Production, " +
  "junto a BETTER_AUTH_SECRET, BETTER_AUTH_URL y VITE_AUTH_ENABLED=true, y luego haz Redeploy. " +
  "En desarrollo, local o preview sin DATABASE_URL la app sigue usando PGLite sin problema.";

/** Minimal env surface the guard reads, so it is unit-testable without globals. */
export interface DbEnv {
  NODE_ENV?: string;
  VERCEL_ENV?: string;
  VERCEL?: string;
  DATABASE_URL?: string;
}

/**
 * True on a production deploy.
 *
 * `VERCEL_ENV=production` (Vercel always sets it at runtime) is the main
 * signal. `NODE_ENV=production` counts only on Vercel (`VERCEL=1`) — because
 * a local `vite preview` of the production build ALSO runs with
 * `NODE_ENV=production`, and that local preview must keep working on PGLite
 * without DATABASE_URL (measured 2026-11-11: the unguarded `NODE_ENV` check
 * broke `npm run preview` with the fail-fast error). Vercel sets both
 * `VERCEL=1` and `VERCEL_ENV=production` at runtime, so the real production
 * deploy is fully covered by either signal.
 */
export function isProductionEnv(env: DbEnv): boolean {
  return (
    env.VERCEL_ENV === "production" ||
    (env.NODE_ENV === "production" && env.VERCEL === "1")
  );
}

/**
 * Decide the backend from the environment, without side effects.
 * `postgres` when DATABASE_URL is set (Supabase/Neon via `pg`), else `pglite`.
 */
export function resolveDbBackend(env: DbEnv): {
  backend: DbBackend;
  production: boolean;
  databaseUrlSet: boolean;
} {
  const databaseUrlSet = Boolean(env.DATABASE_URL?.trim());
  return {
    backend: databaseUrlSet ? "postgres" : "pglite",
    production: isProductionEnv(env),
    databaseUrlSet,
  };
}

/**
 * Fail-fast guard (P0-3): in production the app must NOT silently fall back
 * to PGLite — that silence is what left tdcp.vercel.app creating accounts in
 * memory while Supabase stayed at 0 users. Throws PRODUCTION_DATABASE_ERROR
 * when production has no DATABASE_URL. Dev / local / preview without
 * DATABASE_URL keep working on PGLite.
 */
export function assertProductionDatabase(env: DbEnv): void {
  const { backend, production } = resolveDbBackend(env);
  if (production && backend === "pglite") {
    throw new Error(PRODUCTION_DATABASE_ERROR);
  }
}

/**
 * Active backend: real **Neon** when `DATABASE_URL` is set (deployed / configured
 * sandbox), otherwise a local embedded **PGLite** (Postgres compiled to WASM) so
 * the app has a working database even with nothing configured — the live preview
 * included. Swap in Neon later by just setting `DATABASE_URL`; no code changes.
 */
export const dbSource: DbSource = databaseUrl ? "neon" : "pglite";

/**
 * Human-facing backend name for the startup log and `/api/db-status`:
 * `postgres` when a real DATABASE_URL is set (Supabase Postgres — the internal
 * `dbSource` name for this case is the legacy `neon`), else `pglite`.
 * Never a host, user, password or URL — just the backend name.
 */
export const dbBackend: DbBackend = dbSource === "neon" ? "postgres" : "pglite";

// Fail fast at server startup in production (P0-3). This module is the single
// place that decides the backend — every server path (auth, accounts, server
// functions) imports it — so no path can silently reach PGLite in production.
// Client bundles skip this (`window` is defined there); the build only bundles
// this module, it never executes it.
const globalGuard = globalThis as typeof globalThis & {
  __pgDbBackendLogged__?: boolean;
};
if (typeof window === "undefined" && typeof process !== "undefined") {
  assertProductionDatabase(process.env);
  if (!globalGuard.__pgDbBackendLogged__) {
    globalGuard.__pgDbBackendLogged__ = true;
    console.info(
      dbBackend === "postgres"
        ? "[db] backend=postgres (DATABASE_URL configurada; cuentas en Postgres/Supabase)"
        : "[db] backend=pglite (SOLO desarrollo/preview: base en memoria, los datos se pierden al reiniciar; en producción la app no arranca sin DATABASE_URL)",
    );
  }
}

/**
 * Minimal shared SQL surface, satisfied by both Neon and PGLite. Both the
 * tagged-template and `.query()` forms resolve to an array of row objects:
 *
 *   const sql = await getSql();
 *   const rows = await sql`select * from todos where id = ${id}`; // parameterized
 *   const rows2 = await sql.query("select * from todos where id = $1", [id]);
 */
export interface Sql {
  <T = Record<string, unknown>>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<T[]>;
  query<T = Record<string, unknown>>(
    text: string,
    params?: unknown[],
  ): Promise<T[]>;
}

/**
 * Init state lives on globalThis as promises: dev HMR creates new instances of
 * this module, and two instances racing module-level state would open a second
 * pool or run two concurrent PGLite migration passes (whose duplicate
 * `_migrations` insert rejects — and would get memoized, poisoning every later
 * `getSql()`). A failed init clears its slot so the next call retries.
 */
const globalRef = globalThis as typeof globalThis & {
  __pgSqlPromise__?: Promise<Sql>;
  __pgliteInstance__?: Promise<import("@electric-sql/pglite").PGlite>;
  __pgliteMigrateChain__?: Promise<void>;
};

/**
 * Result-type parity: Postgres sends every value as text plus a type OID — the
 * JS value is the DRIVER's parsing choice, and pg and PGLite disagree (pg:
 * int8 -> string, date -> local-midnight Date; PGLite: int8 -> BigInt, which
 * JSON.stringify rejects, date -> UTC Date). Normalize both so preview and
 * production return identical, JSON-safe shapes:
 *   int8/bigint (incl. count(*)) -> number (past 2^53 loses precision — cast
 *                                   `::text` if you ever need huge integers)
 *   date                         -> 'YYYY-MM-DD' string
 *   interval                     -> Postgres interval text
 * numeric already comes back as a string on both (arbitrary precision).
 */
const OID_INT8 = 20;
const OID_DATE = 1082;
const OID_INTERVAL = 1186;
const identity = (v: string) => v;

type Run = <T>(text: string, params: unknown[]) => Promise<T[]>;

/** Wrap a query runner in the tagged-template + `.query()` `Sql` surface. */
function toSql(run: Run): Sql {
  const sql = (async <T = Record<string, unknown>>(
    strings: TemplateStringsArray,
    ...values: unknown[]
  ): Promise<T[]> => {
    // Rebuild with $1, $2, … placeholders so values stay parameterized.
    let text = strings[0];
    for (let i = 0; i < values.length; i += 1) text += `$${i + 1}${strings[i + 1]}`;
    return run<T>(text, values);
  }) as unknown as Sql;
  sql.query = <T = Record<string, unknown>>(text: string, params: unknown[] = []) =>
    run<T>(text, params);
  return sql;
}

function createNeonSql(): Promise<Sql> {
  globalRef.__pgSqlPromise__ ??= (async () => {
    // Regular Postgres driver: node-postgres (`pg`) — works directly with Neon's
    // pooled endpoint. One pool per process; warm serverless instances reuse it.
    const { Pool, types } = await import("pg");
    types.setTypeParser(OID_INT8, Number);
    types.setTypeParser(OID_DATE, identity);
    types.setTypeParser(OID_INTERVAL, identity);
    const pool = new Pool({ connectionString: databaseUrl });
    return toSql(async <T>(text: string, params: unknown[]) => {
      const res = await pool.query(text, params);
      return res.rows as T[];
    });
  })().catch((err) => {
    globalRef.__pgSqlPromise__ = undefined;
    throw err;
  });
  return globalRef.__pgSqlPromise__;
}

async function createPgliteSql(): Promise<Sql> {
  // Embedded Postgres, imported on demand so it never loads on the Neon path.
  // One in-memory instance per process, shared across HMR module instances, so
  // data survives source edits (it resets on dev-server restart).
  globalRef.__pgliteInstance__ ??= (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite({
      parsers: {
        [OID_INT8]: Number,
        [OID_DATE]: identity,
        [OID_INTERVAL]: identity,
      },
    });
    await pg.waitReady;
    await pg.exec(
      "create table if not exists _migrations (name text primary key, applied_at timestamptz not null default now())",
    );
    return pg;
  })().catch((err) => {
    globalRef.__pgliteInstance__ = undefined;
    throw err;
  });
  const pg = await globalRef.__pgliteInstance__;

  // Apply migrations/ (the single schema source) so preview matches production.
  // SQL is inlined by the bundler via import.meta.glob (no runtime fs); applied
  // files are tracked in _migrations. The glob does not descend, so the opt-in
  // auth schema under migrations/auth/ stays out. Runs once per module instance
  // — so an HMR reload after adding a migration file applies it live — with
  // passes serialized on a global chain so concurrent callers never
  // double-apply.
  const migrate = async (): Promise<void> => {
    const migrations = import.meta.glob("/migrations/*.sql", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;
    const doneRows = await pg.query<{ name: string }>(
      "select name from _migrations",
    );
    const done = doneRows.rows.map((r) => r.name);
    for (const { name, path } of pendingMigrations(Object.keys(migrations), done)) {
      // Apply + record atomically (parity with scripts/migrate.mjs) so a failed
      // statement can't leave a file half-applied but untracked.
      await pg.transaction(async (tx) => {
        await tx.exec(migrations[path]);
        await tx.query("insert into _migrations (name) values ($1)", [name]);
      });
    }
  };
  const pass = (globalRef.__pgliteMigrateChain__ ?? Promise.resolve())
    .catch(() => undefined) // an earlier failed pass must not wedge the chain
    .then(migrate);
  globalRef.__pgliteMigrateChain__ = pass;
  await pass;

  return toSql(async <T>(text: string, params: unknown[]) => {
    const result = await pg.query<T>(text, params);
    return result.rows;
  });
}

let sqlPromise: Promise<Sql> | null = null;

async function createSql(): Promise<Sql> {
  if (typeof window !== "undefined") {
    throw new Error(
      "@/lib/db is server-only — call getSql() from a createServerFn handler " +
        "or a server route loader, never from client code.",
    );
  }
  return dbSource === "neon" ? createNeonSql() : createPgliteSql();
}

/**
 * Get the shared, **server-only** SQL client. Neon when `DATABASE_URL` is set,
 * otherwise the local PGLite fallback. Memoized — safe to call per request.
 *
 * Schema comes from `migrations/*.sql`, auto-applied before the first query on
 * both backends — define tables there, never inline in server functions.
 */
export function getSql(): Promise<Sql> {
  sqlPromise ??= createSql().catch((err) => {
    sqlPromise = null; // don't memoize failures — let the next call retry
    throw err;
  });
  return sqlPromise;
}

/**
 * The shared PGLite instance (preview only), with `migrations/*.sql` applied.
 * Lets Better Auth persist to the SAME embedded DB as app data in preview (via a
 * Kysely dialect). Throws when `DATABASE_URL` is set (that path uses Neon).
 */
export async function getPglite(): Promise<import("@electric-sql/pglite").PGlite> {
  if (dbSource !== "pglite") {
    throw new Error("getPglite() is only available on the PGLite fallback (no DATABASE_URL)");
  }
  await getSql();
  const pg = await globalRef.__pgliteInstance__;
  if (!pg) throw new Error("PGLite instance failed to initialize");
  return pg;
}

/**
 * Finish DB bootstrap before the server handles traffic.
 *
 * - **PGLite** (preview / no `DATABASE_URL`): open the in-memory DB and apply
 *   `migrations/*.sql`. Idempotent — concurrent callers share one promise.
 * - **Neon**: no-op (pool is created lazily on first query).
 *
 * Vite `configureServer` awaits this at dev startup; production imports of this
 * module kick it off immediately (see bottom of file).
 */
export function ensureDbReady(): Promise<void> {
  if (dbSource !== "pglite") return Promise.resolve();
  return getSql().then(() => undefined);
}

/** What `/api/db-status` reports. Backend name only — never host, user, password or URL. */
export interface DbStatus {
  backend: DbBackend;
  databaseConfigured: boolean;
  production: boolean;
  ready: boolean;
}

/**
 * Live backend status: which backend is active and whether a `select 1`
 * against it answers. `ready: false` means the DB did not answer (wrong URL,
 * DB down, migrations pending) — it never leaks the reason's secrets, only
 * that the ping failed. Safe to expose: no credentials, no connection details.
 */
export async function getDbStatus(): Promise<DbStatus> {
  const { backend, production, databaseUrlSet } = resolveDbBackend(process.env);
  let ready = false;
  try {
    const sql = await getSql();
    const rows = await sql.query<{ ok: number }>("select 1 as ok");
    ready = rows[0]?.ok === 1;
  } catch {
    ready = false;
  }
  return { backend, databaseConfigured: databaseUrlSet, production, ready };
}

// Server-only eager start: kick PGLite bootstrap as soon as this module loads in
// Node. Client bundles never hit this path (`getSql` throws in the browser).
// In production this line is unreachable without DATABASE_URL: the fail-fast
// guard at the top of this module already threw (P0-3).
const globalBoot = globalThis as typeof globalThis & {
  __pgBootstrapPromise__?: Promise<void>;
};
if (typeof window === "undefined" && dbSource === "pglite") {
  globalBoot.__pgBootstrapPromise__ ??= ensureDbReady().catch((err) => {
    globalBoot.__pgBootstrapPromise__ = undefined;
    console.error("[db] PGLite bootstrap failed:", err);
    throw err;
  });
}
