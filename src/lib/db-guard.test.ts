import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

// The test process runs under plain Node (no Vite), where db.ts's PGLite
// bootstrap would hit `import.meta.glob` — a Vite-only feature. So this file
// never imports db.ts statically: it sets a dummy DATABASE_URL first (which
// selects the postgres path, no bootstrap) and then imports it dynamically.
// The real fail-fast behaviour is covered by the subprocess tests below,
// which run db.ts exactly as the deployed server would load it.
process.env.DATABASE_URL = "postgresql://dummy:dummy@127.0.0.1:5432/postgres";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

let db: typeof import("./db.ts");

before(async () => {
  db = await import("./db.ts");
});

/** Run `node -e "await import('./src/lib/db.ts')"` in a child with a controlled env. */
async function importDbInChild(env: NodeJS.ProcessEnv): Promise<{
  code: number;
  stdout: string;
  stderr: string;
}> {
  const childEnv = { ...process.env, ...env };
  for (const key of ["DATABASE_URL", "NODE_ENV", "VERCEL_ENV", "VERCEL"]) {
    if (!(key in env)) delete childEnv[key];
  }
  try {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      [
        "--experimental-strip-types",
        "--input-type=module",
        "-e",
        "await import('./src/lib/db.ts')",
      ],
      { cwd: repoRoot, env: childEnv, timeout: 30_000 },
    );
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

describe("P0-3 guardia fail-fast de base de datos en producción", () => {
  it("producción es VERCEL_ENV=production, o NODE_ENV=production en Vercel (VERCEL=1)", () => {
    assert.equal(db.isProductionEnv({ NODE_ENV: "production" }), false);
    assert.equal(
      db.isProductionEnv({ NODE_ENV: "production", VERCEL: "1" }),
      true,
    );
    assert.equal(db.isProductionEnv({ VERCEL_ENV: "production" }), true);
    assert.equal(db.isProductionEnv({ NODE_ENV: "development" }), false);
    assert.equal(db.isProductionEnv({ NODE_ENV: "test" }), false);
    assert.equal(db.isProductionEnv({ VERCEL_ENV: "preview" }), false);
    assert.equal(db.isProductionEnv({}), false);
  });

  it("sin DATABASE_URL el backend es pglite; con ella, postgres", () => {
    assert.equal(db.resolveDbBackend({}).backend, "pglite");
    assert.equal(
      db.resolveDbBackend({ DATABASE_URL: "postgresql://x" }).backend,
      "postgres",
    );
    // Una URL en blanco (error típico al pegar en Vercel) cuenta como ausente.
    assert.equal(db.resolveDbBackend({ DATABASE_URL: "   " }).backend, "pglite");
  });

  it("producción sin DATABASE_URL → error exacto; resto de casos → arranca", () => {
    assert.throws(
      () => db.assertProductionDatabase({ NODE_ENV: "production", VERCEL: "1" }),
      (err: unknown) =>
        err instanceof Error && err.message === db.PRODUCTION_DATABASE_ERROR,
    );
    assert.throws(
      () => db.assertProductionDatabase({ VERCEL_ENV: "production" }),
      (err: unknown) =>
        err instanceof Error && err.message === db.PRODUCTION_DATABASE_ERROR,
    );
    assert.throws(
      () =>
        db.assertProductionDatabase({
          NODE_ENV: "production",
          VERCEL: "1",
          DATABASE_URL: "  ",
        }),
      /FALTA DATABASE_URL/,
    );
    assert.doesNotThrow(() =>
      db.assertProductionDatabase({
        NODE_ENV: "production",
        VERCEL: "1",
        DATABASE_URL: "postgresql://x",
      }),
    );
    assert.doesNotThrow(() => db.assertProductionDatabase({}));
    assert.doesNotThrow(() =>
      db.assertProductionDatabase({ NODE_ENV: "development" }),
    );
    assert.doesNotThrow(() =>
      db.assertProductionDatabase({ VERCEL_ENV: "preview" }),
    );
    // Un `vite preview` local corre con NODE_ENV=production pero sin marcas
    // de Vercel: NO es producción y debe seguir con PGLite.
    assert.doesNotThrow(() =>
      db.assertProductionDatabase({ NODE_ENV: "production" }),
    );
  });

  it("el error dice qué falta y qué hacer en Vercel, sin secretos", () => {
    assert.match(db.PRODUCTION_DATABASE_ERROR, /FALTA DATABASE_URL/);
    assert.match(db.PRODUCTION_DATABASE_ERROR, /PGLite/);
    assert.match(db.PRODUCTION_DATABASE_ERROR, /Vercel/);
    assert.match(db.PRODUCTION_DATABASE_ERROR, /Redeploy/);
    assert.doesNotMatch(db.PRODUCTION_DATABASE_ERROR, /postgres:\/\//);
  });

  it("importar db.ts en producción (Vercel) sin DATABASE_URL falla al arrancar", async () => {
    const res = await importDbInChild({ NODE_ENV: "production", VERCEL: "1" });
    assert.notEqual(res.code, 0, `esperaba fallo, stdout: ${res.stdout}`);
    assert.ok(
      res.stderr.includes(db.PRODUCTION_DATABASE_ERROR),
      `el error exacto debe salir por stderr, stderr: ${res.stderr.slice(0, 500)}`,
    );
  });

  it("importar db.ts en producción con VERCEL_ENV=production sin DATABASE_URL también falla", async () => {
    const res = await importDbInChild({ VERCEL_ENV: "production" });
    assert.notEqual(res.code, 0);
    assert.ok(res.stderr.includes("FALTA DATABASE_URL"));
  });

  it("un preview local (NODE_ENV=production sin marcas de Vercel) NO dispara la guardia", async () => {
    // En Node puro el bootstrap de PGLite tropieza con `import.meta.glob`
    // (solo existe bajo Vite), así que el hijo muere por eso, no por la
    // guardia: lo que se comprueba es que el log dice backend=pglite y que
    // el error fail-fast NO aparece. El camino real (vite preview) se
    // verifica aparte con el servidor construido.
    const res = await importDbInChild({ NODE_ENV: "production" });
    const output = res.stdout + res.stderr;
    assert.ok(
      output.includes("backend=pglite"),
      `el log debe decir backend=pglite, salida: ${output.slice(0, 500)}`,
    );
    assert.ok(
      !output.includes("FALTA DATABASE_URL"),
      "la guardia no debe dispararse en un preview local",
    );
  });

  it("importar db.ts en producción con DATABASE_URL arranca y reporta backend=postgres", async () => {
    const res = await importDbInChild({
      NODE_ENV: "production",
      DATABASE_URL: "postgresql://dummy:dummy@127.0.0.1:5432/postgres",
    });
    assert.equal(res.code, 0, `esperaba exit 0, stderr: ${res.stderr}`);
    assert.ok(
      (res.stdout + res.stderr).includes("backend=postgres"),
      `el log de arranque debe decir backend=postgres, salida: ${res.stdout}${res.stderr}`,
    );
  });
});
