#!/usr/bin/env node
/**
 * P2-5 smoke end-to-end (real CSG sidecar, real factory + Gatekeeper):
 *
 *   node scripts/csg-pkg-smoke.mjs
 *
 * 1. Starts the in-repo CSG sidecar (server/csg-sidecar/main.py, Python
 *    stdlib + cryptography, Ed25519 + SHA3-256) on 127.0.0.1:8010 with a
 *    throwaway data dir.
 * 2. Phase A: protect sealed -> open OK; tamper 1 byte -> DENIED
 *    CSG_PACKAGE_SEAL_FAILED; legacy (no seal) opens.
 * 3. Kills the sidecar. Phase B: the sealed .pkg must be DENIED
 *    (fail closed — an unverifiable seal never opens).
 *
 * Requires: python3 with the `cryptography` package
 * (pip install cryptography). If it is missing the script exits 2 with a
 * clear message instead of faking a pass. Never commits the temp data dir.
 */
import { spawn, execFile } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = process.env.CSG_SMOKE_PORT ?? '8010';
const SIDECAR_URL = `http://127.0.0.1:${PORT}`;
const PKG_PATH = join(mkdtempSync(join(tmpdir(), 'csg-pkg-smoke-')), 'sealed.pkg.json');

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    // Hard timeout: a hung child must fail loudly, never hang the smoke.
    const child = execFile(cmd, args, { timeout: 120000, ...opts }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr });
    });
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitHealthz(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${SIDECAR_URL}/healthz`);
      if (res.ok) return true;
    } catch {
      /* not up yet */
    }
    await sleep(500);
  }
  return false;
}

const cryptoCheck = await run('python3', ['-c', 'import cryptography']);
if (cryptoCheck.code !== 0) {
  console.error(
    'SMOKE ABORT (exit 2): python3 + package `cryptography` is required to run the real CSG sidecar.\n' +
      'Install it (pip install cryptography) and re-run: node scripts/csg-pkg-smoke.mjs'
  );
  process.exit(2);
}

const dataDir = mkdtempSync(join(tmpdir(), 'csg-sidecar-data-'));
const sidecar = spawn(
  'python3',
  [join(ROOT, 'server/csg-sidecar/main.py')],
  {
    cwd: ROOT,
    env: { ...process.env, CSG_PORT: PORT, CSG_DATA_DIR: dataDir, CSG_NOTARIO_NAME: 'TDCP-Notario-Smoke' },
    stdio: ['ignore', 'pipe', 'pipe'],
  }
);
sidecar.stdout.on('data', (d) => process.stdout.write(`[sidecar] ${d}`));
sidecar.stderr.on('data', (d) => process.stderr.write(`[sidecar:err] ${d}`));

let exitCode = 0;
try {
  if (!(await waitHealthz())) {
    console.error(`SMOKE FAIL: sidecar did not answer ${SIDECAR_URL}/healthz in 15 s`);
    exitCode = 1;
  } else {
    const envA = { ...process.env, CSG_SEAL_URL: SIDECAR_URL, CSG_SMOKE_PHASE: 'A', CSG_SMOKE_PKG_PATH: PKG_PATH };
    const phaseA = await run('node', ['--experimental-strip-types', join(ROOT, 'scripts/csg-pkg-smoke-run.ts')], { env: envA, cwd: ROOT });
    process.stdout.write(phaseA.stdout);
    process.stderr.write(phaseA.stderr);
    if (phaseA.code !== 0) {
      console.error(`SMOKE FAIL: phase A exited ${phaseA.code}`);
      exitCode = 1;
    }
  }
} finally {
  sidecar.kill('SIGTERM');
  await sleep(500);
  if (!sidecar.killed) sidecar.kill('SIGKILL');
}

if (exitCode === 0) {
  // Phase B: sidecar is down on purpose.
  const envB = { ...process.env, CSG_SEAL_URL: SIDECAR_URL, CSG_SMOKE_PHASE: 'B', CSG_SMOKE_PKG_PATH: PKG_PATH };
  const phaseB = await run('node', ['--experimental-strip-types', join(ROOT, 'scripts/csg-pkg-smoke-run.ts')], { env: envB, cwd: ROOT });
  process.stdout.write(phaseB.stdout);
  process.stderr.write(phaseB.stderr);
  if (phaseB.code !== 0) {
    console.error(`SMOKE FAIL: phase B exited ${phaseB.code}`);
    exitCode = 1;
  }
}

rmSync(dataDir, { recursive: true, force: true });
rmSync(join(PKG_PATH, '..'), { recursive: true, force: true });
if (exitCode === 0) console.log('CSG PKG SMOKE OK: seal -> open OK, tamper -> DENIED, sidecar-down -> DENIED, legacy -> OK.');
process.exit(exitCode);
