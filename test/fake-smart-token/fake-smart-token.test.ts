/**
 * Tests de la FAKE Smart Token (servidor + CLI) — SOLO PARA PRUEBAS.
 *
 * Cubren el contrato observable contra el SmartTokenClient REAL de TDCP
 * (nunca contra un cliente falso): healthz, protect/open roundtrip,
 * 401 sin key, 403 opaco DENIED (master incorrecto y artefacto
 * desconocido, mismo cuerpo), forma de friction, nada en claro en
 * memoria, y caída simulada. Los tests de la CLI la ejecutan como
 * subproceso real.
 *
 * La contraseña maestra de estos tests es un valor de test, no un secreto
 * real: solo existe dentro del proceso de test.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SmartTokenClient } from '../../sdk/typescript/src/smart-token-client.ts';
import { createFakeSmartTokenServer } from './fake-smart-token-server.mjs';

const API_KEY = 'fake-test-key-123';
const MASTER = 'master-de-test-fake-cli';
const WRONG = 'master-equivocado-de-test';
const CLI = fileURLToPath(new URL('./fake-smart-token-cli.ts', import.meta.url));

let baseUrl: string;
let client: SmartTokenClient;
let fake: ReturnType<typeof createFakeSmartTokenServer>;

before(async () => {
  fake = createFakeSmartTokenServer({ apiKey: API_KEY });
  const { url } = await fake.listen(0, '127.0.0.1');
  baseUrl = url;
  client = new SmartTokenClient({ baseUrl, apiKey: API_KEY });
});

after(async () => {
  await fake.close();
});

function runCli(args: string[], env: Record<string, string> = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ['--experimental-strip-types', CLI, ...args],
      { env: { ...process.env, ...env }, timeout: 30000 },
      (error, stdout, stderr) => {
        resolve({ code: error ? ((error as { code?: number }).code ?? 1) : 0, stdout, stderr });
      }
    );
  });
}

async function protectBytes(data: Buffer, master = MASTER, filename = 'cek.bin'): Promise<string> {
  const res = await client.protect(new Blob([data], { type: 'application/octet-stream' }), master, filename);
  assert.ok(/^[0-9a-f]{32}$/.test(res.artifact_id), `artifact_id con formato real: ${res.artifact_id}`);
  assert.equal(res.status, 'PROTECTED');
  assert.equal(res.filename, filename);
  return res.artifact_id;
}

describe('FAKE Smart Token — servidor (contrato HTTP)', () => {
  it('GET /healthz: {ok:true, storage_backend, smart_token_available:true}, sin auth', async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 200);
    const body: any = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.storage_backend, 'memory');
    assert.equal(body.smart_token_available, true);
    const health = await client.healthz();
    assert.equal(health.ok, true);
  });

  it('GET /v1/status: forma sdk_status + fake:true', async () => {
    const res = await fetch(`${baseUrl}/v1/status`, { headers: { Authorization: `Bearer ${API_KEY}` } });
    assert.equal(res.status, 200);
    const body: any = await res.json();
    assert.equal(body.version, '0.10.5');
    assert.equal(body.available, true);
    assert.equal(body.fake, true);
    assert.equal(body.native_friction, false);
  });

  it('protect/open roundtrip: bytes idénticos, header X-Smart-Token-Status OPEN', async () => {
    const data = randomBytes(1024);
    const id = await protectBytes(data, MASTER, 'documento.bin');
    const opened = await client.open(id, MASTER);
    assert.equal(opened.ok, true);
    if (opened.ok) {
      assert.equal(opened.status, 'OPEN');
      assert.deepEqual(Buffer.from(opened.plaintext), data);
    }
  });

  it('CEK de 32 bytes: roundtrip exacto (caso del custodio del visor)', async () => {
    const cek = randomBytes(32);
    const id = await protectBytes(cek, MASTER, 'cek.bin');
    const opened = await client.open(id, MASTER);
    assert.equal(opened.ok, true);
    if (opened.ok) assert.deepEqual(Buffer.from(opened.plaintext), cek);
  });

  it('sin API key o con key incorrecta → 401 en /v1/*', async () => {
    const noKey = new SmartTokenClient({ baseUrl, apiKey: '' });
    await assert.rejects(() => noKey.protect(new Blob(['x']), MASTER), /HTTP 401/);
    const badKey = new SmartTokenClient({ baseUrl, apiKey: 'clave-mala' });
    await assert.rejects(() => badKey.protect(new Blob(['x']), MASTER), /HTTP 401/);
    const res = await fetch(`${baseUrl}/v1/status`);
    assert.equal(res.status, 401);
  });

  it('sin master en protect → 400 (el cliente lanza)', async () => {
    const res = await fetch(`${baseUrl}/v1/artifacts`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${API_KEY}` },
      body: new FormData(),
    });
    assert.equal(res.status, 400);
  });

  it('master incorrecto → 403 cuerpo opaco DENIED; artefacto desconocido → mismo 403 DENIED', async () => {
    const data = randomBytes(64);
    const id = await protectBytes(data);
    const denied = await client.open(id, WRONG);
    assert.deepEqual(denied, { ok: false, status: 403, body: 'DENIED' });
    const unknown = await client.open('0123456789abcdef0123456789abcdef', MASTER);
    assert.deepEqual(unknown, { ok: false, status: 403, body: 'DENIED' });
    assert.equal(denied.body, unknown.body, 'indistinguible: mismo cuerpo opaco');
  });

  it('friction: forma de friction_status del real; fail_count sube con fallos y resetea al abrir bien', async () => {
    const id = await protectBytes(randomBytes(32));
    let fr: any = await client.friction(id);
    assert.equal(fr.friction_snapshot.fail_count, 0);
    assert.equal(fr.friction_snapshot.recovery_tier, 0);
    assert.equal(fr.friction_snapshot.stok_id, id);
    assert.equal(fr.has_embedded_sk, false);
    assert.equal(fr.public_label, 'cek.bin');
    await client.open(id, WRONG);
    await client.open(id, WRONG);
    fr = await client.friction(id);
    assert.equal(fr.friction_snapshot.fail_count, 2);
    assert.equal(fr.friction_snapshot.recovery_tier, 2);
    assert.equal(fr.friction_snapshot.work_factor, 4);
    assert.equal(fr.cumulative_iters, 2000);
    const ok = await client.open(id, MASTER);
    assert.equal(ok.ok, true);
    fr = await client.friction(id);
    assert.equal(fr.friction_snapshot.fail_count, 0);
  });

  it('friction de artefacto desconocido → 404 como el real', async () => {
    const res = await fetch(`${baseUrl}/v1/artifacts/0123456789abcdef0123456789abcdef/friction`, {
      headers: { Authorization: `Bearer ${API_KEY}` },
    });
    assert.equal(res.status, 404);
  });

  it('nada en claro en memoria: el blob guardado no contiene el plaintext ni el master', async () => {
    const cek = randomBytes(32);
    const id = await protectBytes(cek);
    const stored = fake.debugStoredBytes(id);
    assert.ok(stored);
    assert.ok(!stored.includes(cek), 'el plaintext aparece en los bytes guardados');
    assert.ok(!stored.includes(Buffer.from(MASTER, 'utf8')), 'el master aparece en los bytes guardados');
    assert.equal(
      fake.debugMasterHash(id),
      createHash('sha256').update(MASTER, 'utf8').digest('hex'),
      'del master solo se guarda su SHA-256'
    );
  });

  it('caída simulada: healthz/protect/open fallan (503 / lanza) y al levantar vuelve', async () => {
    const id = await protectBytes(randomBytes(16));
    fake.setDown(true);
    try {
      await assert.rejects(() => client.healthz(), /healthz failed: HTTP 503/);
      await assert.rejects(() => client.protect(new Blob(['x']), MASTER), /HTTP 503/);
      await assert.rejects(() => client.open(id, MASTER), /HTTP 503/);
      const res = await fetch(`${baseUrl}/healthz`);
      assert.equal(res.status, 503);
      assert.equal((await res.json() as any).ok, false);
    } finally {
      fake.setDown(false);
    }
    const ok = await client.open(id, MASTER);
    assert.equal(ok.ok, true);
  });

  it('control solo-fake: POST /__fake__/down|up|reset y GET /__fake__/state', async () => {
    const before = (await (await fetch(`${baseUrl}/__fake__/state`)).json()) as any;
    assert.equal(before.down, false);
    assert.ok(before.artifacts >= 1);
    await fetch(`${baseUrl}/__fake__/down`, { method: 'POST' });
    assert.equal(((await (await fetch(`${baseUrl}/__fake__/state`)).json()) as any).down, true);
    await fetch(`${baseUrl}/__fake__/up`, { method: 'POST' });
    assert.equal(((await (await fetch(`${baseUrl}/__fake__/state`)).json()) as any).down, false);
    const id = await protectBytes(randomBytes(8));
    assert.equal(fake.artifactCount() >= 1, true);
    await fetch(`${baseUrl}/__fake__/reset`, { method: 'POST' });
    assert.equal(fake.artifactCount(), 0);
    assert.equal(fake.debugStoredBytes(id), null);
  });
});

describe('FAKE Smart Token — CLI (subproceso real)', () => {
  it('--help y version llevan la marca FAKE y listan los comandos del real', async () => {
    const help = await runCli(['--help']);
    assert.equal(help.code, 0);
    assert.match(help.stdout, /FAKE/);
    for (const cmd of ['serve', 'protect', 'open', 'status', 'demo', 'version', 'doctor', 'print-dep', 'integrate', 'repair-mac']) {
      assert.ok(help.stdout.includes(cmd), `falta el comando ${cmd} en --help`);
    }
    const version = await runCli(['version']);
    assert.equal(version.code, 0);
    assert.match(version.stdout, /0\.10\.5/);
    assert.match(version.stdout, /FAKE/);
  });

  it('sin comando → exit 2 con ayuda; comando desconocido → exit 2', async () => {
    assert.equal((await runCli([])).code, 2);
    assert.equal((await runCli(['no-existe'])).code, 2);
  });

  it('serve en puerto efímero: imprime ready con puerto, responde /healthz, y muere con SIGTERM', async () => {
    const child = spawn(process.execPath, ['--experimental-strip-types', CLI, 'serve', '--port', '0', '--api-key', 'cli-serve-key'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    const url = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`serve no imprimió ready: out=${stdout} err=${stderr}`)), 15000);
      const onData = () => {
        const m = /url=(http:\/\/127\.0\.0\.1:\d+)/.exec(stdout);
        if (m) {
          clearTimeout(timer);
          resolve(m[1]);
        }
      };
      child.stdout.on('data', onData);
    });
    assert.match(stdout, /FAKE/);
    const res = await fetch(`${url}/healthz`);
    assert.equal(res.status, 200);
    assert.equal(((await res.json()) as any).ok, true);
    child.kill('SIGTERM');
    const code = await new Promise<number | null>((resolve) => child.once('exit', resolve));
    assert.equal(code, 0);
  });

  it('protect/open/status por CLI contra el servidor en proceso (recibo + -o)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fake-cli-'));
    const input = join(dir, 'doc.txt');
    writeFileSync(input, 'documento de prueba de la CLI fake');
    const env = { SMART_TOKEN_API_URL: baseUrl, SMART_TOKEN_API_KEY: API_KEY, SMART_TOKEN_MASTER: MASTER };
    const prot = await runCli(['protect', input, '--master', MASTER], env);
    assert.equal(prot.code, 0, prot.stderr);
    assert.match(prot.stdout, /FAKE/);
    assert.match(prot.stdout, /Protegido:/);
    const receiptPath = `${input}.fake-stok.json`;
    assert.ok(existsSync(receiptPath), 'protect debe escribir el recibo JSON');
    const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
    assert.ok(/^[0-9a-f]{32}$/.test(receipt.artifact_id));
    const outPath = join(dir, 'doc.out');
    const opened = await runCli(['open', receiptPath, '--master', MASTER, '-o', outPath], env);
    assert.equal(opened.code, 0, opened.stderr);
    assert.match(opened.stdout, /OPEN/);
    assert.equal(readFileSync(outPath, 'utf8'), 'documento de prueba de la CLI fake');
    const status = await runCli(['status', receipt.artifact_id], env);
    assert.equal(status.code, 0, status.stderr);
    assert.match(status.stdout, /fail_count\s*:\s*0/);
    const denied = await runCli(['open', receipt.artifact_id, '--master', WRONG, '-o', outPath], env);
    assert.equal(denied.code, 1);
    assert.match(denied.stdout, /DENIED/);
    const statusAfter = await runCli(['status', receipt.artifact_id], env);
    assert.match(statusAfter.stdout, /fail_count\s*:\s*1/);
  });

  it('open sin master → exit 2; integrate sin --dry-run → exit 2 y no escribe', async () => {
    const env = { SMART_TOKEN_API_URL: baseUrl, SMART_TOKEN_API_KEY: API_KEY };
    const noMaster = await runCli(['open', '0123456789abcdef0123456789abcdef'], { ...env, SMART_TOKEN_MASTER: '' });
    assert.equal(noMaster.code, 2);
    const dir = mkdtempSync(join(tmpdir(), 'fake-cli-int-'));
    const integ = await runCli(['integrate', dir], env);
    assert.equal(integ.code, 2);
    assert.equal(existsSync(join(dir, 'smart_token_bridge.py')), false);
    const dry = await runCli(['integrate', dir, '--dry-run'], env);
    assert.equal(dry.code, 0);
    assert.match(dry.stdout, /FAKE/);
  });

  it('doctor OK contra el servidor en proceso; print-dep avisa que no hay pip', async () => {
    const env = { SMART_TOKEN_API_URL: baseUrl, SMART_TOKEN_API_KEY: API_KEY };
    const doctor = await runCli(['doctor'], env);
    assert.equal(doctor.code, 0, doctor.stderr);
    assert.match(doctor.stdout, /FAKE/);
    assert.match(doctor.stdout, /available: true/);
    const dep = await runCli(['print-dep'], env);
    assert.equal(dep.code, 0);
    assert.match(dep.stdout, /no hay paquete pip/);
  });

  it('demo: protect + open legítimo + 3 DENIED + recuperación, exit 0', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fake-cli-demo-'));
    const sample = join(dir, 'muestra.stl');
    const demo = await runCli(['demo', sample, '--master', 'demo-master-fake'], {});
    assert.equal(demo.code, 0, demo.stderr);
    assert.match(demo.stdout, /OPEN/);
    assert.match(demo.stdout, /DENIED/);
    assert.ok(existsSync(sample));
  });

  it('repair-mac: lee la fricción sin cambiar la deuda', async () => {
    const env = { SMART_TOKEN_API_URL: baseUrl, SMART_TOKEN_API_KEY: API_KEY, SMART_TOKEN_MASTER: MASTER };
    const id = await protectBytes(randomBytes(16));
    await client.open(id, WRONG);
    const repair = await runCli(['repair-mac', id], env);
    assert.equal(repair.code, 0, repair.stderr);
    assert.match(repair.stdout, /fail_count\s*:\s*1/);
    assert.match(repair.stdout, /debt preserved/);
  });
});
