/**
 * Smoke e2e del visor offline REAL contra la FAKE Smart Token.
 *
 * Flujo completo sin servicio real ni red externa:
 *   1. Levanta la fake en un puerto local efímero.
 *   2. Crea un paquete TDCP en modo `smart-token-custody` contra ella con
 *      el custodio HTTP REAL (HttpSmartTokenCekCustodian + SmartTokenClient).
 *   3. Corre el CLI REAL del visor (src/viewer/offline-viewer-cli.ts
 *      --export-offline) con SMART_TOKEN_API_URL apuntando a la fake.
 *   4. Ejecuta el runtime embebido del HTML generado: la contraseña
 *      correcta abre (plaintext idéntico) y la incorrecta es DENIED.
 *   5. Con la fake caída, el CLI del visor falla cerrado (exit 1).
 *
 * La contraseña maestra de este test es un valor de test, no un secreto
 * real: solo existe dentro del proceso de test.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { execFile } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createTDCPPackage } from '../../src/core/package/tdcp-factory.ts';
import { serializeTDCPPackage } from '../../src/core/package/package-format.ts';
import { AuthorizationOracle } from '../../src/oracle/authorization-oracle.ts';
import { HttpSmartTokenCekCustodian } from '../../src/protection/smart-token-cek-custody.ts';
import { SmartTokenClient } from '../../sdk/typescript/src/smart-token-client.ts';
import { createFakeSmartTokenServer } from './fake-smart-token-server.mjs';

const API_KEY = 'fake-e2e-key-456';
const MASTER = 'master-de-emisor-solo-para-test-e2e';
const WRONG_MASTER = 'contrasena-equivocada-de-test-e2e';
const PLAINTEXT = 'Documento de prueba del visor offline contra la fake Smart Token.';
const VIEWER_CLI = fileURLToPath(new URL('../../src/viewer/offline-viewer-cli.ts', import.meta.url));

let baseUrl: string;
let fake: ReturnType<typeof createFakeSmartTokenServer>;
let dir: string;

before(async () => {
  fake = createFakeSmartTokenServer({ apiKey: API_KEY });
  const { url } = await fake.listen(0, '127.0.0.1');
  baseUrl = url;
  dir = mkdtempSync(join(tmpdir(), 'viewer-e2e-fake-'));
});

after(async () => {
  await fake.close();
  rmSync(dir, { recursive: true, force: true });
});

function runViewerCli(env: Record<string, string>, extraArgs: string[] = []): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ['--experimental-strip-types', VIEWER_CLI, '--pkg', join(dir, 'pkg.json'), '--out', join(dir, 'visor.html'), '--master-env', 'TDCP_MASTER', '--export-offline', ...extraArgs],
      { env: { ...process.env, ...env }, timeout: 60000 },
      (error, stdout, stderr) => {
        resolve({ code: error ? ((error as { code?: number }).code ?? 1) : 0, stdout, stderr });
      }
    );
  });
}

function extractData(html: string): Record<string, unknown> {
  const m = html.match(/<script id="tdcp-offline-data" type="application\/json">([^<]*)<\/script>/);
  assert.ok(m, 'el HTML debe llevar los datos embebidos');
  return JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'));
}

function loadEmbeddedViewer(html: string): any {
  const m = html.match(/<script id="tdcp-viewer-runtime">([\s\S]*?)<\/script>/);
  assert.ok(m, 'el HTML debe llevar el runtime embebido');
  return vm.runInThisContext(`(function(){\n${m[1]}\n; return TDCPOfflineViewer; })()`, {
    filename: 'offline-viewer-runtime-embebido-e2e.js',
  });
}

describe('Visor offline e2e contra la FAKE Smart Token', () => {
  it('paquete en custodia vía HTTP fake → CLI del visor genera HTML que abre bien y niega mal', async () => {
    const oracle = new AuthorizationOracle();
    const custodian = new HttpSmartTokenCekCustodian(
      new SmartTokenClient({ baseUrl, apiKey: API_KEY })
    );
    const pkg = await createTDCPPackage({
      plaintext: new TextEncoder().encode(PLAINTEXT).buffer,
      password: 'PasswordOriginal!',
      originalFileName: 'documento.txt',
      mimeType: 'text/plain',
      policyLevel: 'STANDARD',
      allowExtraction: false,
      oracle,
      cekCustodyMode: 'smart-token',
      smartTokenCustodian: custodian,
      smartTokenMaster: MASTER,
      csgSeal: 'off',
    });
    assert.equal(pkg.metadata.custodyMode, 'smart-token');
    assert.ok(pkg.smartTokenCustody?.artifactId);
    assert.equal(fake.artifactCount(), 1, 'la CEK debe haberse protegido en la fake');

    const blob = await serializeTDCPPackage(pkg);
    writeFileSync(join(dir, 'pkg.json'), await blob.text(), 'utf8');

    const run = await runViewerCli({
      SMART_TOKEN_API_URL: baseUrl,
      SMART_TOKEN_API_KEY: API_KEY,
      TDCP_MASTER: MASTER,
    });
    assert.equal(run.code, 0, `CLI del visor falló: ${run.stderr}`);
    assert.match(run.stdout, /Visor offline generado/);

    const html = readFileSync(join(dir, 'visor.html'), 'utf8');
    assert.ok(!html.includes(MASTER), 'la contraseña maestra aparece en el HTML');
    const viewer = loadEmbeddedViewer(html);
    const ok = await viewer.openOfflineViewer(extractData(html), MASTER);
    if (!ok.ok) assert.fail(`no abrió con la contraseña correcta: ${JSON.stringify(ok)}`);
    assert.equal(new TextDecoder().decode(ok.plaintext), PLAINTEXT);
    const denied = await viewer.openOfflineViewer(extractData(html), WRONG_MASTER);
    assert.equal(denied.ok, false);
    assert.equal(denied.reason, 'DENIED');
  });

  it('con la fake caída el CLI del visor falla cerrado (exit 1, sin HTML)', async () => {
    const oracle = new AuthorizationOracle();
    const custodian = new HttpSmartTokenCekCustodian(
      new SmartTokenClient({ baseUrl, apiKey: API_KEY })
    );
    const pkg = await createTDCPPackage({
      plaintext: new TextEncoder().encode(PLAINTEXT).buffer,
      password: 'PasswordOriginal!',
      originalFileName: 'documento.txt',
      mimeType: 'text/plain',
      policyLevel: 'STANDARD',
      allowExtraction: false,
      oracle,
      cekCustodyMode: 'smart-token',
      smartTokenCustodian: custodian,
      smartTokenMaster: MASTER,
      csgSeal: 'off',
    });
    const blob = await serializeTDCPPackage(pkg);
    writeFileSync(join(dir, 'pkg.json'), await blob.text(), 'utf8');

    fake.setDown(true);
    try {
      const run = await runViewerCli({
        SMART_TOKEN_API_URL: baseUrl,
        SMART_TOKEN_API_KEY: API_KEY,
        TDCP_MASTER: MASTER,
      });
      assert.equal(run.code, 1, `debió fallar cerrado, salió ${run.code}: ${run.stdout} ${run.stderr}`);
      assert.match(run.stderr, /OFFLINE_VIEWER_FAILED/);
    } finally {
      fake.setDown(false);
    }
  });
});
