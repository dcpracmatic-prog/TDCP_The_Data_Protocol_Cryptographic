/**
 * Tests de la guarda soberana (scripts/check-sovereign-architecture.mjs).
 * Corren con `npm run test:scripts`.
 *
 * Los patrones prohibidos se reconstruyen por concatenación para que este
 * propio archivo no contenga los literales que la guarda prohíbe.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const CHECKER = fileURLToPath(new URL('./check-sovereign-architecture.mjs', import.meta.url));
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const P = {
  host: 'onrender' + '.com',
  def: 'local-dev-only-' + 'change-me',
  mkey: 'MASTER_KEY_' + 'HEX',
  smokeReal: 'Smart Token ' + 'REAL',
  smokeSvc: 'smoke contra el ' + 'servicio',
  sidecar: 'sidecar ' + 'real',
  credEnv: 'process.env.SMART_TOKEN_' + 'API_KEY',
  credEnvUrl: 'process.env.SMART_TOKEN_' + 'API_URL',
};

function run(root) {
  return spawnSync(process.execPath, [CHECKER, root], { encoding: 'utf8' });
}

describe('check-sovereign-architecture (guarda)', () => {
  it('arbol limpio del repo: exit 0', () => {
    const r = run(ROOT);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /OK/);
  });

  it('detecta cada patron plantado en un arbol temporal', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sovereign-dirty-'));
    try {
      writeFileSync(join(dir, 'a.md'), 'host https://x.' + P.host + '/healthz\n');
      writeFileSync(join(dir, 'b.yml'), 'token: ' + P.def + '\n');
      writeFileSync(join(dir, 'c.yml'), 'key: ${{ secrets.' + P.mkey + ' }}\n');
      writeFileSync(join(dir, 'd.md'), 'Pendiente: ' + P.smokeReal + ' y ' + P.smokeSvc + ' REAL\n');
      writeFileSync(join(dir, 'e.md'), 'contra el ' + P.sidecar + ' en local\n');
      mkdirSync(join(dir, 'test'));
      writeFileSync(join(dir, 'test', 'x.test.mjs'), 'const k = ' + P.credEnv + ';\n');
      const r = run(dir);
      assert.equal(r.status, 1, 'debió fallar');
      for (const id of [
        'real-host-onrender',
        'hardcoded-admin-default',
        'master-key-hex-injected',
        'smoke-against-real-service',
        'sidecar-real',
        'test-reads-real-credential-env',
      ]) {
        assert.ok(r.stderr.includes('[' + id + ']'), 'falta regla ' + id + ' en:\n' + r.stderr);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('arbol temporal limpio y linea marcada como sintetica: exit 0', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sovereign-clean-'));
    try {
      writeFileSync(join(dir, 'ok.md'), 'nada sospechoso\n');
      writeFileSync(
        join(dir, 'synthetic.md'),
        'ejemplo sintetico https://x.' + P.host + ' SOVEREIGN-GUARD-ALLOW: ejemplo en doc\n'
      );
      const r = run(dir);
      assert.equal(r.status, 0, r.stderr + r.stdout);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('test con patron fail-closed (delete process.env) no dispara', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sovereign-failclosed-'));
    try {
      writeFileSync(
        join(dir, 'f.test.mjs'),
        'delete ' + P.credEnv + ';\nconst u = ' + P.credEnvUrl + ';\n'
      );
      const r = run(dir);
      assert.equal(r.status, 0, r.stderr + r.stdout);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
