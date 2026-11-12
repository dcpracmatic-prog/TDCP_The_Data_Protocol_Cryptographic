#!/usr/bin/env node
/**
 * Guarda contra regresiones de la directiva de arquitectura soberana
 * (docs/SOVEREIGN_ARCHITECTURE.md): el repo no debe acoplarse a ningún
 * servicio real/externo ni a ninguna credencial real.
 *
 * Uso: node scripts/check-sovereign-architecture.mjs [root]
 * Exit 0 si el árbol está limpio, exit 1 con la lista de violaciones.
 *
 * Reglas (patrones concretos de la auditoría 2026-11-11):
 *  1. real-host-onrender — hosts reales de servicios (onrender.com).
 *  2. hardcoded-admin-default — el default fijo del token de admin.
 *  3. master-key-hex-injected — MASTER_KEY_HEX en el repo (nada lo lee).
 *  4. smoke-against-real-service — referencias a un smoke contra el
 *     servicio real (pendiente o en mayúsculas) o a "smoke contra el
 *     servicio" en general.
 *  5. sidecar-real — "sidecar real": el sidecar es el Python en-repo en
 *     loopback; se dice "sidecar local".
 *  6. test-reads-real-credential-env — un test que lee variables de
 *     credenciales reales, salvo el patrón fail-closed (el test borra la
 *     variable con `delete process.env.…` para probar su ausencia).
 *
 * Exclusiones: este script (contiene los patrones como literales),
 * docs/SOVEREIGN_ARCHITECTURE.md (los cita como ejemplos), y líneas
 * marcadas explícitamente como sintéticas con `SOVEREIGN-GUARD-ALLOW:`.
 * No se escanean .git, node_modules, dist, coverage, data ni .mvp
 * (estado de ejecución, no código del repo).
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.argv[2] ?? join(fileURLToPath(new URL('.', import.meta.url)), '..');
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'coverage', 'data', '.mvp']);
const EXCLUDED_FILES = new Set([
  'scripts/check-sovereign-architecture.mjs',
  'docs/SOVEREIGN_ARCHITECTURE.md',
]);
const ALLOW_MARKER = 'SOVEREIGN-GUARD-ALLOW:';
const CRED_ENV_VARS = ['SMART_TOKEN_API_URL', 'SMART_TOKEN_API_KEY', 'MASTER_KEY_HEX'];

const RULES = [
  {
    id: 'real-host-onrender',
    pattern: /onrender\.com/,
    hint: 'host real de servicio; usa la variable del despliegue propio del operador ($TDCP_AUTHORITY_URL / $SMART_TOKEN_API_URL)',
  },
  {
    id: 'hardcoded-admin-default',
    pattern: /local-dev-only-change-me/,
    hint: 'default hardcodeado de credencial; genera por corrida (openssl rand -hex 32) o exige la variable con fail-closed',
  },
  {
    id: 'master-key-hex-injected',
    pattern: /MASTER_KEY_HEX/,
    hint: 'ningun archivo del repo lee MASTER_KEY_HEX; no inyectarlo en CI ni en tests',
  },
  {
    id: 'smoke-against-real-service',
    // "REAL" en mayúsculas es deliberadamente case-sensitive: la frase en
    // minúscula ("el servicio real") aparece en contextos legítimos que
    // describen la fake frente al servicio (p. ej. la ayuda del CLI fake).
    patterns: [/Smart Token REAL/, /smoke contra el servicio/i, /pendiente:\s*smoke/i],
    hint: 'no existe smoke contra un servicio externo; el canonico es npm run smoke:viewer-e2e contra la fake local',
  },
  {
    id: 'sidecar-real',
    pattern: /sidecar real/i,
    hint: 'el sidecar es el Python en-repo en loopback; se dice "sidecar local"',
  },
];

function isTestFile(relPosix) {
  // Solo archivos de test (*.test.*): lo que vive bajo test/ incluye la
  // implementación de la propia fake (fake-smart-token-cli.ts), que espeja
  // la interfaz env del CLI real y NO es un test.
  return /\.test\.(ts|mts|cts|js|mjs|cjs)$/.test(relPosix);
}

function walk(dir, out) {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, out);
    else if (st.isFile()) out.push(full);
  }
  return out;
}

function check(root) {
  const violations = [];
  for (const full of walk(root, [])) {
    const rel = relative(root, full).split(sep).join('/');
    if (EXCLUDED_FILES.has(rel)) continue;
    let text;
    try {
      text = readFileSync(full, 'utf8');
    } catch {
      continue;
    }
    if (text.includes('\0')) continue; // binario
    const lines = text.split('\n');
    const deletesCredEnv = text.includes('delete process.env.');
    lines.forEach((line, i) => {
      if (line.includes(ALLOW_MARKER)) return;
      for (const rule of RULES) {
        const patterns = rule.patterns ?? [rule.pattern];
        if (patterns.some((p) => p.test(line))) {
          violations.push({ file: rel, line: i + 1, rule: rule.id, hint: rule.hint, text: line.trim().slice(0, 160) });
        }
      }
      if (isTestFile(rel) && !deletesCredEnv) {
        for (const v of CRED_ENV_VARS) {
          if (line.includes(`process.env.${v}`)) {
            violations.push({
              file: rel,
              line: i + 1,
              rule: 'test-reads-real-credential-env',
              hint: `un test no debe leer ${v} para contactar un despliegue; usa la fake local o el patron fail-closed (delete process.env.${v})`,
              text: line.trim().slice(0, 160),
            });
          }
        }
      }
    });
  }
  return violations;
}

const violations = check(ROOT);
if (violations.length > 0) {
  for (const v of violations) {
    console.error(`[sovereign] ${v.file}:${v.line} [${v.rule}] ${v.hint}\n  > ${v.text}`);
  }
  console.error(`[sovereign] FAIL: ${violations.length} violacion(es) de docs/SOVEREIGN_ARCHITECTURE.md`);
  process.exit(1);
}
console.log('[sovereign] OK: arbol limpio (sin acoplamiento a servicios ni credenciales reales)');
