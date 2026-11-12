#!/usr/bin/env node
/**
 * FAKE Smart Token CLI — SOLO PARA PRUEBAS. NO ES PRODUCCION.
 *
 * Espeja la estructura de la CLI real de Smart Token Prod v0.10.5
 * (`smart_token_prod/cli.py`, prog `smart-token`): mismos subcomandos,
 * mismos flags y mismas salidas en lo que el transporte lo permite,
 * marcados FAKE en cada salida y en el --help. La diferencia estructural
 * es deliberada y documentada: la CLI real opera sobre archivos .stok
 * locales (ML-KEM + Argon2id, fricción file-borne); la fake opera contra
 * el servidor HTTP fake (este mismo directorio) con el SmartTokenClient
 * real de TDCP, porque su propósito es probar el contrato HTTP que usa
 * el visor offline. No hay archivos .stok ni .stok.key en la fake.
 *
 * Uso:
 *   node --experimental-strip-types test/fake-smart-token/fake-smart-token-cli.ts \
 *     [--api-url URL] [--api-key KEY] <comando> [args...]
 *   SMART_TOKEN_API_URL / SMART_TOKEN_API_KEY / SMART_TOKEN_MASTER
 *   cubren --api-url / --api-key / --master cuando no se pasan por argv.
 *
 * Subcomandos (reales espejados + 1 extra fake):
 *   serve        FAKE-EXTRA: arranca el servidor fake (puerto efímero o --port)
 *   protect      espeja `smart-token protect` (vía HTTP, no .stok local)
 *   open         espeja `smart-token open` (0 OPEN, 1 DENIED, 2 sin master)
 *   status       espeja `smart-token status` (fricción del dueño)
 *   demo         espeja `smart-token demo` (sin ladder ni hang: documentado)
 *   version      espeja `smart-token version` (0.10.5 + marca FAKE)
 *   doctor       espeja `smart-token doctor` (chequeos locales Node, no pqcrypto)
 *   print-dep    espeja `smart-token print-dep` (sin paquete pip: solo aviso)
 *   integrate    espeja `smart-token integrate` (nunca escribe: solo --dry-run)
 *   repair-mac   espeja `smart-token repair-mac` (deuda preservada, sin re-MAC)
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { SmartTokenClient } from '../../sdk/typescript/src/smart-token-client.ts';
import {
  createFakeSmartTokenServer,
  FAKE_MIRRORS_REAL_VERSION,
} from './fake-smart-token-server.mjs';

const FAKE_TAG = '[FAKE]';

function out(line = ''): void {
  console.log(`${FAKE_TAG} ${line}`);
}

function err(line = ''): void {
  console.error(`${FAKE_TAG} ${line}`);
}

const HELP = [
  `${FAKE_TAG} smart-token (FAKE — SOLO PARA PRUEBAS, espeja Smart Token Prod ${FAKE_MIRRORS_REAL_VERSION})`,
  `${FAKE_TAG} Uso: fake-smart-token-cli.ts [--api-url URL] [--api-key KEY] <comando> [args...]`,
  `${FAKE_TAG}   SMART_TOKEN_API_URL / SMART_TOKEN_API_KEY / SMART_TOKEN_MASTER como defaults.`,
  `${FAKE_TAG} Comandos (misma estructura que la CLI real; 'serve' es extra fake):`,
  `${FAKE_TAG}   serve <none> [--port N] [--host H] [--api-key K] [--down]  Arranca el servidor fake`,
  `${FAKE_TAG}   protect <archivo> [--master M] [--out RUTA] [--key RUTA] [--backend B] [--tarpit-mode M] [--tarpit-seconds N]`,
  `${FAKE_TAG}   open <artifact-id|recibo.json> [--master M] [--key RUTA] [-o SALIDA] [--force-failure]`,
  `${FAKE_TAG}   status <artifact-id>`,
  `${FAKE_TAG}   demo [archivo_muestra]`,
  `${FAKE_TAG}   version`,
  `${FAKE_TAG}   doctor`,
  `${FAKE_TAG}   print-dep [--editable PATH]`,
  `${FAKE_TAG}   integrate <project_dir> [--bridge PATH] [--editable PATH] [--dry-run]`,
  `${FAKE_TAG}   repair-mac <artifact-id> [--key RUTA]`,
  `${FAKE_TAG} Notas fake: protect/open hablan HTTP contra el servidor fake (no hay .stok local);`,
  `${FAKE_TAG} --backend/--tarpit-mode/--tarpit-seconds/--key se aceptan por compatibilidad pero la fake`,
  `${FAKE_TAG} NO implementa backend nativo, tarpit ni .stok.key. Ver test/fake-smart-token/README.md.`,
].join('\n');

type GlobalOpts = { apiUrl: string; apiKey: string };

function parseGlobal(argv: string[]): { global: GlobalOpts; rest: string[] } {
  let apiUrl = process.env.SMART_TOKEN_API_URL ?? '';
  let apiKey = process.env.SMART_TOKEN_API_KEY ?? '';
  const rest: string[] = [];
  // Solo se consumen flags globales ANTES del subcomando; después de él,
  // todo pertenece al subcomando (p. ej. `serve --api-key K`).
  let seenCommand = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!seenCommand && (a === '--api-url' || a === '--api-key')) {
      if (a === '--api-url') apiUrl = argv[++i] ?? '';
      else apiKey = argv[++i] ?? '';
    } else {
      seenCommand = true;
      rest.push(a);
    }
  }
  return { global: { apiUrl, apiKey }, rest };
}

/** Parser mínimo estilo argparse: flags --x valor, -o valor, booleanos. */
function parseArgs(argv: string[]): { positional: string[]; flags: Record<string, string | boolean> } {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-o' || a === '--out') {
      flags['out'] = argv[++i] ?? '';
    } else if (a.startsWith('--')) {
      const key = a.slice(2);
      if (['force-failure', 'dry-run', 'down', 'help'].includes(key)) {
        flags[key] = true;
      } else {
        flags[key] = argv[++i] ?? '';
      }
    } else if (a.startsWith('-') && a.length > 1) {
      flags[a.slice(1)] = true;
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function masterFrom(flags: Record<string, string | boolean>, allowDemoDefault: boolean): string | null {
  if (typeof flags['master'] === 'string' && flags['master']) return flags['master'];
  const env = process.env.SMART_TOKEN_MASTER;
  if (env) return env;
  if (allowDemoDefault) {
    err('WARNING: using built-in demo-master-secret — NEVER use this for real data. Set --master or SMART_TOKEN_MASTER.');
    return 'demo-master-secret';
  }
  err('error: --master or SMART_TOKEN_MASTER is required (demo-master-secret is only for `smart-token demo`)');
  return null;
}

function requireApi(global: GlobalOpts): SmartTokenClient | null {
  if (!global.apiUrl) {
    err('error: SMART_TOKEN_API_URL / --api-url es obligatorio (la fake no tiene servidor implicito; usa `serve` o `demo`)');
    return null;
  }
  return new SmartTokenClient({ baseUrl: global.apiUrl, apiKey: global.apiKey });
}

function noteIgnored(flags: Record<string, string | boolean>): void {
  if (flags['backend'] && flags['backend'] !== 'auto') out(`nota: --backend ${flags['backend']} aceptado por compatibilidad; la fake no tiene backend nativo (siempre memoria)`);
  if (flags['tarpit-mode'] && flags['tarpit-mode'] !== 'off') out('nota: --tarpit-mode aceptado por compatibilidad; la fake NO implementa tarpit');
  if (typeof flags['key'] === 'string') out('nota: --key aceptado por compatibilidad; la fake no usa .stok.key (no hay sk fuera de banda)');
}

async function cmdServe(global: GlobalOpts, args: string[]): Promise<number> {
  const { flags } = parseArgs(args);
  const port = flags['port'] ? Number(flags['port']) : 0;
  const host = typeof flags['host'] === 'string' ? flags['host'] : '127.0.0.1';
  const apiKey =
    typeof flags['api-key'] === 'string'
      ? flags['api-key']
      : (global.apiKey || process.env.SMART_TOKEN_API_KEY || '');
  if (!apiKey) {
    err('error: serve exige --api-key o SMART_TOKEN_API_KEY (sin key el servidor responde 503 como el real)');
    return 2;
  }
  const fake = createFakeSmartTokenServer({ apiKey, down: Boolean(flags['down']) });
  const { url, port: bound } = await fake.listen(port, host);
  out(`FAKE Smart Token server listening on ${url} (api-key configurada, storage memory, down=${fake.isDown()})`);
  out(`FAKE ready port=${bound} url=${url}`);
  await new Promise<void>((resolve) => {
    const stop = () => resolve();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  await fake.close();
  out('FAKE server stopped');
  return 0;
}

async function cmdProtect(global: GlobalOpts, args: string[]): Promise<number> {
  const { positional, flags } = parseArgs(args);
  const input = positional[0];
  if (!input) {
    err('error: protect exige un archivo de entrada');
    return 2;
  }
  const master = masterFrom(flags, false);
  if (master === null) return 2;
  const client = requireApi(global);
  if (!client) return 2;
  noteIgnored(flags);
  let data: Buffer;
  try {
    data = readFileSync(input);
  } catch (e) {
    err(`error: no se pudo leer ${input}: ${(e as Error).message}`);
    return 2;
  }
  const file = new File([data], input.split('/').pop() ?? input, { type: 'application/octet-stream' });
  let result;
  try {
    result = await client.protect(file, master);
  } catch (e) {
    err(`error: ${(e as Error).message}`);
    return 1;
  }
  out(`Protegido: ${input}`);
  out(`  artifact_id: ${result.artifact_id}`);
  out(`  filename   : ${result.filename ?? ''}`);
  out(`  status     : ${result.status}`);
  out(`  origen     : ${data.length} bytes (guardado envuelto en memoria fake, no en .stok)`);
  const outPath = typeof flags['out'] === 'string' ? flags['out'] : `${input}.fake-stok.json`;
  writeFileSync(outPath, JSON.stringify({ artifact_id: result.artifact_id, filename: result.filename ?? null, status: result.status, fake: true }, null, 2));
  out(`  recibo     : ${outPath}`);
  return 0;
}

function resolveArtifactId(input: string): string | null {
  if (existsSync(input) && input.endsWith('.json')) {
    try {
      const parsed = JSON.parse(readFileSync(input, 'utf8')) as { artifact_id?: string };
      return parsed.artifact_id ?? null;
    } catch {
      return null;
    }
  }
  return input;
}

async function cmdOpen(global: GlobalOpts, args: string[]): Promise<number> {
  const { positional, flags } = parseArgs(args);
  const input = positional[0];
  if (!input) {
    err('error: open exige un artifact-id o un recibo .json');
    return 2;
  }
  const master = masterFrom(flags, false);
  if (master === null) return 2;
  const client = requireApi(global);
  if (!client) return 2;
  noteIgnored(flags);
  const artifactId = resolveArtifactId(input);
  if (!artifactId) {
    err(`error: no se pudo resolver artifact_id desde ${input}`);
    return 2;
  }
  const effectiveMaster = flags['force-failure'] ? `${master}-forced-wrong` : master;
  out(`Abriendo: ${artifactId}`);
  const t0 = performance.now();
  let result;
  try {
    result = await client.open(artifactId, effectiveMaster);
  } catch (e) {
    err(`error: ${(e as Error).message}`);
    return 1;
  }
  const elapsed = (performance.now() - t0) / 1000;
  if (result.ok) {
    const plaintext = Buffer.from(result.plaintext);
    out(`  Resultado       : OPEN — payload recuperado (${plaintext.length} bytes)`);
    if (typeof flags['out'] === 'string') {
      writeFileSync(flags['out'], plaintext);
      out(`  Escrito en      : ${flags['out']}`);
    } else {
      out('  payload         : no escrito en disco (usa -o para guardar el plaintext)');
    }
    out(`  Tiempo          : ${elapsed.toFixed(3)}s`);
    return 0;
  }
  out('  Resultado       : DENIED');
  out(`  Tiempo          : ${elapsed.toFixed(3)}s`);
  return 1;
}

async function cmdStatus(global: GlobalOpts, args: string[]): Promise<number> {
  const { positional } = parseArgs(args);
  const artifactId = positional[0];
  if (!artifactId) {
    err('error: status exige un artifact-id');
    return 2;
  }
  const client = requireApi(global);
  if (!client) return 2;
  let st: any;
  try {
    st = await client.friction(artifactId);
  } catch (e) {
    err(`error: ${(e as Error).message}`);
    return 1;
  }
  const snap = st.friction_snapshot ?? {};
  out(`Archivo : ${st.path ?? artifactId}`);
  out(`Label   : ${st.public_label ?? ''}`);
  out(`Coherencia objetivo : ${st.target_coherence ?? ''}`);
  out(`sk embebida en .stok : ${st.has_embedded_sk ?? false}`);
  out('Fricción (snapshot interno):');
  out(`  fail_count       : ${snap.fail_count ?? 0}`);
  out(`  recovery_tier    : ${snap.recovery_tier ?? 0}`);
  out(`  work_factor      : ${snap.work_factor ?? 1}`);
  out(`  cumulative_iters : ${snap.cumulative_iters ?? 0}`);
  out(`  stok_id          : ${snap.stok_id ?? ''}`);
  out(`  flag_fibonacci   : ${snap.flag_fibonacci ?? false}`);
  out(`  flag_persistencia: ${snap.flag_persistencia ?? false}`);
  out(`  tarpit_triggered : ${snap.tarpit_triggered ?? false}`);
  return 0;
}

async function cmdDemo(args: string[]): Promise<number> {
  const { positional, flags } = parseArgs(args);
  const sample = positional[0] ?? 'sample_cad.stl';
  const master = masterFrom(flags, true);
  if (master === null) return 2;
  noteIgnored(flags);
  if (!existsSync(sample)) {
    writeFileSync(sample, 'solid sample_tetrahedron\nendsolid sample_tetrahedron\n');
    out(`Creando archivo de muestra: ${sample}`);
  }
  const apiKey = `fake-demo-${Date.now()}`;
  const fake = createFakeSmartTokenServer({ apiKey });
  const { url } = await fake.listen(0, '127.0.0.1');
  const client = new SmartTokenClient({ baseUrl: url, apiKey });
  try {
    out('============================================================');
    out('1. PROTEGER archivo real');
    out('============================================================');
    const data = readFileSync(sample);
    const prot = await client.protect(new File([data], sample, { type: 'application/octet-stream' }), master);
    out(`   ${sample} (${data.length} B)`);
    out(`   → artifact_id ${prot.artifact_id}  [FAKE: en memoria, sin .stok ni .key]`);
    out('');
    out('============================================================');
    out('2. APERTURA LEGÍTIMA (master correcto)');
    out('============================================================');
    const t0 = performance.now();
    const opened = await client.open(prot.artifact_id, master);
    const elapsed = (performance.now() - t0) / 1000;
    if (!opened.ok) {
      err('error: la apertura legítima fue DENIED en la demo fake');
      return 1;
    }
    out(`   OK — OPEN (${Buffer.from(opened.plaintext).length} B) en ${elapsed.toFixed(3)}s`);
    out('');
    out('============================================================');
    out('3. INTENTOS ERRÓNEOS (denegación OPAQUE; sin trap en la fake)');
    out('============================================================');
    out('   La fake NO implementa hang de fase 3 ni validation ladder:');
    out('   cada intento incorrecto es DENIED y suma fail_count; el master');
    out('   correcto posterior abre de inmediato (ver README).');
    for (let i = 1; i <= 3; i++) {
      const wrong = await client.open(prot.artifact_id, `${master}-wrong-${i}`);
      out(`   Intento ${i}: ${wrong.ok ? 'OPEN (inesperado)' : 'DENIED'}`);
      if (wrong.ok) return 1;
    }
    const st: any = await client.friction(prot.artifact_id);
    out(`   status (inspección): tier=${st.recovery_tier} fail_count=${st.friction_snapshot?.fail_count} cum=${st.cumulative_iters}`);
    out('');
    out('============================================================');
    out('4. RECUPERACIÓN: el master correcto abre (sin ladder en la fake)');
    out('============================================================');
    const again = await client.open(prot.artifact_id, master);
    out(`   Validación 1/1 → ${again.ok ? 'OPEN' : 'DENIED'} (el real exigiría 4 tras 3 fallos)`);
    if (!again.ok) return 1;
    out('');
    out('============================================================');
    out('5. ESTADO FINAL');
    out('============================================================');
    const final: any = await client.friction(prot.artifact_id);
    out(`   ${JSON.stringify(final)}`);
    return 0;
  } finally {
    await fake.close();
  }
}

function cmdVersion(): number {
  out(`${FAKE_MIRRORS_REAL_VERSION} (FAKE — test only, mirrors Smart Token Prod ${FAKE_MIRRORS_REAL_VERSION})`);
  return 0;
}

async function cmdDoctor(global: GlobalOpts): Promise<number> {
  out('Smart Token Prod — doctor (FAKE)');
  let ok = true;
  try {
    const { pbkdf2Sync } = await import('node:crypto');
    pbkdf2Sync('x', 'y', 1, 32, 'sha256');
    out('  pbkdf2+aes-gcm   : OK (fake usa PBKDF2, no Argon2id ni ML-KEM)');
  } catch (e) {
    out(`  pbkdf2+aes-gcm   : FAIL (${(e as Error).message})`);
    ok = false;
  }
  out(`  fetch            : ${typeof fetch === 'function' ? 'OK' : 'FAIL'}`);
  if (typeof fetch !== 'function') ok = false;
  if (global.apiUrl) {
    try {
      const res = await fetch(`${global.apiUrl.replace(/\/+$/, '')}/healthz`);
      const body: any = await res.json().catch(() => ({}));
      out(`  fake server      : ${res.ok && body.ok ? 'OK' : `FAIL (HTTP ${res.status})`} (${global.apiUrl})`);
      if (!res.ok || !body.ok) ok = false;
    } catch (e) {
      out(`  fake server      : FAIL (${(e as Error).message})`);
      ok = false;
    }
  } else {
    out('  fake server      : sin SMART_TOKEN_API_URL (arranca con `serve`)');
  }
  out('status():');
  out(`  version: ${FAKE_MIRRORS_REAL_VERSION} (FAKE)`);
  out('  native_friction: false');
  out('  import_error: null');
  out('  role: sdk');
  out(`  available: ${ok}`);
  return ok ? 0 : 1;
}

function cmdPrintDep(args: string[]): number {
  const { flags } = parseArgs(args);
  if (typeof flags['editable'] === 'string') out(`nota: --editable ${flags['editable']} sin efecto en la fake (no hay paquete pip)`);
  out('FAKE: no hay paquete pip que instalar.');
  out('FAKE: usa el CLI con Node: node --experimental-strip-types test/fake-smart-token/fake-smart-token-cli.ts');
  out('FAKE: (el real imprime: pip install "smart-token-prod @ git+https://github.com/dcpracmatic-prog/Smart-Token-Prod.git@v0.10.5")');
  return 0;
}

function cmdIntegrate(args: string[]): number {
  const { positional, flags } = parseArgs(args);
  const root = positional[0];
  if (!root) {
    err('error: integrate exige un project_dir');
    return 2;
  }
  const bridge = typeof flags['bridge'] === 'string' ? flags['bridge'] : 'smart_token_bridge.py';
  out('smart-token integrate (FAKE — dry-run siempre; la fake NUNCA escribe en un proyecto)');
  out(`  root     : ${root}`);
  out(`  bridge   : ${bridge} (no creado)`);
  out('  dep      : (no instalada) la fake no tiene paquete pip');
  out('  next:');
  out('    - Usa el Smart Token real para integrar en un proyecto de verdad.');
  if (!flags['dry-run']) {
    err('error: la fake solo admite --dry-run; sin --dry-run no hace nada (exit 2)');
    return 2;
  }
  return 0;
}

async function cmdRepairMac(global: GlobalOpts, args: string[]): Promise<number> {
  const { positional, flags } = parseArgs(args);
  const artifactId = positional[0];
  if (!artifactId) {
    err('error: repair-mac exige un artifact-id');
    return 2;
  }
  noteIgnored(flags);
  const client = requireApi(global);
  if (!client) return 2;
  let st: any;
  try {
    st = await client.friction(artifactId);
  } catch (e) {
    err(`error: ${(e as Error).message}`);
    return 1;
  }
  const snap = st.friction_snapshot ?? {};
  out(`Repaired friction_mac: ${st.path ?? artifactId} (FAKE: no hay MAC real; solo lectura)`);
  out(`  fail_count       : ${snap.fail_count ?? 0}`);
  out(`  recovery_tier    : ${snap.recovery_tier ?? 0}`);
  out(`  cumulative_iters : ${snap.cumulative_iters ?? 0}`);
  out('  (debt preserved — use open with correct master to recover)');
  return 0;
}

async function main(): Promise<number> {
  const { global, rest } = parseGlobal(process.argv.slice(2));
  const [command, ...args] = rest;
  if (!command || command === '--help' || command === '-h' || command === 'help') {
    console.log(HELP);
    return command ? 0 : 2;
  }
  if (command === 'version') return cmdVersion();
  switch (command) {
    case 'serve':
      return cmdServe(global, args);
    case 'protect':
      return cmdProtect(global, args);
    case 'open':
      return cmdOpen(global, args);
    case 'status':
      return cmdStatus(global, args);
    case 'demo':
      return cmdDemo(args);
    case 'doctor':
      return cmdDoctor(global);
    case 'print-dep':
      return cmdPrintDep(args);
    case 'integrate':
      return cmdIntegrate(args);
    case 'repair-mac':
      return cmdRepairMac(global, args);
    default:
      err(`error: comando desconocido: ${command}`);
      console.log(HELP);
      return 2;
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e: unknown) => {
    err(`error: ${e instanceof Error ? e.message : String(e)}`);
    process.exitCode = 1;
  });
