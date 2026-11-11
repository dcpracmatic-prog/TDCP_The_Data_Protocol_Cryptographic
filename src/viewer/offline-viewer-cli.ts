#!/usr/bin/env node
/**
 * CLI del generador del Visor HTML Offline.
 *
 * Uso:
 *   node --experimental-strip-types src/viewer/offline-viewer-cli.ts \
 *     --pkg <ruta.pkg.json> --out <ruta.html> \
 *     --master-env <VAR_CON_CONTRASENA_MAESTRA> --export-offline \
 *     [--policy-binding <ruta.json>] [--seal-required] \
 *     [--notary-pubkey-hex <hex>] [--csg-seal-url <url>] \
 *     [--authority-spki-base64 <b64>]
 *
 * La contrasena maestra se lee SOLO de la variable de entorno indicada
 * (--master-env): nunca de argv ni de logs. El custodio Smart Token se
 * resuelve del entorno (SMART_TOKEN_API_URL / SMART_TOKEN_API_KEY); sin
 * el, el comando falla cerrado.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { buildOfflineViewer } from './offline-viewer.ts';
import { smartTokenCekCustodianFromEnv } from '../protection/smart-token-cek-custody.ts';
import { deserializeTDCPPackage } from '../core/package/package-format.ts';
import type { PolicyBinding } from '../channel/policy-binding.ts';

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    if (key === 'export-offline' || key === 'seal-required' || key === 'help') {
      out[key] = true;
      continue;
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`CLI_ARG_MISSING_VALUE: --${key} exige un valor`);
    }
    out[key] = value;
    i++;
  }
  return out;
}

function usage(): string {
  return [
    'Uso: offline-viewer-cli.ts --pkg <ruta> --out <ruta.html> --master-env <VAR> --export-offline',
    '  [--policy-binding <ruta.json>] [--seal-required] [--notary-pubkey-hex <hex>]',
    '  [--csg-seal-url <url>] [--authority-spki-base64 <b64>]',
  ].join('\n');
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args['help']) {
    console.log(usage());
    return;
  }
  if (!args['export-offline']) {
    console.error(
      'OFFLINE_VIEWER_EXPORT_NOT_EXPLICIT: generar un visor offline es una exportacion deliberada; exige --export-offline'
    );
    console.error(usage());
    process.exitCode = 2;
    return;
  }
  const pkgPath = args['pkg'];
  const outPath = args['out'];
  const masterEnv = args['master-env'];
  if (typeof pkgPath !== 'string' || typeof outPath !== 'string' || typeof masterEnv !== 'string') {
    console.error('CLI_ARGS: faltan --pkg, --out o --master-env');
    console.error(usage());
    process.exitCode = 2;
    return;
  }
  const masterPassword = process.env[masterEnv];
  if (!masterPassword) {
    console.error(
      `OFFLINE_VIEWER_NO_MASTER: la variable de entorno ${masterEnv} esta vacia o no existe; la contrasena maestra nunca se pasa por argv`
    );
    process.exitCode = 2;
    return;
  }

  const parsed = await deserializeTDCPPackage(readFileSync(pkgPath, 'utf8'));
  if (!parsed.isValidEnvelope || !parsed.package) {
    console.error(`OFFLINE_VIEWER_BAD_PACKAGE: ${parsed.error ?? 'paquete invalido'}`);
    process.exitCode = 2;
    return;
  }

  let policyBinding: PolicyBinding | undefined;
  if (typeof args['policy-binding'] === 'string') {
    policyBinding = JSON.parse(readFileSync(args['policy-binding'], 'utf8')) as PolicyBinding;
  }

  const custodian = smartTokenCekCustodianFromEnv();
  if (!custodian) {
    console.error(
      'OFFLINE_VIEWER_NO_CUSTODIAN: SMART_TOKEN_API_URL / SMART_TOKEN_API_KEY no configurados; sin custodio no se puede obtener la CEK'
    );
    process.exitCode = 2;
    return;
  }

  const html = await buildOfflineViewer({
    pkg: parsed.package,
    masterPassword,
    cekCustodian: custodian,
    exportOffline: true,
    policyBinding,
    authorityPublicKeySpkiBase64:
      typeof args['authority-spki-base64'] === 'string' ? args['authority-spki-base64'] : undefined,
    notaryPublicKeyHex:
      typeof args['notary-pubkey-hex'] === 'string' ? args['notary-pubkey-hex'] : undefined,
    csgSealUrl: typeof args['csg-seal-url'] === 'string' ? args['csg-seal-url'] : undefined,
    sealMode: args['seal-required'] ? 'required' : 'optional',
  });
  writeFileSync(outPath, html, 'utf8');
  console.log(
    `Visor offline generado: ${outPath} (documento ${parsed.package.documentId}, paquete ${parsed.package.packageId})`
  );
}

main().catch((err: unknown) => {
  console.error(`OFFLINE_VIEWER_FAILED: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = 1;
});
