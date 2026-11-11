/**
 * Example: CSG / Sello sidecar end-to-end check from TDCP.
 * Seals a sample content via CsgClient, verifies it OK, then verifies
 * altered content and expects todo_valido === false.
 *
 * Requires the Rust CSG sidecar running on loopback:
 *   cd <CSG repo>/sidecar && CSG_PORT=8010 ./target/release/csg-sidecar
 * (or the in-repo Python sidecar: python3 server/csg-sidecar/main.py)
 *
 * Usage (from repo root, with Node that supports strip-types):
 *   CSG_SEAL_URL=http://127.0.0.1:8010 \
 *   node --experimental-strip-types examples/csg-seal-verify-example.ts
 *
 * For the full package flow (seal embedded in the .pkg, verified by the
 * Gatekeeper before decrypt), see scripts/csg-pkg-smoke.mjs
 * (`npm run smoke:csg-pkg`).
 */

import { CsgClient, csgClientFromEnv } from '../src/protection/csg-client.ts';

async function main(): Promise<void> {
  const client =
    csgClientFromEnv() ??
    new CsgClient({ baseUrl: process.env.CSG_SEAL_URL ?? 'http://127.0.0.1:8010' });

  const health = await client.healthz();
  console.log('CSG healthz:', health);
  if (!health.ok) throw new Error('CSG sidecar not healthy');

  const content = new TextEncoder().encode('TDCP e2e: grant-issue attestation sample');
  const sello = await client.seal(content, {
    label: 'tdcp-e2e',
    attributes: { ejemplo: 'grant-issue' },
    proyecto_id: 'tdcp',
  });
  console.log('seal:', {
    schema: sello.schema,
    evento_id: sello.evento_id,
    aceptado: sello.aceptado,
    hash_contenido: sello.hash_contenido.slice(0, 16) + '...',
  });
  if (!sello.aceptado) throw new Error(`seal rejected: ${sello.razon}`);

  const ok = await client.verify(content, sello);
  console.log('verify original:', ok);
  if (!ok.todo_valido) throw new Error('original content must verify');

  const altered = new TextEncoder().encode('TDCP e2e: grant-issue attestation sample ALTERADO');
  const bad = await client.verify(altered, sello);
  console.log('verify altered:', bad);
  if (bad.todo_valido) throw new Error('altered content must NOT verify');
  if (bad.checks.content_digest_match !== false) {
    throw new Error('altered content must fail content_digest_match');
  }

  console.log('CSG e2e OK: seal -> verify true, altered -> verify false.');
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
