/**
 * Example: optional Smart Token client against a self-hosted API.
 * Does not bypass Gatekeeper. Run Smart Token API locally first:
 *   uvicorn api.main:app --host 127.0.0.1 --port 8000
 *
 * Usage (from repo root, with Node that supports strip-types):
 *   SMART_TOKEN_API_URL=http://127.0.0.1:8000 \
 *   SMART_TOKEN_API_KEY=... \
 *   node --experimental-strip-types examples/smart-token-bridge-example.ts
 */

import { SmartTokenClient, smartTokenClientFromEnv } from '../sdk/typescript/src/index.ts';

async function main(): Promise<void> {
  const client =
    smartTokenClientFromEnv() ??
    new SmartTokenClient({
      baseUrl: process.env.SMART_TOKEN_API_URL ?? 'http://127.0.0.1:8000',
      apiKey: process.env.SMART_TOKEN_API_KEY ?? '',
    });

  const health = await client.healthz();
  console.log('Smart Token healthz:', health);

  // protect/open require a real master and are intentionally not hard-coded here.
  // After a successful TDCP Gatekeeper grant, an integrator may call:
  //   const result = await client.open(artifactId, masterFromOperatorPath);
  console.log(
    'Bridge ready. Use protect/open only after Gatekeeper authorization; never cache master in TDCP state.'
  );
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
