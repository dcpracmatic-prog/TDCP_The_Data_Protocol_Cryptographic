#!/usr/bin/env node
/**
 * Fake LOCAL-COMMAND signer (tests / local demo only — P0-2).
 *
 * Protocol (the same one ExternalOracleKeyStore expects from any local
 * signer command):
 *   - argv: node fake-cmd-signer.mjs <private-jwk-file>
 *   - stdin: the canonical UTF-8 bytes to sign
 *   - stdout: ONE line — the raw ECDSA P-256 signature (r||s) in base64
 *
 * The private JWK file is created by the caller (e.g. a test that generates
 * an ephemeral keypair); this script never generates or persists keys.
 * NOT production: the key sits in a file the operator controls.
 */

import { readFileSync } from 'node:fs';

const keyFile = process.argv[2];
if (!keyFile) {
  console.error('Usage: node fake-cmd-signer.mjs <private-jwk-file>');
  process.exit(2);
}

const jwk = JSON.parse(readFileSync(keyFile, 'utf8'));
const privateKey = await crypto.subtle.importKey(
  'jwk',
  jwk,
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,
  ['sign']
);

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const canonical = Buffer.concat(chunks).toString('utf8');
if (!canonical) {
  console.error('No canonical bytes on stdin.');
  process.exit(2);
}

const sig = await crypto.subtle.sign(
  { name: 'ECDSA', hash: 'SHA-256' },
  privateKey,
  new TextEncoder().encode(canonical)
);
process.stdout.write(`${Buffer.from(sig).toString('base64')}\n`);
