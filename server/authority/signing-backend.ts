/**
 * Authority signing backend selection.
 *
 *   TDCP_SIGNING_BACKEND=file      → DurableFileOracleKeyStore (disk; encrypt with passphrase)
 *   TDCP_SIGNING_BACKEND=external  → ExternalOracleKeyStore (sidecar / local signer; the key
 *                                     never enters this process — see external-signing-backend.ts)
 *
 * AWS KMS is intentionally not a runtime dependency: the `external` backend
 * talks to a sidecar over plain HTTP (or a local command), and the sidecar
 * is the only process that touches AWS credentials. No AWS SDK in this repo.
 *
 * HONESTY: file JWK (even encrypted) is NOT HSM-grade. The `external`
 * backend is production-grade ONLY when the operator attests the signer
 * is a real KMS/HSM (TDCP_SIGNING_EXTERNAL_ATTESTED=true).
 *
 * FAIL CLOSED: an unknown TDCP_SIGNING_BACKEND value, or an `external`
 * backend without its URL/command (or with a bad one), throws at startup
 * instead of silently signing with a different backend.
 */

import type { OracleKeyStore } from '../../src/oracle/oracle-key-store.ts';
import type { DurableAuthoritySnapshot, DurableAuthorityStore } from './durable-store.ts';
import { DurableFileOracleKeyStore } from './durable-key-store.ts';
import {
  ExternalOracleKeyStore,
  readExternalSigningConfigFromEnv,
} from './external-signing-backend.ts';

export type SigningBackendKind = 'file' | 'external';

export function readSigningBackendFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): SigningBackendKind {
  const raw = (env.TDCP_SIGNING_BACKEND || 'file').trim().toLowerCase();
  // Legacy aliases map to file; do not load AWS SDK or kms-stub runtime path.
  // They stay only so old deployments keep booting; new setups use file|external.
  if (raw === 'kms-stub' || raw === 'kms_stub' || raw === 'kms' || raw === 'aws') {
    console.warn(
      `[tdcp-authority] TDCP_SIGNING_BACKEND=${raw} is deprecated; using encrypted file store. ` +
        'Wire TDCP_SIGNING_BACKEND=external with a real KMS/HSM sidecar for production signing.'
    );
    return 'file';
  }
  if (raw === 'file') return 'file';
  if (raw === 'external') {
    // Validate the external config now: a misconfigured signer must fail
    // startup, never the first grant request (and never fall back to file).
    readExternalSigningConfigFromEnv(env);
    return 'external';
  }
  throw new Error(
    `[tdcp-authority] Unknown TDCP_SIGNING_BACKEND=${JSON.stringify(raw)}. ` +
      'Expected "file" or "external". Refusing to start with an unknown signing backend.'
  );
}

export function createAuthoritySigningKeyStore(options: {
  backend?: SigningBackendKind;
  snapshot: Pick<
    DurableAuthoritySnapshot,
    'keyId' | 'signingPrivateJwk' | 'signingPublicJwk' | 'signingPrivateJwkEnc'
  >;
  onPersist: (privateJwk: JsonWebKey, publicJwk: JsonWebKey) => void | Promise<void>;
  store?: DurableAuthorityStore;
}): OracleKeyStore {
  if (options.backend === 'external') {
    // The file snapshot is ignored: the key lives in the external signer,
    // and onPersist is never called because no private key exists here.
    return new ExternalOracleKeyStore(readExternalSigningConfigFromEnv());
  }
  return new DurableFileOracleKeyStore(options.snapshot, options.onPersist, options.store);
}
