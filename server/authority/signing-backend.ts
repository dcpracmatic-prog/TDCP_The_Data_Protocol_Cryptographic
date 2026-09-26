/**
 * Authority signing backend selection.
 *
 *   TDCP_SIGNING_BACKEND=file  → DurableFileOracleKeyStore (disk; encrypt with passphrase)
 *
 * AWS KMS is intentionally not a runtime dependency. External KMS/HSM can still
 * be plugged via a custom OracleKeyStore implementing signCanonical; this module
 * no longer instantiates AWS-oriented stubs by default.
 *
 * HONESTY: file JWK (even encrypted) is NOT HSM-grade.
 */

import type { OracleKeyStore } from '../../src/oracle/oracle-key-store.ts';
import type { DurableAuthoritySnapshot } from './durable-store.ts';
import type { DurableJsonAuthorityStore } from './durable-store.ts';
import { DurableFileOracleKeyStore } from './durable-key-store.ts';

export type SigningBackendKind = 'file';

export function readSigningBackendFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): SigningBackendKind {
  const raw = (env.TDCP_SIGNING_BACKEND || 'file').trim().toLowerCase();
  // Legacy aliases map to file; do not load AWS SDK or kms-stub runtime path
  if (raw === 'kms-stub' || raw === 'kms_stub' || raw === 'kms' || raw === 'aws') {
    console.warn(
      `[tdcp-authority] TDCP_SIGNING_BACKEND=${raw} is deprecated; using encrypted file store. Wire a custom OracleKeyStore for real KMS/HSM.`
    );
  }
  return 'file';
}

export function createAuthoritySigningKeyStore(options: {
  backend?: SigningBackendKind;
  snapshot: Pick<
    DurableAuthoritySnapshot,
    'keyId' | 'signingPrivateJwk' | 'signingPublicJwk' | 'signingPrivateJwkEnc'
  >;
  onPersist: (privateJwk: JsonWebKey, publicJwk: JsonWebKey) => void;
  store?: DurableJsonAuthorityStore;
}): OracleKeyStore {
  void options.backend;
  return new DurableFileOracleKeyStore(options.snapshot, options.onPersist, options.store);
}
