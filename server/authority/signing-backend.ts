/**
 * Authority signing backend selection.
 *
 *   TDCP_SIGNING_BACKEND=file      → DurableFileOracleKeyStore (extractable JWK on disk)
 *   TDCP_SIGNING_BACKEND=kms-stub  → KmsOracleKeyStore stub (documents AWS KMS hook; no AWS creds)
 *
 * HONESTY: file JWK is NOT production-grade. kms-stub is NOT a real KMS.
 */

import type { OracleKeyStore } from '../../src/oracle/oracle-key-store.ts';
import { KmsOracleKeyStore } from '../../src/oracle/oracle-key-store.ts';
import type { DurableAuthoritySnapshot } from './durable-store.ts';
import { DurableFileOracleKeyStore } from './durable-key-store.ts';

export type SigningBackendKind = 'file' | 'kms-stub';

export function readSigningBackendFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): SigningBackendKind {
  const raw = (env.TDCP_SIGNING_BACKEND || 'file').trim().toLowerCase();
  if (raw === 'kms-stub' || raw === 'kms_stub' || raw === 'kms') return 'kms-stub';
  return 'file';
}

export function createAuthoritySigningKeyStore(options: {
  backend?: SigningBackendKind;
  snapshot: Pick<DurableAuthoritySnapshot, 'keyId' | 'signingPrivateJwk' | 'signingPublicJwk'>;
  onPersist: (privateJwk: JsonWebKey, publicJwk: JsonWebKey) => void;
}): OracleKeyStore {
  const backend = options.backend ?? readSigningBackendFromEnv();
  if (backend === 'kms-stub') {
    return new KmsOracleKeyStore({
      mode: 'stub',
      keyId: options.snapshot.keyId || 'AUTHORITY-KEY-KMS-STUB',
    });
  }
  return new DurableFileOracleKeyStore(options.snapshot, options.onPersist);
}
