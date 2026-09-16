/**
 * File-backed ECDSA P-256 signing key for Authority durability across restarts.
 * DEVELOPMENT ONLY — extractable JWK on disk. Not HSM/KMS.
 */

import type { OracleKeyStore } from '../../src/oracle/oracle-key-store.ts';
import type { DurableAuthoritySnapshot } from './durable-store.ts';

export class DurableFileOracleKeyStore implements OracleKeyStore {
  public readonly kind = 'DEVELOPMENT_IN_MEMORY' as const;
  public readonly isProductionGrade = false;
  public readonly developmentOnly = true;

  private keyPair: CryptoKeyPair | null = null;
  private readonly keyId: string;
  private privateJwk: JsonWebKey | null;
  private publicJwk: JsonWebKey | null;
  private readonly onPersist: (privateJwk: JsonWebKey, publicJwk: JsonWebKey) => void;

  constructor(
    snapshot: Pick<DurableAuthoritySnapshot, 'keyId' | 'signingPrivateJwk' | 'signingPublicJwk'>,
    onPersist: (privateJwk: JsonWebKey, publicJwk: JsonWebKey) => void
  ) {
    this.keyId = snapshot.keyId || 'AUTHORITY-KEY-P256-DURABLE-DEV';
    this.privateJwk = snapshot.signingPrivateJwk;
    this.publicJwk = snapshot.signingPublicJwk;
    this.onPersist = onPersist;
  }

  public getKeyId(): string {
    return this.keyId;
  }

  public async getOrCreateSigningKey(): Promise<CryptoKeyPair> {
    if (this.keyPair) return this.keyPair;

    if (this.privateJwk && this.publicJwk) {
      const privateKey = await crypto.subtle.importKey(
        'jwk',
        this.privateJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
      );
      const publicKey = await crypto.subtle.importKey(
        'jwk',
        this.publicJwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      );
      this.keyPair = { privateKey, publicKey };
      return this.keyPair;
    }

    this.keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, // extractable for durable DEV persistence only
      ['sign', 'verify']
    );
    this.privateJwk = await crypto.subtle.exportKey('jwk', this.keyPair.privateKey);
    this.publicJwk = await crypto.subtle.exportKey('jwk', this.keyPair.publicKey);
    this.onPersist(this.privateJwk, this.publicJwk);
    return this.keyPair;
  }

  public async getPublicKey(): Promise<CryptoKey> {
    const pair = await this.getOrCreateSigningKey();
    return pair.publicKey;
  }
}
