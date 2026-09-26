/**
 * File-backed ECDSA P-256 signing key for Authority durability across restarts.
 * Private JWK is encrypted at rest when TDCP_AUTHORITY_KEY_PASSPHRASE is set.
 * Not HSM / not AWS KMS — local disk only.
 */

import type { OracleKeyStore } from '../../src/oracle/oracle-key-store.ts';
import type { DurableAuthoritySnapshot } from './durable-store.ts';
import { DurableJsonAuthorityStore } from './durable-store.ts';

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
    snapshot: Pick<
      DurableAuthoritySnapshot,
      'keyId' | 'signingPrivateJwk' | 'signingPublicJwk' | 'signingPrivateJwkEnc'
    >,
    onPersist: (privateJwk: JsonWebKey, publicJwk: JsonWebKey) => void,
    store?: DurableJsonAuthorityStore
  ) {
    this.keyId = snapshot.keyId || 'AUTHORITY-KEY-P256-DURABLE-DEV';
    this.publicJwk = snapshot.signingPublicJwk;
    this.onPersist = onPersist;

    // Resolve private material (encrypted or plaintext)
    if (store) {
      try {
        this.privateJwk = store.resolvePrivateJwk(snapshot as DurableAuthoritySnapshot);
      } catch (err) {
        console.error('[tdcp-authority] Failed to resolve private JWK:', err);
        this.privateJwk = null;
      }
    } else {
      this.privateJwk = snapshot.signingPrivateJwk;
    }
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
      true, // extractable for durable persistence only
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
