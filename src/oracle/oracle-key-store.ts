/**
 * The Data Cryptographic Protocol (TDCP)
 * Oracle signing-key storage abstraction
 *
 * DEVELOPMENT ONLY in this build: keys live in process/browser memory or
 * durable file JWK (Authority MVP). Private keys must NEVER ship to browsers
 * as production Authority material.
 *
 * Production: plug AWS KMS / CloudHSM / platform Secure Key Store via
 * OracleKeyStore (prefer signCanonical when private key is non-exportable).
 */

export type OracleKeyStoreKind =
  | 'DEVELOPMENT_IN_MEMORY'
  | 'HSM'
  | 'KMS'
  | 'SECURE_KEY_STORE';

export interface OracleKeyStore {
  readonly kind: OracleKeyStoreKind;
  readonly isProductionGrade: boolean;
  readonly developmentOnly: boolean;
  getKeyId(): string;
  getOrCreateSigningKey(): Promise<CryptoKeyPair>;
  getPublicKey(): Promise<CryptoKey>;
  /**
   * Optional: sign canonical grant bytes without exporting a private CryptoKey.
   * Real KMS backends should implement this (e.g. AWS KMS Sign).
   * When absent, AuthorizationOracle falls back to local ECDSA with the key pair.
   */
  signCanonical?(canonicalUtf8: string): Promise<ArrayBuffer>;
}

/**
 * [DEVELOPMENT ONLY]
 * Ephemeral ECDSA P-256 keypair held in RAM for the lifetime of the page.
 * Refreshing the tab rotates the Oracle identity. Never persist this key.
 */
export class DevelopmentInMemoryOracleKeyStore implements OracleKeyStore {
  public readonly kind = 'DEVELOPMENT_IN_MEMORY' as const;
  public readonly isProductionGrade = false;
  public readonly developmentOnly = true;

  private keyPair: CryptoKeyPair | null = null;
  private readonly keyId = 'ORACLE-KEY-P256-v2.5-DEV';

  public getKeyId(): string {
    return this.keyId;
  }

  public async getOrCreateSigningKey(): Promise<CryptoKeyPair> {
    if (!this.keyPair) {
      this.keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );
    }
    return this.keyPair;
  }

  public async getPublicKey(): Promise<CryptoKey> {
    const pair = await this.getOrCreateSigningKey();
    return pair.publicKey;
  }
}

/**
 * [PRODUCTION STUB — NOT IMPLEMENTED]
 * Would wrap a PKCS#11 / CloudHSM signing handle. Calling any method throws.
 */
export class HsmOracleKeyStore implements OracleKeyStore {
  public readonly kind = 'HSM' as const;
  public readonly isProductionGrade = true;
  public readonly developmentOnly = false;

  public getKeyId(): string {
    return 'ORACLE-KEY-HSM-UNIMPLEMENTED';
  }

  public async getOrCreateSigningKey(): Promise<CryptoKeyPair> {
    throw new Error(
      'HsmOracleKeyStore is a production stub. Wire a real HSM before deploying TDCP.'
    );
  }

  public async getPublicKey(): Promise<CryptoKey> {
    throw new Error(
      'HsmOracleKeyStore is a production stub. Wire a real HSM before deploying TDCP.'
    );
  }
}

export interface KmsOracleKeyStoreOptions {
  /**
   * `stub` — local ECDSA that documents the KMS Sign hook (no AWS credentials).
   * `aws` — reserved; throws until a real AWS KMS client is wired.
   */
  mode?: 'stub' | 'aws';
  keyId?: string;
  /** Future: AWS KMS key ARN / alias. Ignored in stub mode. */
  kmsKeyId?: string;
  region?: string;
}

/**
 * KMS signing backend.
 *
 * - mode=`stub` (TDCP_SIGNING_BACKEND=kms-stub): holds an in-process ECDSA P-256
 *   key and implements `signCanonical` as the hook AWS KMS Sign would replace.
 *   **Not production-grade** — no AWS credentials, no remote KMS.
 * - mode=`aws`: throws until a real AWS SDK Sign path is implemented.
 *
 * Production plug-in checklist:
 * 1. Call KMS Sign (ECDSA_SHA_256) on the canonical grant UTF-8 bytes.
 * 2. Never export the private key to the Authority process.
 * 3. Expose verify material via GetPublicKey → SPKI for clients.
 */
export class KmsOracleKeyStore implements OracleKeyStore {
  public readonly kind = 'KMS' as const;
  public readonly isProductionGrade: boolean;
  public readonly developmentOnly: boolean;

  private readonly mode: 'stub' | 'aws';
  private readonly keyId: string;
  private readonly kmsKeyId?: string;
  private readonly region?: string;
  private keyPair: CryptoKeyPair | null = null;

  constructor(options: KmsOracleKeyStoreOptions = {}) {
    this.mode = options.mode ?? 'aws';
    this.keyId =
      options.keyId ||
      (this.mode === 'stub' ? 'AUTHORITY-KEY-KMS-STUB' : 'ORACLE-KEY-KMS-UNIMPLEMENTED');
    this.kmsKeyId = options.kmsKeyId;
    this.region = options.region;
    if (this.mode === 'stub') {
      this.isProductionGrade = false;
      this.developmentOnly = true;
    } else {
      this.isProductionGrade = true;
      this.developmentOnly = false;
    }
  }

  public getKeyId(): string {
    return this.keyId;
  }

  public async getOrCreateSigningKey(): Promise<CryptoKeyPair> {
    if (this.mode === 'aws') {
      throw new Error(
        'KmsOracleKeyStore aws mode is not wired. Use TDCP_SIGNING_BACKEND=kms-stub for the documented hook, or implement AWS KMS Sign.'
      );
    }
    if (!this.keyPair) {
      this.keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );
    }
    return this.keyPair;
  }

  public async getPublicKey(): Promise<CryptoKey> {
    const pair = await this.getOrCreateSigningKey();
    return pair.publicKey;
  }

  /**
   * Hook point for AWS KMS Sign (ECDSA_SHA_256 over SHA-256 digest of canonical bytes).
   * Stub: local WebCrypto ECDSA. Production: replace body with KMS Sign API call.
   */
  public async signCanonical(canonicalUtf8: string): Promise<ArrayBuffer> {
    if (this.mode === 'aws') {
      throw new Error(
        `KmsOracleKeyStore.signCanonical aws mode not implemented (kmsKeyId=${this.kmsKeyId ?? 'unset'}, region=${this.region ?? 'unset'}).`
      );
    }
    const pair = await this.getOrCreateSigningKey();
    const data = new TextEncoder().encode(canonicalUtf8);
    return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data);
  }
}

/**
 * [PRODUCTION STUB — NOT IMPLEMENTED]
 * Would wrap a platform Secure Enclave / TPM-backed non-exportable key.
 */
export class SecureKeyStoreOracleKeyStore implements OracleKeyStore {
  public readonly kind = 'SECURE_KEY_STORE' as const;
  public readonly isProductionGrade = true;
  public readonly developmentOnly = false;

  public getKeyId(): string {
    return 'ORACLE-KEY-SKS-UNIMPLEMENTED';
  }

  public async getOrCreateSigningKey(): Promise<CryptoKeyPair> {
    throw new Error(
      'SecureKeyStoreOracleKeyStore is a production stub. Wire a hardware-backed key store before deploying TDCP.'
    );
  }

  public async getPublicKey(): Promise<CryptoKey> {
    throw new Error(
      'SecureKeyStoreOracleKeyStore is a production stub. Wire a hardware-backed key store before deploying TDCP.'
    );
  }
}
