/**
 * The Data Cryptographic Protocol (TDCP)
 * Oracle signing-key storage abstraction
 *
 * DEVELOPMENT ONLY in this build: keys live in process/browser memory.
 * Private keys are NEVER written to localStorage, IndexedDB, or the package.
 *
 * Production implementations (stubs below) must back the signing key with
 * HSM / KMS / platform Secure Key Store. They do not exist in this demo.
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
        false, // non-extractable even in development
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

/**
 * [PRODUCTION STUB — NOT IMPLEMENTED]
 * Would wrap AWS KMS / GCP KMS / Azure Key Vault asymmetric signing.
 */
export class KmsOracleKeyStore implements OracleKeyStore {
  public readonly kind = 'KMS' as const;
  public readonly isProductionGrade = true;
  public readonly developmentOnly = false;

  public getKeyId(): string {
    return 'ORACLE-KEY-KMS-UNIMPLEMENTED';
  }

  public async getOrCreateSigningKey(): Promise<CryptoKeyPair> {
    throw new Error(
      'KmsOracleKeyStore is a production stub. Wire a real KMS before deploying TDCP.'
    );
  }

  public async getPublicKey(): Promise<CryptoKey> {
    throw new Error(
      'KmsOracleKeyStore is a production stub. Wire a real KMS before deploying TDCP.'
    );
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
