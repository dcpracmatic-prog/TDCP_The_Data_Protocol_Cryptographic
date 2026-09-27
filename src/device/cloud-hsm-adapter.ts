/**
 * Multi-vendor Cloud HSM adapter interface.
 *
 * Concrete AWS/Azure/GCP/Vault SDKs are NOT bundled. Adapters document the
 * contract and throw until the operator injects a real implementation
 * (server-side Authority). Browser builds remain developmentOnly.
 */

import type { CloudHsmVendor } from '../lib/security-device-prefs.ts';

export interface CloudHsmAdapterConfig {
  vendor: CloudHsmVendor;
  regionOrNamespace: string;
  keyIdOrAlias: string;
  endpoint?: string;
  /** Optional credentials handle — never log or persist in browser demos. */
  credentialsRef?: string;
}

export interface CloudHsmSignRequest {
  /** Canonical bytes to sign (e.g. TDCP grant payload). */
  message: Uint8Array;
  /** Hash algorithm hint (default SHA-256). */
  hash?: 'SHA-256' | 'SHA-384' | 'SHA-512';
}

export interface CloudHsmSignResult {
  signature: Uint8Array;
  keyId: string;
  vendor: CloudHsmVendor;
  algorithm: string;
}

export interface CloudHsmAdapter {
  readonly vendor: CloudHsmVendor;
  readonly developmentOnly: boolean;
  readonly isConfigured: boolean;
  describe(): string;
  sign(request: CloudHsmSignRequest): Promise<CloudHsmSignResult>;
  getPublicKeySpki?(): Promise<Uint8Array>;
}

abstract class BaseCloudHsmAdapter implements CloudHsmAdapter {
  abstract readonly vendor: CloudHsmVendor;
  readonly developmentOnly = true;
  protected readonly config: CloudHsmAdapterConfig;

  constructor(config: CloudHsmAdapterConfig) {
    this.config = config;
  }

  get isConfigured(): boolean {
    return Boolean(this.config.keyIdOrAlias?.trim() && this.config.regionOrNamespace?.trim());
  }

  describe(): string {
    return `${this.vendor} key=${this.config.keyIdOrAlias || '(unset)'} region=${this.config.regionOrNamespace || '(unset)'}`;
  }

  async sign(_request: CloudHsmSignRequest): Promise<CloudHsmSignResult> {
    throw new Error(
      `CloudHSM adapter ${this.vendor} is not wired with a real SDK. ` +
        `Configure server-side Authority OracleKeyStore.signCanonical for production. ` +
        `Config: ${this.describe()}`
    );
  }
}

export class AwsKmsAdapter extends BaseCloudHsmAdapter {
  readonly vendor = 'aws-kms' as const;
}

export class AzureKeyVaultAdapter extends BaseCloudHsmAdapter {
  readonly vendor = 'azure-keyvault' as const;
}

export class GcpKmsAdapter extends BaseCloudHsmAdapter {
  readonly vendor = 'gcp-kms' as const;
}

export class HashicorpVaultAdapter extends BaseCloudHsmAdapter {
  readonly vendor = 'hashicorp-vault' as const;
}

export function createCloudHsmAdapter(config: CloudHsmAdapterConfig): CloudHsmAdapter {
  switch (config.vendor) {
    case 'aws-kms':
      return new AwsKmsAdapter(config);
    case 'azure-keyvault':
      return new AzureKeyVaultAdapter(config);
    case 'gcp-kms':
      return new GcpKmsAdapter(config);
    case 'hashicorp-vault':
      return new HashicorpVaultAdapter(config);
    default: {
      const _exhaustive: never = config.vendor;
      throw new Error(`Unknown Cloud HSM vendor: ${String(_exhaustive)}`);
    }
  }
}

/** Resolve adapter from persisted security-device prefs cloud block. */
export function cloudHsmAdapterFromPrefs(cloud: {
  vendor: CloudHsmVendor;
  regionOrNamespace: string;
  keyIdOrAlias: string;
  endpoint?: string;
}): CloudHsmAdapter {
  return createCloudHsmAdapter({
    vendor: cloud.vendor,
    regionOrNamespace: cloud.regionOrNamespace,
    keyIdOrAlias: cloud.keyIdOrAlias,
    endpoint: cloud.endpoint,
  });
}
