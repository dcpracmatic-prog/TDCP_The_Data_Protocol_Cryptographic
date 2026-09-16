/**
 * The Data Cryptographic Protocol (TDCP)
 * Device Identity Provider Abstraction & Implementations
 *
 * NOTICE:
 * MockDeviceIdentityProvider is for DEMO / MOCK / DEVELOPMENT ONLY.
 * navigator.userAgent is NOT a cryptographic identity and is never used as one.
 */

import type { DeviceIdentity } from '../core/authorization/types.ts';
import { computeSHA256 } from '../core/crypto/primitives.ts';

export interface DeviceIdentityProvider {
  providerName: string;
  isHardwareBacked: boolean;
  getDeviceIdentity(): Promise<DeviceIdentity>;
}

/**
 * [DEMO / MOCK / DEVELOPMENT ONLY]
 * Deterministic device identity for local testing and demonstration.
 */
export class MockDeviceIdentityProvider implements DeviceIdentityProvider {
  public providerName = 'MockDeviceIdentityProvider (DEMO / MOCK / DEVELOPMENT ONLY)';
  public isHardwareBacked = false;

  private mockDeviceId: string = 'DEV-STATION-SECTOR-4';

  public setDeviceId(id: string): void {
    this.mockDeviceId = id;
  }

  public async getDeviceIdentity(): Promise<DeviceIdentity> {
    const digest = await computeSHA256(`MOCK_DEVICE_ROOT::${this.mockDeviceId}`);
    return {
      deviceId: this.mockDeviceId,
      hardwareBacked: false,
      platform: 'TDCP-Web-Dev-Sandbox',
      fingerprintDigest: digest,
      attestationType: 'MOCK_DEVELOPMENT',
    };
  }
}

/**
 * [PRODUCTION HARDWARE INTEGRATION STUB]
 * Requires a previously enrolled non-exportable WebAuthn credential.
 * Does not fall back to userAgent.
 */
export class WebAuthnDeviceIdentityProvider implements DeviceIdentityProvider {
  public providerName = 'WebAuthnDeviceIdentityProvider (Hardware Attestation STUB)';
  public isHardwareBacked = true;

  public async getDeviceIdentity(): Promise<DeviceIdentity> {
    if (typeof window === 'undefined' || !window.PublicKeyCredential) {
      throw new Error(
        'WebAuthnDeviceIdentityProvider: hardware attestation no está disponible. Use MockDeviceIdentityProvider (DEVELOPMENT ONLY).'
      );
    }

    throw new Error(
      'WebAuthnDeviceIdentityProvider is a production stub: no enrolled non-exportable device credential exists in this build. navigator.userAgent is intentionally NOT used as a cryptographic identity.'
    );
  }
}
