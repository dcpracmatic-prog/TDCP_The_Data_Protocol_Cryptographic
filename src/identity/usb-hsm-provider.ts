/**
 * Browser side of the USB-HSM (the user's hardware ID) and the account
 * credential that replaces the old NFC card.
 *
 *  - AccountCredentialProvider: the credential is the signed-in TDCP account
 *    (`ACCOUNT-<userId>`), verified by the Authority from the session token.
 *  - UsbHsmProver: enrolls a USB security key and, when a policy requires it,
 *    asks the key to sign usbHsmChallenge(request) (WebAuthn, UV required).
 *
 * No private key ever exists in the browser: it lives in the USB secure element.
 */

import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
} from '@simplewebauthn/browser';
import type { DeviceIdentity, UserCredential } from '../core/authorization/types.ts';
import {
  usbHsmChallenge,
  usbHsmDeviceIdFromCredentialId,
  type UsbHsmAssertion,
  type UsbHsmAuthorizationContext,
  type UsbHsmDeviceInfo,
} from '../core/authorization/usb-hsm.ts';
import type { NFCProvider } from './credential-provider.ts';
import type { DeviceIdentityProvider } from './device-identity-provider.ts';
import type { HttpAuthorityClient } from '../authority/http-authority-client.ts';

/** Credential = verified account (replaces the NFC card). */
export class AccountCredentialProvider implements NFCProvider {
  public providerName = 'Cuenta TDCP (sesión verificada por el Authority)';
  public isHardwareBacked = false;
  private account: { userId: string; email: string } | null = null;

  public setAccount(account: { userId: string; email: string } | null): void {
    this.account = account;
  }

  public async isAvailable(): Promise<boolean> {
    return this.account !== null;
  }

  public async readCredential(): Promise<UserCredential> {
    if (!this.account) throw new Error('Inicia sesión para usar tu cuenta como credencial.');
    return {
      credentialId: `ACCOUNT-${this.account.userId}`,
      holderName: this.account.email,
      credentialType: 'ACCOUNT_SESSION',
      assignedRole: 'OPERATOR',
      isSimulated: false,
    };
  }
}

/** Device identity for documents that do not require a USB-HSM. */
export class BrowserSessionDeviceProvider implements DeviceIdentityProvider {
  public providerName = 'Navegador (sin USB-HSM)';
  public isHardwareBacked = false;
  private readonly deviceId = `WEB-${crypto.getRandomValues(new Uint32Array(2)).join('')}`;

  public async getDeviceIdentity(): Promise<DeviceIdentity> {
    return {
      deviceId: this.deviceId,
      hardwareBacked: false,
      platform: 'browser-session',
      fingerprintDigest: this.deviceId,
      attestationType: 'BROWSER_SESSION',
    };
  }
}

export interface UsbHsmProof {
  deviceId: string;
  assertion: UsbHsmAssertion;
}

export type UsbHsmProverFn = (ctx: UsbHsmAuthorizationContext) => Promise<UsbHsmProof>;

function friendlyWebAuthnError(err: unknown): Error {
  const name = (err as { name?: string })?.name;
  if (name === 'NotAllowedError') {
    return new Error('Operación cancelada o sin respuesta del USB-HSM (tiempo agotado).');
  }
  if (name === 'InvalidStateError') {
    return new Error('Este USB-HSM ya está registrado en tu cuenta.');
  }
  if (name === 'SecurityError') {
    return new Error('El dominio no coincide con el configurado para USB-HSM (TDCP_WEBAUTHN_RP_ID).');
  }
  return err instanceof Error ? err : new Error(String(err));
}

export class UsbHsmProver {
  private readonly authority: HttpAuthorityClient;

  constructor(authority: HttpAuthorityClient) {
    this.authority = authority;
  }

  public static isSupported(): boolean {
    return typeof window !== 'undefined' && browserSupportsWebAuthn();
  }

  public list(): Promise<UsbHsmDeviceInfo[]> {
    return this.authority.listUsbHsm();
  }

  /** "Convertir mi USB en mi ID": create a non-exportable key in the USB and bind it. */
  public async enroll(label: string, replaceDeviceId?: string): Promise<UsbHsmDeviceInfo> {
    if (!UsbHsmProver.isSupported()) throw new Error('Este navegador no soporta WebAuthn.');
    const optionsJSON = await this.authority.usbHsmRegistrationOptions({ label, replaceDeviceId });
    let response;
    try {
      response = await startRegistration({ optionsJSON });
    } catch (err) {
      throw friendlyWebAuthnError(err);
    }
    return this.authority.registerUsbHsm(response);
  }

  public changeStatus(deviceId: string, action: 'revoke' | 'suspend' | 'reactivate') {
    return this.authority.changeUsbHsmStatus(deviceId, action);
  }

  /** Sign this exact authorization request with the USB-HSM. */
  public prove: UsbHsmProverFn = async (ctx) => {
    if (!UsbHsmProver.isSupported()) throw new Error('Este navegador no soporta WebAuthn.');
    const { rpId, allowCredentials } = await this.authority.usbHsmAuthenticationOptions();
    if (allowCredentials.length === 0) {
      throw new Error('No tienes un USB-HSM activo. Regístralo en "Hardware & Identidad".');
    }
    const challenge = await usbHsmChallenge(ctx);
    let assertion;
    try {
      assertion = await startAuthentication({
        optionsJSON: {
          challenge,
          rpId,
          timeout: 120_000,
          userVerification: 'required',
          allowCredentials: allowCredentials.map((c) => ({
            id: c.id,
            type: 'public-key' as const,
            transports: c.transports as Array<'usb'>,
          })),
        },
      });
    } catch (err) {
      throw friendlyWebAuthnError(err);
    }
    return {
      deviceId: await usbHsmDeviceIdFromCredentialId(assertion.id),
      assertion: assertion as unknown as UsbHsmAssertion,
    };
  };
}
