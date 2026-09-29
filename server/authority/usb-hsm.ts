/**
 * USB-HSM registry (Authority side).
 *
 * Enrollment ("convertir tu USB en tu ID"): a signed-in user registers a USB
 * security key with a secure element. The key pair is generated inside the
 * device (WebAuthn); the Authority stores only the public key, bound to the
 * user, with lifecycle ACTIVE → SUSPENDED → REVOKED → REPLACED
 * (docs/PROPOSAL_SMART_TOKEN_CSG_PLATFORM.md).
 *
 * Accepted as USB-HSM only if:
 *   - user verification (PIN / on-key biometrics) was performed,
 *   - the credential is single-device (not a synced/cloud passkey),
 *   - the authenticator reports the `usb` transport.
 *
 * Authorization: the key signs usbHsmChallenge(request); the Authority checks
 * the signature, rpId/origin, UV flag and the signature counter (a counter
 * going backwards suspends the key as a possible clone).
 */

import {
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  MetadataService,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport as AuthenticatorTransportFuture,
  type PublicKeyCredentialCreationOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import {
  usbHsmDeviceIdFromCredentialId,
  type UsbHsmAssertion,
  type UsbHsmDeviceInfo,
  type UsbHsmStatus,
} from '../../src/core/authorization/usb-hsm.ts';

export interface UsbHsmConfig {
  rpId: string;
  rpName: string;
  origins: string[];
  /** Max ACTIVE/SUSPENDED keys per user. */
  maxDevicesPerUser: number;
  /** Require email_verified=true in the user token to enroll. */
  requireVerifiedEmail: boolean;
  /**
   * 'none' (default): the authenticator's model/vendor is not verified —
   * only that the key is single-device + reports 'usb' transport.
   * 'direct': the authenticator must present a real attestation certificate,
   * and its AAGUID must resolve in the FIDO Metadata Service (or the local
   * allowlist below). This is what actually proves "this is a genuine
   * hardware security key," not just a same-shaped software authenticator.
   */
  attestationMode: 'none' | 'direct';
  /**
   * How to treat an AAGUID with no FIDO MDS entry when attestationMode is
   * 'direct'. 'strict' (default, recommended): reject it. 'permissive':
   * accept it (useful for keys not yet published to MDS).
   */
  mdsVerificationMode: 'strict' | 'permissive';
  /**
   * Optional allowlist of AAGUIDs (lowercase, dashed form) accepted in
   * 'direct' mode regardless of MDS. Empty means "any AAGUID that MDS (or
   * the permissive mode) accepts."
   */
  allowedAaguids: string[];
}

export interface UsbHsmDeviceRecord {
  deviceId: string;
  userId: string;
  credentialId: string;
  publicKeyB64u: string;
  counter: number;
  transports: string[];
  aaguid: string;
  label: string;
  status: UsbHsmStatus;
  suspendedReason?: 'USER' | 'CLONE_SUSPECTED';
  createdAt: number;
  lastUsedAt: number | null;
  replacedBy?: string;
}

export class UsbHsmError extends Error {
  public readonly code: string;
  constructor(code: string, message?: string) {
    super(message ?? code);
    this.code = code;
  }
}

function b64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function loadUsbHsmConfigFromEnv(
  env: Record<string, string | undefined> = process.env as Record<string, string | undefined>
): UsbHsmConfig {
  const issuer = env.TDCP_USER_ISSUER?.trim();
  let defaultOrigin = 'http://localhost:8080';
  let defaultRpId = 'localhost';
  if (issuer) {
    try {
      const u = new URL(issuer);
      defaultOrigin = u.origin;
      defaultRpId = u.hostname;
    } catch {
      /* keep defaults */
    }
  }
  const origins = (env.TDCP_WEBAUTHN_ORIGINS || defaultOrigin)
    .split(',')
    .map((o) => o.trim().replace(/\/$/, ''))
    .filter(Boolean);
  return {
    rpId: env.TDCP_WEBAUTHN_RP_ID?.trim() || defaultRpId,
    rpName: env.TDCP_WEBAUTHN_RP_NAME?.trim() || 'TDCP',
    origins,
    maxDevicesPerUser: Number(env.TDCP_USB_HSM_MAX_PER_USER || 5),
    requireVerifiedEmail: env.TDCP_REQUIRE_VERIFIED_EMAIL === 'true',
    attestationMode: env.TDCP_USB_HSM_ATTESTATION === 'direct' ? 'direct' : 'none',
    mdsVerificationMode: env.TDCP_USB_HSM_MDS_MODE === 'permissive' ? 'permissive' : 'strict',
    allowedAaguids: (env.TDCP_USB_HSM_ALLOWED_AAGUIDS || '')
      .split(',')
      .map((a) => a.trim().toLowerCase())
      .filter(Boolean),
  };
}

const REGISTRATION_TTL_MS = 5 * 60_000;
let mdsInitPromise: Promise<void> | null = null;

/** Lazily initialize the FIDO MDS client once per process. */
function ensureMetadataServiceReady(mode: 'strict' | 'permissive'): Promise<void> {
  if (!mdsInitPromise) {
    mdsInitPromise = MetadataService.initialize({ verificationMode: mode }).catch((err) => {
      // Allow retrying on the next registration instead of caching a failure forever.
      mdsInitPromise = null;
      throw err;
    });
  }
  return mdsInitPromise;
}

export class UsbHsmRegistry {
  private devices: UsbHsmDeviceRecord[];
  private readonly pending = new Map<
    string,
    { challenge: string; expiresAt: number; label: string; replaceDeviceId?: string }
  >();
  private readonly onChange: () => void;
  public readonly config: UsbHsmConfig;

  constructor(config: UsbHsmConfig, initial: UsbHsmDeviceRecord[], onChange: () => void) {
    this.config = config;
    this.devices = initial.map((d) => ({ ...d }));
    this.onChange = onChange;
  }

  public exportRecords(): UsbHsmDeviceRecord[] {
    return this.devices.map((d) => ({ ...d }));
  }

  private toInfo(d: UsbHsmDeviceRecord): UsbHsmDeviceInfo {
    return {
      deviceId: d.deviceId,
      label: d.label,
      status: d.status,
      createdAt: d.createdAt,
      lastUsedAt: d.lastUsedAt,
      transports: d.transports,
      aaguid: d.aaguid,
      userVerification: true,
      ...(d.replacedBy ? { replacedBy: d.replacedBy } : {}),
    };
  }

  public listForUser(userId: string): UsbHsmDeviceInfo[] {
    return this.devices.filter((d) => d.userId === userId).map((d) => this.toInfo(d));
  }

  public isActiveDevice(userId: string, deviceId: string): boolean {
    return this.devices.some(
      (d) => d.userId === userId && d.deviceId === deviceId && d.status === 'ACTIVE'
    );
  }

  public hasActiveDevice(userId: string): boolean {
    return this.devices.some((d) => d.userId === userId && d.status === 'ACTIVE');
  }

  private liveDevices(userId: string): UsbHsmDeviceRecord[] {
    return this.devices.filter(
      (d) => d.userId === userId && (d.status === 'ACTIVE' || d.status === 'SUSPENDED')
    );
  }

  public async registrationOptions(
    user: { userId: string; email?: string; emailVerified?: boolean },
    opts: { label?: string; replaceDeviceId?: string } = {}
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    if (this.config.requireVerifiedEmail && user.emailVerified !== true) {
      throw new UsbHsmError('EMAIL_NOT_VERIFIED', 'Confirma tu correo antes de registrar un USB-HSM.');
    }
    if (opts.replaceDeviceId) {
      const old = this.devices.find(
        (d) => d.deviceId === opts.replaceDeviceId && d.userId === user.userId
      );
      if (!old || old.status === 'REVOKED' || old.status === 'REPLACED') {
        throw new UsbHsmError('USB_HSM_NOT_FOUND');
      }
    } else if (this.liveDevices(user.userId).length >= this.config.maxDevicesPerUser) {
      throw new UsbHsmError('USB_HSM_LIMIT', 'Límite de USB-HSM por cuenta alcanzado.');
    }

    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpId,
      userName: user.email || user.userId,
      userID: new TextEncoder().encode(user.userId),
      attestationType: this.config.attestationMode === 'direct' ? 'direct' : 'none',
      timeout: 120_000,
      excludeCredentials: this.devices
        .filter((d) => d.userId === user.userId && d.status !== 'REVOKED')
        .map((d) => ({
          id: d.credentialId,
          transports: d.transports as AuthenticatorTransportFuture[],
        })),
      authenticatorSelection: {
        authenticatorAttachment: 'cross-platform',
        residentKey: 'discouraged',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7, -8],
      preferredAuthenticatorType: 'securityKey',
    });

    const label = (opts.label || 'USB-HSM').trim().slice(0, 60) || 'USB-HSM';
    this.pending.set(user.userId, {
      challenge: options.challenge,
      expiresAt: Date.now() + REGISTRATION_TTL_MS,
      label,
      replaceDeviceId: opts.replaceDeviceId,
    });
    return options;
  }

  public async completeRegistration(
    userId: string,
    response: RegistrationResponseJSON
  ): Promise<UsbHsmDeviceInfo> {
    const pending = this.pending.get(userId);
    this.pending.delete(userId); // one attempt per challenge
    if (!pending || pending.expiresAt < Date.now()) {
      throw new UsbHsmError('USB_HSM_REGISTRATION_EXPIRED');
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: this.config.origins,
        expectedRPID: this.config.rpId,
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7, -8],
      });
    } catch (err) {
      throw new UsbHsmError(
        'USB_HSM_REGISTRATION_INVALID',
        err instanceof Error ? err.message : String(err)
      );
    }
    if (!verification.verified || !verification.registrationInfo) {
      throw new UsbHsmError('USB_HSM_REGISTRATION_INVALID');
    }
    const info = verification.registrationInfo;

    // A synced passkey (iCloud/Google) is not an HSM: its key can leave the device.
    if (info.credentialDeviceType !== 'singleDevice' || info.credentialBackedUp) {
      throw new UsbHsmError(
        'USB_HSM_NOT_HARDWARE_BOUND',
        'La credencial es sincronizable (passkey en la nube). Usa una llave USB con elemento seguro.'
      );
    }
    const transports = (response.response.transports ?? []) as string[];
    if (!transports.includes('usb')) {
      throw new UsbHsmError(
        'USB_HSM_NOT_USB',
        'El autenticador no es una llave USB (transporte distinto de "usb").'
      );
    }

    // 'direct' mode: the AAGUID must be a real, MDS-recognized security key
    // model — this is what actually distinguishes hardware from a software
    // authenticator that merely reports singleDevice+usb, since those two
    // flags alone are self-declared by the client.
    if (this.config.attestationMode === 'direct') {
      const allowlist = this.config.allowedAaguids;
      const aaguidLower = info.aaguid.toLowerCase();
      const isAllowlisted = allowlist.length > 0 && allowlist.includes(aaguidLower);
      if (!isAllowlisted) {
        await ensureMetadataServiceReady(this.config.mdsVerificationMode);
        let statement;
        try {
          statement = await MetadataService.getStatement(info.aaguid);
        } catch (err) {
          // In 'strict' mode, MetadataService itself throws for an AAGUID it
          // has no statement for — that IS "unrecognized model", not a
          // transport/network failure. Only a genuine lookup error (e.g. the
          // MDS blob never downloaded) should surface as unavailable.
          const message = err instanceof Error ? err.message : String(err);
          if (/no metadata statement/i.test(message)) {
            throw new UsbHsmError(
              'USB_HSM_UNRECOGNIZED_MODEL',
              'El modelo de llave no está en la lista permitida ni en el FIDO Metadata Service.'
            );
          }
          throw new UsbHsmError('USB_HSM_MDS_UNAVAILABLE', message);
        }
        if (!statement) {
          throw new UsbHsmError(
            'USB_HSM_UNRECOGNIZED_MODEL',
            'El modelo de llave no está en la lista permitida ni en el FIDO Metadata Service.'
          );
        }
      }
    }

    const credentialId = info.credential.id;
    if (this.devices.some((d) => d.credentialId === credentialId)) {
      throw new UsbHsmError('USB_HSM_ALREADY_REGISTERED');
    }

    const deviceId = await usbHsmDeviceIdFromCredentialId(credentialId);
    const record: UsbHsmDeviceRecord = {
      deviceId,
      userId,
      credentialId,
      publicKeyB64u: b64u(info.credential.publicKey),
      counter: info.credential.counter,
      transports,
      aaguid: info.aaguid,
      label: pending.label,
      status: 'ACTIVE',
      createdAt: Date.now(),
      lastUsedAt: null,
    };
    this.devices.push(record);

    if (pending.replaceDeviceId) {
      const old = this.devices.find(
        (d) => d.deviceId === pending.replaceDeviceId && d.userId === userId
      );
      if (old) {
        old.status = 'REPLACED';
        old.replacedBy = deviceId;
      }
    }
    this.onChange();
    return this.toInfo(record);
  }

  /**
   * Verify a USB-HSM assertion for `userId` over `expectedChallenge`.
   * Returns the device id and whether user verification (PIN/biometric) ran.
   */
  public async verifyAssertion(
    userId: string,
    assertion: UsbHsmAssertion,
    expectedChallenge: string
  ): Promise<{ deviceId: string; userVerified: boolean }> {
    if (!assertion || typeof assertion.id !== 'string') {
      throw new UsbHsmError('USB_HSM_ASSERTION_INVALID');
    }
    const device = this.devices.find(
      (d) => d.credentialId === assertion.id && d.userId === userId
    );
    if (!device) throw new UsbHsmError('USB_HSM_NOT_REGISTERED');
    if (device.status !== 'ACTIVE') {
      throw new UsbHsmError(
        device.status === 'SUSPENDED' ? 'USB_HSM_SUSPENDED' : 'USB_HSM_REVOKED'
      );
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: assertion as unknown as AuthenticationResponseJSON,
        expectedChallenge,
        expectedOrigin: this.config.origins,
        expectedRPID: this.config.rpId,
        requireUserVerification: true,
        credential: {
          id: device.credentialId,
          publicKey: new Uint8Array(Buffer.from(device.publicKeyB64u, 'base64url')),
          counter: device.counter,
          transports: device.transports as AuthenticatorTransportFuture[],
        },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (/counter/i.test(message)) {
        // Signature counter went backwards → the key may have been cloned.
        device.status = 'SUSPENDED';
        device.suspendedReason = 'CLONE_SUSPECTED';
        this.onChange();
        throw new UsbHsmError('USB_HSM_CLONE_SUSPECTED');
      }
      throw new UsbHsmError('USB_HSM_ASSERTION_INVALID', message);
    }
    if (!verification.verified) throw new UsbHsmError('USB_HSM_ASSERTION_INVALID');

    device.counter = verification.authenticationInfo.newCounter;
    device.lastUsedAt = Date.now();
    this.onChange();
    return {
      deviceId: device.deviceId,
      userVerified: verification.authenticationInfo.userVerified === true,
    };
  }

  /** Allowed credentials for a user's authentication ceremony (public data). */
  public allowCredentials(userId: string): Array<{ id: string; transports: string[] }> {
    return this.devices
      .filter((d) => d.userId === userId && d.status === 'ACTIVE')
      .map((d) => ({ id: d.credentialId, transports: d.transports }));
  }

  public changeStatus(
    userId: string,
    deviceId: string,
    action: 'revoke' | 'suspend' | 'reactivate'
  ): UsbHsmDeviceInfo {
    const device = this.devices.find((d) => d.deviceId === deviceId && d.userId === userId);
    if (!device || device.status === 'REVOKED' || device.status === 'REPLACED') {
      throw new UsbHsmError('USB_HSM_NOT_FOUND');
    }
    if (action === 'revoke') {
      device.status = 'REVOKED';
    } else if (action === 'suspend') {
      if (device.status !== 'ACTIVE') throw new UsbHsmError('USB_HSM_NOT_ACTIVE');
      device.status = 'SUSPENDED';
      device.suspendedReason = 'USER';
    } else {
      if (device.status !== 'SUSPENDED') throw new UsbHsmError('USB_HSM_NOT_SUSPENDED');
      // A key suspended as a possible clone can only be replaced, never reactivated.
      if (device.suspendedReason === 'CLONE_SUSPECTED') {
        throw new UsbHsmError('USB_HSM_CLONE_SUSPECTED');
      }
      device.status = 'ACTIVE';
      delete device.suspendedReason;
    }
    this.onChange();
    return this.toInfo(device);
  }
}
