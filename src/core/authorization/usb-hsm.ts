/**
 * USB-HSM — the user's hardware ID for TDCP.
 *
 * A USB-HSM is a USB security key with a secure element (FIDO2/WebAuthn:
 * YubiKey, Nitrokey, SoloKey, Feitian, Token2, …). On enrollment it generates
 * a key pair INSIDE the device; the private key is non-exportable. TDCP binds
 * that credential to the account in the Authority (status ACTIVE). From then
 * on, each authorization is signed by the USB-HSM over a challenge that
 * commits to the exact request, and the Authority verifies it.
 *
 * This is the "non-exportable device key via secure element/HSM" evolution
 * recommended in docs/PROPOSAL_SMART_TOKEN_CSG_PLATFORM.md: unlike VID/PID/
 * serial descriptors, the key cannot be copied to another USB.
 *
 * Shared by browser (Gatekeeper) and Authority — keep it dependency-free.
 */

import type { TDCPRequestedOperation } from './types.ts';
import { bytesToHex, arrayBufferToBase64, base64ToArrayBuffer } from '../crypto/primitives.ts';

export const USB_HSM_CHALLENGE_DOMAIN = 'TDCP-USB-HSM-AUTHZ-v1';
export const USB_HSM_DEVICE_PREFIX = 'USBHSM-';

export type UsbHsmStatus = 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'REPLACED';

/** WebAuthn AuthenticationResponseJSON (subset; base64url strings). */
export interface UsbHsmAssertion {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: 'cross-platform' | 'platform';
}

/** Public view of an enrolled USB-HSM (never includes key material). */
export interface UsbHsmDeviceInfo {
  deviceId: string;
  label: string;
  status: UsbHsmStatus;
  createdAt: number;
  lastUsedAt: number | null;
  transports: string[];
  aaguid: string;
  userVerification: boolean;
  replacedBy?: string;
}

export interface UsbHsmAuthorizationContext {
  challenge: string;
  documentId: string;
  packageId: string;
  operationId: string;
  requestedOperation: TDCPRequestedOperation;
}

export function canonicalUsbHsmContext(ctx: UsbHsmAuthorizationContext): string {
  return [
    USB_HSM_CHALLENGE_DOMAIN,
    `CHALLENGE:${ctx.challenge}`,
    `DOC:${ctx.documentId}`,
    `PKG:${ctx.packageId}`,
    `OP_ID:${ctx.operationId}`,
    `OP:${ctx.requestedOperation}`,
  ].join('\n');
}

/**
 * Fast Base64Url conversion for WebAuthn challenges/assertions.
 * Leverages arrayBufferToBase64 primitive (>100x speedup in Node, 10-50x in browser via chunking)
 * instead of single-byte string concatenation loop.
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return arrayBufferToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Fast Base64URL to byte decoding.
 * Leverages base64ToArrayBuffer primitive (~6x-8x speedup in Node/server via Buffer.from fast-path)
 * instead of single-byte charCodeAt loops.
 */
export function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  return new Uint8Array(base64ToArrayBuffer(b64 + pad));
}

/**
 * The WebAuthn challenge the USB-HSM signs: SHA-256 over the canonical
 * request, so a signature cannot be replayed for another document/operation.
 * The device id is NOT part of it: the Authority derives it from whichever
 * enrolled key actually signed.
 */
export async function usbHsmChallenge(ctx: UsbHsmAuthorizationContext): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalUsbHsmContext(ctx))
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

/** Stable, non-secret device id derived from the WebAuthn credential id. */
export async function usbHsmDeviceIdFromCredentialId(credentialIdB64Url: string): Promise<string> {
  const raw = base64UrlToBytes(credentialIdB64Url);
  const digest = await crypto.subtle.digest('SHA-256', raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer);
  const hex = bytesToHex(new Uint8Array(digest).subarray(0, 8)).toUpperCase();
  return `${USB_HSM_DEVICE_PREFIX}${hex}`;
}

/** Policies that must be opened with a USB-HSM. */
export function policyRequiresUsbHsm(policy: {
  policyLevel: string;
  requireUsbHsm?: boolean;
}): boolean {
  return (
    policy.requireUsbHsm === true ||
    policy.policyLevel === 'CRITICAL' ||
    policy.policyLevel === 'ULTRA_CRITICAL'
  );
}
