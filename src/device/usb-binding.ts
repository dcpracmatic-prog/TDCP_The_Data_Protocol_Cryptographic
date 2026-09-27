/**
 * USB physical trust-root binding (schema v1).
 *
 * Validates that a presented hardware snapshot matches a registered binding
 * sealed with Smart Token authorization digest + CSG integrity digest.
 * Does not perform WebUSB I/O itself — callers supply HardwareSnapshot.
 */

export interface HardwareSnapshot {
  vendorId: number;
  productId: number;
  serialNumber: string;
  manufacturerName: string;
  productName: string;
  usbVersionMajor: number;
  usbVersionMinor: number;
  interfaceClasses: number[];
}

export interface UsbSmartTokenRef {
  artifactId: string;
  authorizationDigest: string;
}

export interface UsbCsgSeal {
  sealId: string;
  digest: string;
  algorithm: string;
}

export interface UsbBindingCore {
  schema: 'tdcp.usb-binding.v1';
  deviceId: string;
  accountId: string;
  hardware: HardwareSnapshot;
  validationMode: 'persistent' | 'ephemeral';
  createdAt: number;
  expiresAt: number | null;
}

export interface UsbBindingRecord {
  version: number;
  binding: UsbBindingCore;
  hardwareDigest: string;
  smartToken: UsbSmartTokenRef;
  csg: UsbCsgSeal;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
}

export type UsbValidationResult =
  | { valid: true; reason: 'MATCH'; binding: UsbBindingRecord }
  | {
      valid: false;
      reason:
        | 'HARDWARE_MISMATCH'
        | 'CSG_MISMATCH'
        | 'TOKEN_MISMATCH'
        | 'REVOKED'
        | 'EXPIRED'
        | 'DIGEST_MISMATCH';
    };

function stableHardwareJson(h: HardwareSnapshot): string {
  const classes = [...h.interfaceClasses].sort((a, b) => a - b);
  return JSON.stringify({
    vendorId: h.vendorId,
    productId: h.productId,
    serialNumber: h.serialNumber,
    manufacturerName: h.manufacturerName,
    productName: h.productName,
    usbVersionMajor: h.usbVersionMajor,
    usbVersionMinor: h.usbVersionMinor,
    interfaceClasses: classes,
  });
}

async function sha256Hex(data: string): Promise<string> {
  const bytes = new TextEncoder().encode(data);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hardwareDigest(hardware: HardwareSnapshot): Promise<string> {
  return sha256Hex(stableHardwareJson(hardware));
}

export async function bindingDigest(binding: UsbBindingCore): Promise<string> {
  return sha256Hex(
    JSON.stringify({
      schema: binding.schema,
      deviceId: binding.deviceId,
      accountId: binding.accountId,
      hardware: JSON.parse(stableHardwareJson(binding.hardware)),
      validationMode: binding.validationMode,
      createdAt: binding.createdAt,
      expiresAt: binding.expiresAt,
    })
  );
}

export async function buildCsgInput(
  binding: UsbBindingCore,
  token: UsbSmartTokenRef
): Promise<string> {
  return sha256Hex(
    JSON.stringify({
      binding: await bindingDigest(binding),
      artifactId: token.artifactId,
      authorizationDigest: token.authorizationDigest,
    })
  );
}

export async function validateUsbBinding(
  presented: HardwareSnapshot,
  record: UsbBindingRecord,
  token: UsbSmartTokenRef,
  expectedCsgDigest: string,
  nowMs: number
): Promise<UsbValidationResult> {
  if (record.status === 'REVOKED') {
    return { valid: false, reason: 'REVOKED' };
  }
  if (record.status === 'EXPIRED') {
    return { valid: false, reason: 'EXPIRED' };
  }
  if (record.binding.expiresAt !== null && nowMs > record.binding.expiresAt) {
    return { valid: false, reason: 'EXPIRED' };
  }

  const presentedDigest = await hardwareDigest(presented);
  if (presentedDigest !== record.hardwareDigest) {
    return { valid: false, reason: 'HARDWARE_MISMATCH' };
  }
  const rebound = await hardwareDigest(record.binding.hardware);
  if (rebound !== record.hardwareDigest) {
    return { valid: false, reason: 'DIGEST_MISMATCH' };
  }

  if (
    token.artifactId !== record.smartToken.artifactId ||
    token.authorizationDigest !== record.smartToken.authorizationDigest
  ) {
    return { valid: false, reason: 'TOKEN_MISMATCH' };
  }

  if (expectedCsgDigest !== record.csg.digest) {
    return { valid: false, reason: 'CSG_MISMATCH' };
  }

  return { valid: true, reason: 'MATCH', binding: record };
}

/**
 * Soft USB HSM facade for demo / integration tests.
 * Real PKCS#11 / WebUSB transport is out of scope; this seals digests with
 * Web Crypto keys scoped to a binding id (developmentOnly).
 */
export class UsbHsmSigningBackend {
  public readonly developmentOnly = true;
  public readonly kind = 'USB_HSM_SOFT' as const;
  private keyPair: CryptoKeyPair | null = null;
  private bindingId: string;

  constructor(bindingId = 'usb-local-soft') {
    this.bindingId = bindingId;
  }

  async ensureKeys(): Promise<CryptoKeyPair> {
    if (this.keyPair) return this.keyPair;
    this.keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );
    return this.keyPair;
  }

  async signCanonical(bytes: Uint8Array): Promise<ArrayBuffer> {
    const { privateKey } = await this.ensureKeys();
    return crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      bytes.buffer as ArrayBuffer
    );
  }

  async sealAntiReplayExport(payload: string): Promise<{ digest: string; signatureBase64: string }> {
    const digest = await sha256Hex(payload);
    const sig = await this.signCanonical(new TextEncoder().encode(`${this.bindingId}:${digest}`));
    const u8 = new Uint8Array(sig);
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
    return { digest, signatureBase64: btoa(s) };
  }
}
