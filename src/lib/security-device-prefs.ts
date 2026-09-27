/**
 * Persisted operator preferences for physical trust root (USB binding),
 * HSM provider selection, and related toggles.
 * Browser localStorage only — not Authority server config.
 */

export type HsmProvider = 'none' | 'usb' | 'cloud';

export type CloudHsmVendor = 'aws-kms' | 'azure-keyvault' | 'gcp-kms' | 'hashicorp-vault';

export type UsbValidationPreference = 'persistent' | 'ephemeral';

export interface CloudHsmConfig {
  vendor: CloudHsmVendor;
  /** Region or vault namespace (provider-specific). */
  regionOrNamespace: string;
  /** Key id / alias / URI. */
  keyIdOrAlias: string;
  /** Optional API endpoint override. */
  endpoint?: string;
}

export interface SecurityDevicePrefs {
  usbBindingEnabled: boolean;
  usbValidationPreference: UsbValidationPreference;
  collaborativeUsbValidation: boolean;
  hsmProvider: HsmProvider;
  cloudHsm: CloudHsmConfig;
  /** Prefer USB-backed signing path when hsmProvider === 'usb'. */
  usbHsmSigningEnabled: boolean;
  /** Seal anti-replay export digests via USB binding path when available. */
  usbHsmAntiReplayEnabled: boolean;
  nfcEnabled: boolean;
}

export const DEFAULT_SECURITY_DEVICE_PREFS: SecurityDevicePrefs = {
  usbBindingEnabled: false,
  usbValidationPreference: 'persistent',
  collaborativeUsbValidation: false,
  hsmProvider: 'none',
  cloudHsm: {
    vendor: 'aws-kms',
    regionOrNamespace: '',
    keyIdOrAlias: '',
    endpoint: '',
  },
  usbHsmSigningEnabled: false,
  usbHsmAntiReplayEnabled: false,
  nfcEnabled: false,
};

const STORAGE_KEY = 'tdcp.securityDevicePrefs.v1';

export function loadSecurityDevicePrefs(): SecurityDevicePrefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_SECURITY_DEVICE_PREFS, cloudHsm: { ...DEFAULT_SECURITY_DEVICE_PREFS.cloudHsm } };
    const parsed = JSON.parse(raw) as Partial<SecurityDevicePrefs>;
    return {
      ...DEFAULT_SECURITY_DEVICE_PREFS,
      ...parsed,
      cloudHsm: {
        ...DEFAULT_SECURITY_DEVICE_PREFS.cloudHsm,
        ...(parsed.cloudHsm ?? {}),
      },
    };
  } catch {
    return { ...DEFAULT_SECURITY_DEVICE_PREFS, cloudHsm: { ...DEFAULT_SECURITY_DEVICE_PREFS.cloudHsm } };
  }
}

export function saveSecurityDevicePrefs(prefs: SecurityDevicePrefs): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    /* quota / private mode */
  }
}
