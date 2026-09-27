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

/**
 * Assurance level for portable ciphertext + dual-path open (USB | MFA).
 * With hsmProvider === 'none', wrap keys and high-value ops stay in software:
 * STP API / browser / file Authority — not a FIPS HSM boundary.
 */
export type HsmAssuranceLevel = 'software_only' | 'usb_hsm_path' | 'cloud_hsm_path';

export function hsmAssuranceLevel(provider: HsmProvider): HsmAssuranceLevel {
  if (provider === 'usb') return 'usb_hsm_path';
  if (provider === 'cloud') return 'cloud_hsm_path';
  return 'software_only';
}

/** User-facing risk copy when HSM is none — dual-path still works, high assurance does not. */
export function hsmNoneRiskSummary(): string {
  return (
    'Con HSM = none el artefacto portátil puede seguir abriéndose por USB autorizada (ruta A) ' +
    'o por step-up MFA (ruta B: contraseña + TOTP [+ WebAuthn]), y la API Smart Token puede ' +
    'seguir siendo obligatoria para el unwrap. Eso NO equivale a claves en un módulo HSM: ' +
    'un compromiso del servidor STP, del proceso del navegador o del almacén de Authority en ' +
    'software expone material que un HSM USB o Cloud HSM habría aislado. Valore integrar ' +
    'al menos HSM USB o un servicio Cloud HSM/KMS si el riesgo de su organización lo exige.'
  );
}

export function hsmProviderLabel(provider: HsmProvider): string {
  switch (provider) {
    case 'usb':
      return 'USB HSM (ruta de anclaje físico endurecida)';
    case 'cloud':
      return 'Cloud HSM / KMS (servicio de nube del cliente)';
    default:
      return 'Ninguno (solo software — soberano, menor aislamiento de claves)';
  }
}
