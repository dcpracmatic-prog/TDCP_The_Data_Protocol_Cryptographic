import { useEffect, useMemo, useState } from 'react';
import {
  Cloud,
  CreditCard,
  HardDrive,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Usb,
} from 'lucide-react';
import {
  DEFAULT_SECURITY_DEVICE_PREFS,
  loadSecurityDevicePrefs,
  saveSecurityDevicePrefs,
  hsmNoneRiskSummary,
  type CloudHsmVendor,
  type HsmProvider,
  type SecurityDevicePrefs,
  type UsbValidationPreference,
} from '../lib/security-device-prefs.ts';
import { cloudHsmAdapterFromPrefs } from '../device/cloud-hsm-adapter.ts';
import UsbHsmIdentityCard from './UsbHsmIdentityCard.tsx';

const CLOUD_VENDORS: Array<{ value: CloudHsmVendor; label: string }> = [
  { value: 'aws-kms', label: 'AWS KMS' },
  { value: 'azure-keyvault', label: 'Azure Key Vault' },
  { value: 'gcp-kms', label: 'Google Cloud KMS' },
  { value: 'hashicorp-vault', label: 'HashiCorp Vault' },
];

export default function SecurityDevicesPanel() {
  const [prefs, setPrefs] = useState<SecurityDevicePrefs>(() => loadSecurityDevicePrefs());

  useEffect(() => {
    saveSecurityDevicePrefs(prefs);
  }, [prefs]);

  const patch = (next: Partial<SecurityDevicePrefs>) =>
    setPrefs((current) => ({ ...current, ...next }));

  const adapter = useMemo(
    () =>
      prefs.hsmProvider === 'cloud'
        ? cloudHsmAdapterFromPrefs(prefs.cloudHsm)
        : null,
    [prefs.hsmProvider, prefs.cloudHsm]
  );

  const hsmOptions: Array<{ value: HsmProvider; label: string; description: string }> = [
    {
      value: 'none',
      label: 'None (solo software)',
      description:
        'Soberano y funcional: dual path USB|MFA + STP siguen operativos. Claves NO en HSM — valúe el riesgo.',
    },
    {
      value: 'usb',
      label: 'USB HSM',
      description:
        'Anclaje en HSM/token USB real del cliente (no pendrive genérico). Mayor aislamiento de claves.',
    },
    {
      value: 'cloud',
      label: 'Cloud HSM',
      description:
        'AWS / Azure / GCP / Vault bajo contrato del cliente. Recomendado si el riesgo exige módulo dedicado.',
    },
  ];

  const validationOptions: Array<{
    value: UsbValidationPreference;
    label: string;
    description: string;
  }> = [
    {
      value: 'persistent',
      label: 'Vinculación permanente',
      description: 'Registra la USB como dispositivo autorizado de la cuenta.',
    },
    {
      value: 'ephemeral',
      label: 'Validar sin guardar',
      description: 'Comprueba la USB y descarta el binding al terminar.',
    },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col gap-2 overflow-y-auto pb-4 [-webkit-overflow-scrolling:touch]">
      <div className="glass-panel p-3 md:p-4">
        <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="flex items-center gap-2 text-base font-bold text-cyan-300">
            <Usb className="h-4 w-4" /> Hardware &amp; Identidad
          </h2>
          <span className="w-fit rounded-full border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-0.5 text-[10px] text-cyan-200">
            Raíz de confianza física
          </span>
        </div>
        <p className="mb-4 text-[11px] leading-relaxed text-white/55">
          Este módulo valida el <strong className="text-white/80">chip físico USB</strong> (binding),
          la <strong className="text-white/80">integridad del sello CSG</strong> y las{' '}
          <strong className="text-white/80">claves / digests de recuperación Smart Token</strong>.
          No sustituye al Gatekeeper ni emite grants TDCP. La USB no inicia sesión: la cuenta se
          autentica por separado; el hardware solo se vincula o valida después.
        </p>

        <UsbHsmIdentityCard />

        <section className="mb-5 space-y-3">
          <h3 className="text-[11px] font-bold tracking-wider text-white/50 uppercase">
            Dispositivos de seguridad
          </h3>

          <label className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-black/30 px-3 py-3">
            <div className="flex min-w-0 items-center gap-2">
              <Usb className="h-4 w-4 shrink-0 text-indigo-300" />
              <div className="min-w-0">
                <div className="text-xs font-bold text-white">Vinculación USB</div>
                <div className="text-[10px] text-white/40">
                  Autorizar almacenamiento físico mediante binding + CSG.
                </div>
              </div>
            </div>
            <input
              type="checkbox"
              checked={prefs.usbBindingEnabled}
              onChange={(e) => patch({ usbBindingEnabled: e.target.checked })}
              className="h-4 w-4 shrink-0 accent-indigo-500"
            />
          </label>

          <div className="rounded-xl border border-white/10 bg-black/30 p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold text-white">
              <ShieldCheck className="h-4 w-4 text-emerald-300" />
              Modo de validación USB
            </div>
            <div className="space-y-2">
              {validationOptions.map((option) => (
                <label
                  key={option.value}
                  className="flex cursor-pointer gap-3 rounded-lg border border-white/5 p-2.5"
                >
                  <input
                    type="radio"
                    name="tdcp-usb-validation-mode"
                    checked={prefs.usbValidationPreference === option.value}
                    onChange={() => patch({ usbValidationPreference: option.value })}
                    className="mt-0.5"
                  />
                  <span>
                    <span className="block text-[11px] font-bold text-white">{option.label}</span>
                    <span className="block text-[10px] leading-snug text-white/40">
                      {option.description}
                    </span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <label className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-black/30 px-3 py-3">
            <div className="flex min-w-0 items-center gap-2">
              <Smartphone className="h-4 w-4 shrink-0 text-cyan-300" />
              <div className="min-w-0">
                <div className="text-xs font-bold text-white">Validación USB colaborativa</div>
                <div className="text-[10px] text-white/40">
                  Comprobar una USB sin convertirla en dispositivo de cuenta.
                </div>
              </div>
            </div>
            <input
              type="checkbox"
              checked={prefs.collaborativeUsbValidation}
              onChange={(e) =>
                patch({
                  collaborativeUsbValidation: e.target.checked,
                  usbValidationPreference: e.target.checked
                    ? 'ephemeral'
                    : prefs.usbValidationPreference,
                })
              }
              className="h-4 w-4 shrink-0 accent-cyan-500"
            />
          </label>
        </section>

        <section className="mb-5 space-y-3">
          <div className="rounded-xl border border-white/10 bg-black/30 p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-bold text-white">
              <HardDrive className="h-4 w-4 text-amber-300" />
              Proveedor HSM
            </div>
            <div className="grid gap-2">
              {hsmOptions.map((option) => (
                <label
                  key={option.value}
                  className="flex cursor-pointer items-center gap-3 rounded-lg border border-white/5 p-2.5"
                >
                  <input
                    type="radio"
                    name="tdcp-hsm-provider"
                    checked={prefs.hsmProvider === option.value}
                    onChange={() => patch({ hsmProvider: option.value })}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block text-[11px] font-bold text-white">{option.label}</span>
                    <span className="block text-[10px] leading-snug text-white/40">
                      {option.description}
                    </span>
                  </span>
                  {option.value === 'usb' ? (
                    <Usb className="h-4 w-4 shrink-0 text-white/30" />
                  ) : null}
                  {option.value === 'cloud' ? (
                    <Cloud className="h-4 w-4 shrink-0 text-white/30" />
                  ) : null}
                </label>
              ))}
            </div>
            {prefs.hsmProvider === 'none' && (
              <div className="mt-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-2.5 text-[10px] leading-relaxed text-amber-100/90">
                <strong className="text-amber-200">Riesgo con HSM = none: </strong>
                {hsmNoneRiskSummary()}
              </div>
            )}
            <p className="mt-2 text-[10px] leading-relaxed text-white/45">
              Artefacto portátil: ruta A (USB autorizada + CSG) o ruta B (contraseña + TOTP
              [+ WebAuthn]). El unwrap depende de la API Smart Token. El dual path{' '}
              <strong className="text-white/70">funciona sin HSM</strong>; el aislamiento de
              claves de grado HSM <strong className="text-white/70">no</strong>.
            </p>
          </div>

          {prefs.hsmProvider === 'usb' && (
            <div className="space-y-2 rounded-xl border border-indigo-500/20 bg-indigo-500/5 p-3">
              <label className="flex items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2">
                  <KeyRound className="h-4 w-4 shrink-0 text-indigo-300" />
                  <div>
                    <div className="text-xs font-bold text-white">Backend de firma en USB HSM</div>
                    <div className="text-[10px] text-white/40">
                      Preferir firma vía módulo USB (binding local; PKCS#11 en producción).
                    </div>
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={prefs.usbHsmSigningEnabled}
                  onChange={(e) => patch({ usbHsmSigningEnabled: e.target.checked })}
                  className="h-4 w-4 accent-indigo-500"
                />
              </label>
              <label className="flex items-center justify-between gap-3 border-t border-white/5 pt-2">
                <div className="flex min-w-0 items-center gap-2">
                  <RefreshCw className="h-4 w-4 shrink-0 text-emerald-300" />
                  <div>
                    <div className="text-xs font-bold text-white">
                      Caché anti-replay respaldada por hardware
                    </div>
                    <div className="text-[10px] text-white/40">
                      Sella exportaciones de replay con digest firmado USB.
                    </div>
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={prefs.usbHsmAntiReplayEnabled}
                  onChange={(e) => patch({ usbHsmAntiReplayEnabled: e.target.checked })}
                  className="h-4 w-4 accent-emerald-500"
                />
              </label>
            </div>
          )}

          {prefs.hsmProvider === 'cloud' && (
            <div className="space-y-3 rounded-xl border border-amber-500/20 bg-amber-500/5 p-3">
              <div className="text-xs font-bold text-white">Proveedor Cloud HSM</div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {CLOUD_VENDORS.map((v) => (
                  <label
                    key={v.value}
                    className={`flex cursor-pointer items-center gap-2 rounded-lg border px-2.5 py-2 text-[11px] ${
                      prefs.cloudHsm.vendor === v.value
                        ? 'border-amber-500/50 bg-amber-500/15 text-amber-100'
                        : 'border-white/10 bg-black/30 text-white/70'
                    }`}
                  >
                    <input
                      type="radio"
                      name="tdcp-cloud-vendor"
                      checked={prefs.cloudHsm.vendor === v.value}
                      onChange={() =>
                        patch({ cloudHsm: { ...prefs.cloudHsm, vendor: v.value } })
                      }
                    />
                    {v.label}
                  </label>
                ))}
              </div>
              <div className="grid gap-2">
                <input
                  type="text"
                  placeholder="Región / namespace"
                  value={prefs.cloudHsm.regionOrNamespace}
                  onChange={(e) =>
                    patch({
                      cloudHsm: { ...prefs.cloudHsm, regionOrNamespace: e.target.value },
                    })
                  }
                  className="w-full rounded border border-white/10 bg-black/40 px-3 py-2 font-mono text-xs text-white outline-none focus:border-amber-500/40"
                />
                <input
                  type="text"
                  placeholder="Key ID / Alias"
                  value={prefs.cloudHsm.keyIdOrAlias}
                  onChange={(e) =>
                    patch({
                      cloudHsm: { ...prefs.cloudHsm, keyIdOrAlias: e.target.value },
                    })
                  }
                  className="w-full rounded border border-white/10 bg-black/40 px-3 py-2 font-mono text-xs text-white outline-none focus:border-amber-500/40"
                />
                <input
                  type="text"
                  placeholder="Endpoint (opcional)"
                  value={prefs.cloudHsm.endpoint ?? ''}
                  onChange={(e) =>
                    patch({
                      cloudHsm: { ...prefs.cloudHsm, endpoint: e.target.value },
                    })
                  }
                  className="w-full rounded border border-white/10 bg-black/40 px-3 py-2 font-mono text-xs text-white outline-none focus:border-amber-500/40"
                />
              </div>
              {adapter && (
                <p className="text-[10px] text-white/45">
                  Adaptador: {adapter.describe()} · configurado={String(adapter.isConfigured)} ·
                  developmentOnly={String(adapter.developmentOnly)}
                </p>
              )}
            </div>
          )}
        </section>

        <label className="mb-4 flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-black/30 px-3 py-3">
          <div className="flex min-w-0 items-center gap-2">
            <CreditCard className="h-4 w-4 shrink-0 text-white/60" />
            <div>
              <div className="text-xs font-bold text-white">NFC (retirado)</div>
              <div className="text-[10px] text-white/40">
                Reemplazado por USB-HSM. La credencial es tu cuenta y el factor físico, tu llave USB.
              </div>
            </div>
          </div>
          <input
            type="checkbox"
            checked={false}
            disabled
            readOnly
            className="h-4 w-4 accent-slate-400"
          />
        </label>

        <button
          type="button"
          className="text-[10px] text-white/40 underline underline-offset-2"
          onClick={() =>
            setPrefs({
              ...DEFAULT_SECURITY_DEVICE_PREFS,
              cloudHsm: { ...DEFAULT_SECURITY_DEVICE_PREFS.cloudHsm },
            })
          }
        >
          Restaurar valores predeterminados
        </button>
      </div>
    </div>
  );
}
