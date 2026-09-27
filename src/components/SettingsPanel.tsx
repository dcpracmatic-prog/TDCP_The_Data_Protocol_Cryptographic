import { useState } from 'react';
import { Settings, Moon, Sun, Monitor, Trash2, X, Eye, EyeOff } from 'lucide-react';
import { useUiPrefs, type ThemeMode } from '../lib/ui-prefs.tsx';

export default function SettingsPanel({ onClose }: { onClose: () => void }) {
  const {
    theme,
    setTheme,
    developerMode,
    setDeveloperMode,
    clearLocalData,
  } = useUiPrefs();
  const [cleared, setCleared] = useState(false);

  const themes: Array<{ id: ThemeMode; label: string; icon: typeof Moon }> = [
    { id: 'dark', label: 'Oscuro', icon: Moon },
    { id: 'light', label: 'Claro', icon: Sun },
    { id: 'system', label: 'Sistema', icon: Monitor },
  ];

  const handleClear = () => {
    if (!window.confirm('¿Borrar historial local, PIN de historial y preferencias de sesión?')) return;
    clearLocalData();
    setCleared(true);
    setTimeout(() => setCleared(false), 2500);
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-end justify-center sm:items-center">
      <button
        type="button"
        aria-label="Cerrar configuración"
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Configuración TDCP"
        className="glass-panel relative z-10 max-h-[90dvh] w-full max-w-md overflow-y-auto rounded-t-2xl border border-white/10 p-5 shadow-2xl sm:rounded-2xl"
      >
        <div className="mb-4 flex items-center justify-between border-b border-white/10 pb-3">
          <div className="flex items-center gap-2">
            <Settings className="h-4 w-4 text-indigo-300" />
            <h2 className="text-sm font-bold tracking-wide text-white uppercase">Configuración</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-2 text-white/50 hover:bg-white/10 hover:text-white"
            aria-label="Cerrar"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <section className="mb-5 space-y-2">
          <h3 className="text-[11px] font-bold tracking-wider text-white/50 uppercase">Tema</h3>
          <div className="grid grid-cols-3 gap-2">
            {themes.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => setTheme(id)}
                className={`flex flex-col items-center gap-1.5 rounded-xl border px-2 py-3 text-[11px] font-bold ${
                  theme === id
                    ? 'border-indigo-500/60 bg-indigo-500/20 text-indigo-100'
                    : 'border-white/10 bg-black/30 text-white/60 hover:bg-white/5'
                }`}
              >
                <Icon className="h-4 w-4" />
                {label}
              </button>
            ))}
          </div>
        </section>

        <section className="mb-5 space-y-2">
          <h3 className="text-[11px] font-bold tracking-wider text-white/50 uppercase">Vista</h3>
          <label className="flex cursor-pointer items-center justify-between gap-3 rounded-xl border border-white/10 bg-black/30 px-3 py-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                {developerMode ? <Eye className="h-3.5 w-3.5 text-amber-300" /> : <EyeOff className="h-3.5 w-3.5" />}
                Modo desarrollador
              </div>
              <p className="mt-0.5 text-[10px] leading-snug text-white/45">
                Muestra logs, métricas y secciones avanzadas por defecto.
              </p>
            </div>
            <input
              type="checkbox"
              checked={developerMode}
              onChange={(e) => setDeveloperMode(e.target.checked)}
              className="h-4 w-4 shrink-0 accent-pink-500"
            />
          </label>
        </section>

        <section className="mb-5 space-y-2">
          <h3 className="text-[11px] font-bold tracking-wider text-white/50 uppercase">Hardware & HSM</h3>
          <p className="text-[10px] leading-relaxed text-white/45">
            Configure USB Binding, firma USB HSM, anti-replay por hardware y Cloud HSM
            (AWS / Azure / GCP / Vault) en la pestaña <strong className="text-white/70">Hardware &amp; Identidad</strong>
            del menú principal. Preferencias en <code className="text-white/60">security-device-prefs</code>.
          </p>
        </section>

        <section className="space-y-2">
          <h3 className="text-[11px] font-bold tracking-wider text-white/50 uppercase">Datos locales</h3>
          <button
            type="button"
            onClick={handleClear}
            className="flex w-full items-center justify-center gap-2 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-xs font-bold tracking-wider text-red-200 uppercase hover:bg-red-500/20"
          >
            <Trash2 className="h-3.5 w-3.5" />
            {cleared ? 'Caché limpiada' : 'Limpiar historial y caché local'}
          </button>
          <p className="text-[10px] leading-relaxed text-white/40">
            No afecta a la Authority remota ni a paquetes ya descargados. Solo limpia datos en este navegador.
          </p>
        </section>
      </div>
    </div>
  );
}
