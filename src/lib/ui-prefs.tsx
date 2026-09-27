/**
 * UI preferences + local package history (demo).
 * History secrets are AES-GCM sealed with a key derived from a local PIN
 * (operator-chosen). This is NOT the Smart Token Prod HTTP API; label is
 * "PIN / Smart Token local" until a self-hosted STP master is wired.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

export type ThemeMode = 'dark' | 'light' | 'system';

export interface PackageHistoryEntry {
  id: string;
  fileName: string;
  pkgFileName: string;
  documentId: string;
  createdAt: number;
  /** AES-GCM ciphertext of the password factor (base64), sealed under PIN key */
  passwordEnc: string;
  iv: string;
}

interface UiPrefsState {
  theme: ThemeMode;
  developerMode: boolean;
  history: PackageHistoryEntry[];
  historyUnlocked: boolean;
  setTheme: (t: ThemeMode) => void;
  setDeveloperMode: (v: boolean) => void;
  addPackageHistory: (entry: {
    fileName: string;
    pkgFileName: string;
    documentId: string;
    password: string;
  }) => Promise<void>;
  unlockHistory: (pin: string) => Promise<boolean>;
  lockHistory: () => void;
  revealPassword: (id: string) => Promise<string | null>;
  clearLocalData: () => void;
}

const THEME_KEY = 'tdcp.ui.theme';
const DEV_KEY = 'tdcp.ui.developerMode';
const HISTORY_KEY = 'tdcp.ui.packageHistory';
const PIN_SALT_KEY = 'tdcp.ui.historyPinSalt';
const PIN_VERIFY_KEY = 'tdcp.ui.historyPinVerify';

const UiPrefsContext = createContext<UiPrefsState | null>(null);

function b64(buf: ArrayBuffer | Uint8Array): string {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s);
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(pin: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 120_000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptSecret(pin: string, salt: Uint8Array, plain: string): Promise<{ ct: string; iv: string }> {
  const key = await deriveKey(pin, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plain)
  );
  return { ct: b64(ct), iv: b64(iv) };
}

async function decryptSecret(
  pin: string,
  salt: Uint8Array,
  ct: string,
  iv: string
): Promise<string | null> {
  try {
    const key = await deriveKey(pin, salt);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(iv).buffer as ArrayBuffer },
      key,
      fromB64(ct).buffer as ArrayBuffer
    );
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

function applyTheme(theme: ThemeMode) {
  const root = document.documentElement;
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const dark = theme === 'dark' || (theme === 'system' && prefersDark);
  root.classList.toggle('tdcp-light', !dark);
  root.dataset.theme = dark ? 'dark' : 'light';
}

export function UiPrefsProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeMode>(() => {
    try {
      const v = localStorage.getItem(THEME_KEY) as ThemeMode | null;
      return v === 'light' || v === 'system' || v === 'dark' ? v : 'dark';
    } catch {
      return 'dark';
    }
  });
  const [developerMode, setDeveloperModeState] = useState(() => {
    try {
      return localStorage.getItem(DEV_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [history, setHistory] = useState<PackageHistoryEntry[]>(() => {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      return raw ? (JSON.parse(raw) as PackageHistoryEntry[]) : [];
    } catch {
      return [];
    }
  });
  const [historyUnlocked, setHistoryUnlocked] = useState(false);
  const [sessionPin, setSessionPin] = useState<string | null>(null);

  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => {
      if (theme === 'system') applyTheme('system');
    };
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [theme]);

  useEffect(() => {
    try {
      localStorage.setItem(DEV_KEY, developerMode ? '1' : '0');
    } catch {
      /* ignore */
    }
  }, [developerMode]);

  const persistHistory = useCallback((entries: PackageHistoryEntry[]) => {
    setHistory(entries);
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, 50)));
    } catch {
      /* ignore */
    }
  }, []);

  const ensureSalt = useCallback((): Uint8Array => {
    try {
      const existing = localStorage.getItem(PIN_SALT_KEY);
      if (existing) return fromB64(existing);
    } catch {
      /* ignore */
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    try {
      localStorage.setItem(PIN_SALT_KEY, b64(salt));
    } catch {
      /* ignore */
    }
    return salt;
  }, []);

  const addPackageHistory = useCallback(
    async (entry: {
      fileName: string;
      pkgFileName: string;
      documentId: string;
      password: string;
    }) => {
      const salt = ensureSalt();
      let pin = sessionPin;
      if (!pin) {
        pin = sessionStorage.getItem('tdcp.ui.sessionPin') || 'tdcp-demo-pin';
      }
      const { ct, iv } = await encryptSecret(pin, salt, entry.password);
      const next: PackageHistoryEntry = {
        id: `hist-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        fileName: entry.fileName,
        pkgFileName: entry.pkgFileName,
        documentId: entry.documentId,
        createdAt: Date.now(),
        passwordEnc: ct,
        iv,
      };
      persistHistory([next, ...history].slice(0, 50));
      if (!localStorage.getItem(PIN_VERIFY_KEY)) {
        const verify = await encryptSecret(pin, salt, 'tdcp-history-ok');
        localStorage.setItem(PIN_VERIFY_KEY, JSON.stringify(verify));
      }
    },
    [ensureSalt, history, persistHistory, sessionPin]
  );

  const unlockHistory = useCallback(
    async (pin: string) => {
      const salt = ensureSalt();
      const raw = localStorage.getItem(PIN_VERIFY_KEY);
      if (raw) {
        const { ct, iv } = JSON.parse(raw) as { ct: string; iv: string };
        const plain = await decryptSecret(pin, salt, ct, iv);
        if (plain !== 'tdcp-history-ok') return false;
      } else {
        const verify = await encryptSecret(pin, salt, 'tdcp-history-ok');
        localStorage.setItem(PIN_VERIFY_KEY, JSON.stringify(verify));
      }
      setSessionPin(pin);
      sessionStorage.setItem('tdcp.ui.sessionPin', pin);
      setHistoryUnlocked(true);
      return true;
    },
    [ensureSalt]
  );

  const lockHistory = useCallback(() => {
    setHistoryUnlocked(false);
    setSessionPin(null);
    sessionStorage.removeItem('tdcp.ui.sessionPin');
  }, []);

  const revealPassword = useCallback(
    async (id: string) => {
      if (!historyUnlocked || !sessionPin) return null;
      const row = history.find((h) => h.id === id);
      if (!row) return null;
      const salt = ensureSalt();
      return decryptSecret(sessionPin, salt, row.passwordEnc, row.iv);
    },
    [ensureSalt, history, historyUnlocked, sessionPin]
  );

  const clearLocalData = useCallback(() => {
    try {
      localStorage.removeItem(HISTORY_KEY);
      localStorage.removeItem(PIN_SALT_KEY);
      localStorage.removeItem(PIN_VERIFY_KEY);
      sessionStorage.removeItem('tdcp.ui.sessionPin');
    } catch {
      /* ignore */
    }
    setHistory([]);
    setHistoryUnlocked(false);
    setSessionPin(null);
  }, []);

  const value = useMemo<UiPrefsState>(
    () => ({
      theme,
      developerMode,
      history,
      historyUnlocked,
      setTheme: setThemeState,
      setDeveloperMode: setDeveloperModeState,
      addPackageHistory,
      unlockHistory,
      lockHistory,
      revealPassword,
      clearLocalData,
    }),
    [
      theme,
      developerMode,
      history,
      historyUnlocked,
      addPackageHistory,
      unlockHistory,
      lockHistory,
      revealPassword,
      clearLocalData,
    ]
  );

  return <UiPrefsContext.Provider value={value}>{children}</UiPrefsContext.Provider>;
}

export function useUiPrefs(): UiPrefsState {
  const ctx = useContext(UiPrefsContext);
  if (!ctx) throw new Error('useUiPrefs must be used within UiPrefsProvider');
  return ctx;
}
