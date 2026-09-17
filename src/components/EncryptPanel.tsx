import { useMemo, useState } from 'react';
import {
  Lock,
  Download,
  KeyRound,
  EyeOff,
  ShieldAlert,
  Clock,
  CheckCircle,
  Copy,
  Activity,
  Share2,
  Info,
  FileText,
  Image as ImageIcon,
  Music,
  Video,
  Archive,
  Check,
  ShieldCheck,
  RefreshCw,
  CloudUpload,
  HardDrive,
  ExternalLink,
} from 'lucide-react';
import { useGoogleAuth } from '../lib/googleDriveContext.tsx';
import { evaluatePasswordStrength } from '../lib/password-strength.ts';
import { tdcpRuntime } from '../runtime/tdcp-runtime.ts';
import type { PolicyLevel } from '../core/authorization/types.ts';
import type { TDCPPackage } from '../core/package/package-format.ts';
import CollapsibleSection from './CollapsibleSection.tsx';

const POLICY_HELP: Record<PolicyLevel, string> = {
  NORMAL: 'Ventana 5 min. Sin marca forense obligatoria.',
  STANDARD: 'Ventana 3 min. Autorización Oracle obligatoria.',
  CRITICAL: 'Ventana 60 s. Biometría de presencia + marca forense.',
  ULTRA_CRITICAL: 'Ventana 45 s. Fragmentos A/B/C + biometría + grant + dispositivo + epoch.',
};

export default function EncryptPanel() {
  const { isSignedIn, selectedFolder, uploadPackageToFolder, openFolderPicker, openFilePicker } =
    useGoogleAuth();
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [policyLevel, setPolicyLevel] = useState<PolicyLevel>('STANDARD');
  const [daysRestriction, setDaysRestriction] = useState(false);
  const [days, setDays] = useState(5);
  const [watermark, setWatermark] = useState(true);
  const [blurMode, setBlurMode] = useState(false);
  const [allowExtraction, setAllowExtraction] = useState(false);
  const [viewOnce, setViewOnce] = useState(false);
  const [logs, setLogs] = useState('>_ ESPERANDO POLÍTICA TDCP Y REGISTRO EN ORACLE...');
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedInstructions, setCopiedInstructions] = useState(false);
  const [sharedStatus, setSharedStatus] = useState<string | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isUploadingToDrive, setIsUploadingToDrive] = useState(false);
  const [driveUploadResult, setDriveUploadResult] = useState<{ id: string; webViewLink?: string } | null>(
    null
  );
  const [encryptionResult, setEncryptionResult] = useState<{
    downloadUrl: string;
    fileName: string;
    monitoringKey: string;
    summary: string[];
    packageBlob: Blob;
    pkgFileName: string;
    integrityHash: string;
    pkg: TDCPPackage;
  } | null>(null);

  const pwdStrength = useMemo(() => evaluatePasswordStrength(password), [password]);

  const generatePassword = () => {
    const uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lowercase = 'abcdefghijkmnopqrstuvwxyz';
    const numbers = '23456789';
    const symbols = '!@#$%^&*()-_=+[]{}';
    const all = uppercase + lowercase + numbers + symbols;
    const randomArray = new Uint8Array(20);
    crypto.getRandomValues(randomArray);
    const chars = [
      uppercase[randomArray[0] % uppercase.length],
      lowercase[randomArray[1] % lowercase.length],
      numbers[randomArray[2] % numbers.length],
      symbols[randomArray[3] % symbols.length],
    ];
    for (let i = 4; i < 20; i++) chars.push(all[randomArray[i] % all.length]);
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomArray[i] % (i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    setPassword(chars.join(''));
  };

  const processEncrypt = async () => {
    if (!file) {
      setLogs('Error: Debe seleccionar un archivo de origen.');
      return;
    }
    if (password.length < 8) {
      setLogs('Error: El factor de contraseña debe tener al menos 8 caracteres. No autoriza por sí sola.');
      return;
    }

    setIsEncrypting(true);
    setEncryptionResult(null);
    setCopiedKey(false);
    setCopiedInstructions(false);
    setSharedStatus(null);
    setLogs('Creando TDCPPackage y registrando política en AuthorizationOracle...');

    try {
      const plaintext = await file.arrayBuffer();
      setLogs((prev) => prev + '\n[FACTORY] createTDCPPackage() — única especificación de formato.');
      setLogs((prev) => prev + '\n[ORACLE] registerDocumentPolicy() — el paquete no contiene autorización.');

      const { pkg, blob, monitoringKey } = await tdcpRuntime.createPackage({
        plaintext,
        password,
        originalFileName: file.name,
        mimeType: file.type || 'application/octet-stream',
        policyLevel,
        allowExtraction,
        expirationDays: daysRestriction ? days : undefined,
        viewOnce,
        watermarkRequired: watermark,
        blurMode,
      });

      const blobUrl = URL.createObjectURL(blob);
      const pkgFileName = `TDCP_${file.name.replace(/\.[^/.]+$/, '')}.pkg`;

      const summaryItems = [
        `Formato TDCPPackage ${pkg.version} · AES-256-GCM + HKDF-SHA256 + AAD`,
        `documentId ${pkg.documentId} · packageId ${pkg.packageId}`,
        `Política ${policyLevel} registrada en el Oracle (no viaja en el archivo)`,
        'CEK aleatoria envuelta con factor de contraseña + secreto Oracle. La contraseña sola no descifra.',
        allowExtraction
          ? 'Extracción física permitida sólo con grant EXTRACT.'
          : 'Extracción física prohibida. Sólo RENDER_RAM en runtime controlado.',
      ];
      if (viewOnce) summaryItems.push('Vista única: consumo autoritativo en el Oracle, no en localStorage.');
      if (daysRestriction) summaryItems.push(`Caducidad de ${days} días según reloj del Oracle.`);
      if (watermark) summaryItems.push('Marca forense de sesión exigida por política.');
      if (policyLevel === 'ULTRA_CRITICAL') {
        summaryItems.push('Fragmentos A/B/C interbloqueados. A, B o C aislados son inútiles.');
      }

      setEncryptionResult({
        downloadUrl: blobUrl,
        fileName: file.name,
        monitoringKey,
        summary: summaryItems,
        packageBlob: blob,
        pkgFileName,
        integrityHash: pkg.integrityHash,
        pkg,
      });

      setLogs(
        (prev) =>
          prev +
          `\n[ÉXITO] TDCPPackage sellado. DOC=${pkg.documentId}` +
          `\n[ORACLE] Política ${policyLevel} registrada. Copiar este .pkg NO concede autorización.` +
          `\n[CLAVE] ${monitoringKey} — revocación via epoch, no localStorage.`
      );
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setLogs(`Fallo de empaquetado TDCP: ${message}`);
    } finally {
      setIsEncrypting(false);
    }
  };

  const handleNativeShare = async () => {
    if (!encryptionResult) return;
    try {
      const shareFile = new File([encryptionResult.packageBlob], encryptionResult.pkgFileName, {
        type: 'application/octet-stream',
      });
      if (navigator.canShare && navigator.canShare({ files: [shareFile] })) {
        await navigator.share({
          title: `TDCP ${encryptionResult.fileName}`,
          text: `Paquete cifrado TDCP. El archivo no autoriza. Ábrelo en el Gatekeeper.`,
          files: [shareFile],
        });
        setSharedStatus('Paquete compartido. La autorización NO viaja con el archivo.');
      } else {
        copyDistributionInstructions();
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== 'AbortError') copyDistributionInstructions();
    }
  };

  const copyDistributionInstructions = () => {
    if (!encryptionResult) return;
    const text = `TDCP PACKAGE (ciphertext only)
Archivo: ${encryptionResult.pkgFileName}
documentId: ${encryptionResult.pkg.documentId}
packageId: ${encryptionResult.pkg.packageId}
SHA-256 envelope: ${encryptionResult.integrityHash.slice(0, 16)}...
Plataforma: ${window.location.origin}

Este archivo NO contiene autorización.
Se requiere credencial + dispositivo + Oracle + Gatekeeper.
La contraseña es un factor adicional, no una llave de apertura.`;
    void navigator.clipboard.writeText(text);
    setCopiedInstructions(true);
    setTimeout(() => setCopiedInstructions(false), 3000);
  };

  const copyMonitoringKey = () => {
    if (!encryptionResult) return;
    void navigator.clipboard.writeText(encryptionResult.monitoringKey);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 3000);
  };

  const handleUploadToDriveFolder = async () => {
    if (!encryptionResult) return;
    if (!selectedFolder) {
      openFolderPicker();
      return;
    }
    setIsUploadingToDrive(true);
    try {
      const uploadRes = await uploadPackageToFolder(
        encryptionResult.packageBlob,
        encryptionResult.pkgFileName
      );
      setDriveUploadResult(uploadRes);
      setSharedStatus(
        `Ciphertext subido a "${selectedFolder.name}". Drive no es autoridad de autorización.`
      );
      await tdcpRuntime.auditSink.recordEvent({
        documentId: encryptionResult.pkg.documentId,
        packageId: encryptionResult.pkg.packageId,
        deviceId: 'STORAGE',
        credentialId: 'STORAGE',
        operationId: `DRIVE-${encryptionResult.pkg.packageId}`,
        operation: 'CLOUD_SYNC_UPLOAD',
        policy: encryptionResult.pkg.metadata.policyLevel,
        result: 'SUCCESS',
        details: `Paquete cifrado almacenado en Google Drive (carpeta ${selectedFolder.name}). Storage ≠ autorización.`,
      });
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : String(err));
    } finally {
      setIsUploadingToDrive(false);
    }
  };

  if (encryptionResult) {
    return (
      <div className="flex h-full min-h-0 flex-col gap-6">
        <div className="glass-panel flex flex-1 flex-col overflow-y-auto p-6 md:p-8">
          <div className="mb-6 text-center">
            <div className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-full border border-emerald-500/50 bg-emerald-500/20 shadow-[0_0_30px_rgba(52,211,153,0.3)]">
              <CheckCircle className="h-7 w-7 text-emerald-400" />
            </div>
            <h2 className="mb-1 text-2xl font-bold text-white">TDCPPackage sellado</h2>
            <p className="text-sm font-medium text-emerald-400">
              <span className="font-mono font-bold text-white">{encryptionResult.pkgFileName}</span>
            </p>
            <p className="mt-2 text-[11px] text-white/50">
              El archivo es ciphertext. La autorización vive en el Oracle.
            </p>
          </div>

          <div className="mx-auto mb-8 flex w-full max-w-3xl flex-col gap-4">
            <div className="flex flex-col space-y-4">
              <div className="glass-card flex-1 border-l-2 border-l-emerald-500 p-6">
                <h3 className="mb-4 flex items-center gap-2 text-xs font-bold tracking-wider text-white/60 uppercase">
                  <ShieldAlert className="h-4 w-4 text-emerald-400" /> Política registrada
                </h3>
                <ul className="space-y-3">
                  {encryptionResult.summary.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2.5 text-xs text-white/80 md:text-sm">
                      <span className="mt-0.5 font-bold text-emerald-400">•</span>
                      <span className="leading-relaxed">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="glass-card border-l-2 border-l-pink-500 p-5">
                <h3 className="mb-1 flex items-center gap-2 text-xs font-bold tracking-wider text-white/60 uppercase">
                  <Activity className="h-4 w-4 text-pink-400" /> Clave de monitoreo (epoch / kill-switch)
                </h3>
                <p className="mb-3 text-[11px] leading-relaxed text-white/60">
                  Revoca el documento en el Oracle. Incrementa epoch. No usa localStorage.
                </p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    readOnly
                    value={encryptionResult.monitoringKey}
                    className="flex-1 rounded border border-pink-500/30 bg-black/40 p-2.5 font-mono text-xs text-pink-300 outline-none"
                  />
                  <button
                    onClick={copyMonitoringKey}
                    className="flex items-center gap-1.5 rounded border border-pink-500/50 bg-pink-500/20 px-3 text-xs font-semibold text-pink-300 hover:bg-pink-500/30"
                  >
                    {copiedKey ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                    {copiedKey ? 'Copiada' : 'Copiar'}
                  </button>
                </div>
              </div>
            </div>

            <div className="flex flex-col space-y-4">
              <div className="glass-card flex flex-1 flex-col justify-between border-l-2 border-l-indigo-500 p-6">
                <div>
                  <h3 className="mb-3 flex items-center gap-2 text-xs font-bold tracking-wider text-indigo-400 uppercase">
                    <Share2 className="h-4 w-4" /> Distribución de ciphertext
                  </h3>
                  <p className="mb-5 text-xs leading-relaxed text-white/70">
                    Google Drive, descarga o compartir nativo almacenan bytes cifrados. Ninguno autoriza.
                  </p>
                  <div className="space-y-3">
                    {isSignedIn && (
                      <button
                        onClick={handleUploadToDriveFolder}
                        disabled={isUploadingToDrive}
                        className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-indigo-500/60 bg-indigo-500/30 p-3.5 text-xs font-bold tracking-wider text-indigo-200 uppercase hover:bg-indigo-500/40 disabled:opacity-50"
                      >
                        <CloudUpload className="h-4 w-4 text-indigo-400" />
                        {isUploadingToDrive
                          ? 'Subiendo ciphertext...'
                          : selectedFolder
                            ? `Guardar en "${selectedFolder.name}"`
                            : 'Subir a carpeta de Drive'}
                      </button>
                    )}
                    {driveUploadResult?.webViewLink && (
                      <a
                        href={driveUploadResult.webViewLink}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center justify-center gap-1.5 text-center text-xs text-indigo-300 hover:text-indigo-200"
                      >
                        <ExternalLink className="h-3.5 w-3.5" /> Abrir en Drive (ciphertext)
                      </a>
                    )}
                    <a
                      href={encryptionResult.downloadUrl}
                      download={encryptionResult.pkgFileName}
                      className="flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-500/50 bg-emerald-500/20 p-3.5 text-center text-xs font-bold tracking-wider text-emerald-300 uppercase hover:bg-emerald-500/30"
                    >
                      <Download className="h-4 w-4" /> Descargar {encryptionResult.pkgFileName}
                    </a>
                    <button
                      onClick={handleNativeShare}
                      className="flex w-full items-center justify-center gap-2 rounded-lg border border-indigo-500/50 bg-indigo-500/20 p-3.5 text-xs font-bold tracking-wider text-indigo-300 uppercase hover:bg-indigo-500/30"
                    >
                      <Share2 className="h-4 w-4" /> Compartir paquete
                    </button>
                    <button
                      onClick={copyDistributionInstructions}
                      className="flex w-full items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/5 p-3.5 text-xs font-semibold text-white/90 hover:bg-white/10"
                    >
                      {copiedInstructions ? (
                        <Check className="h-4 w-4 text-emerald-400" />
                      ) : (
                        <Copy className="h-4 w-4 text-indigo-400" />
                      )}
                      {copiedInstructions ? 'Copiado' : 'Copiar ficha del paquete'}
                    </button>
                  </div>
                </div>
                {sharedStatus && (
                  <p className="mt-3 rounded border border-emerald-500/20 bg-emerald-500/10 py-1.5 text-center text-xs text-emerald-400">
                    {sharedStatus}
                  </p>
                )}
              </div>
            </div>
          </div>

          <div className="mt-auto pt-4 text-center">
            <button
              onClick={() => {
                setEncryptionResult(null);
                setFile(null);
                setPassword('');
                setLogs('>_ ESPERANDO POLÍTICA TDCP Y REGISTRO EN ORACLE...');
              }}
              className="text-xs font-bold tracking-widest text-white/40 uppercase underline decoration-white/20 underline-offset-4 hover:text-white"
            >
              Proteger otro archivo
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col gap-6">
      <div className="glass-panel flex flex-1 flex-col overflow-y-auto p-6">
                <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="flex items-center gap-2 text-xl font-bold text-pink-400">
            <Lock className="h-5 w-5" /> TDCP · Crear paquete
          </h2>
          <div className="flex w-fit items-center gap-2 rounded-full border border-pink-500/30 bg-pink-500/10 px-3 py-1 text-[11px] text-pink-300">
            <ShieldCheck className="h-3.5 w-3.5" /> Gatekeeper-only · v2.5-SEC
          </div>
        </div>

        <div className="mx-auto flex w-full max-w-3xl flex-col gap-4">
          <CollapsibleSection
            title="1. Origen y factor"
            subtitle="Archivo + contraseña — flujo principal"
            accent="pink"
            defaultOpen
          >
            <div className="space-y-4">
              <div>
                <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <label className="flex items-center gap-2 text-xs font-bold text-white/50 uppercase">
                    Recurso de origen
                  </label>
                  {isSignedIn && (
                    <button
                      type="button"
                      onClick={() => {
                        openFilePicker((fileBlob, fileName) => {
                          setFile(new File([fileBlob], fileName, { type: fileBlob.type }));
                        });
                      }}
                      className="flex cursor-pointer items-center gap-1 rounded border border-indigo-500/40 bg-indigo-500/20 px-2.5 py-1 text-[11px] text-indigo-300 hover:bg-indigo-500/30"
                    >
                      <HardDrive className="h-3 w-3" /> Importar desde Drive
                    </button>
                  )}
                </div>
                <input
                  type="file"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="w-full cursor-pointer text-sm text-white/80 file:mr-4 file:rounded-lg file:border-0 file:bg-pink-500/20 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-pink-400 hover:file:bg-pink-500/30"
                />
                {file && (
                  <div className="mt-3 flex items-center justify-between rounded border border-white/5 bg-black/30 p-2.5 font-mono text-xs text-white/70">
                    <span className="max-w-[200px] truncate sm:max-w-xs">{file.name}</span>
                    <span className="font-mono text-white/40">{(file.size / 1024).toFixed(1)} KB</span>
                  </div>
                )}
              </div>

              <div className="space-y-3 border-t border-white/5 pt-4">
                <div className="flex items-center justify-between gap-2">
                  <label className="flex items-center gap-2 text-xs font-bold text-white/50 uppercase">
                    <KeyRound className="h-4 w-4" /> Factor de contraseña (no autoriza sola)
                  </label>
                  <span className={`shrink-0 text-[10px] font-bold tracking-wider uppercase ${pwdStrength.color}`}>
                    {pwdStrength.label}
                  </span>
                </div>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <input
                    type="text"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Factor adicional de derivación"
                    className="min-w-0 flex-1 rounded border border-white/10 bg-white/5 p-3 font-mono text-sm text-white outline-none focus:border-pink-500/50"
                  />
                  <button
                    onClick={generatePassword}
                    className="flex shrink-0 items-center justify-center gap-1.5 rounded bg-white/10 px-4 py-3 text-xs font-bold uppercase hover:bg-white/20 sm:py-0"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Auto
                  </button>
                </div>
                <p className="text-[10px] text-white/50">{pwdStrength.feedback}</p>
              </div>
            </div>
          </CollapsibleSection>

          <CollapsibleSection
            title="Política"
            subtitle="Nivel Oracle · caducidad · EXTRACT"
            accent="amber"
            defaultOpen={false}
          >
            <div className="space-y-5">
              <div>
                <label className="mb-3 flex items-center gap-2 text-xs font-bold text-white/50 uppercase">
                  <ShieldAlert className="h-4 w-4" /> Nivel de política (Oracle)
                </label>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {(['NORMAL', 'STANDARD', 'CRITICAL', 'ULTRA_CRITICAL'] as PolicyLevel[]).map((level) => (
                    <button
                      key={level}
                      type="button"
                      onClick={() => setPolicyLevel(level)}
                      className={`rounded-lg border px-3 py-2 text-left text-[11px] font-bold ${
                        policyLevel === level
                          ? 'border-pink-500/60 bg-pink-500/20 text-pink-200'
                          : 'border-white/10 bg-black/30 text-white/60 hover:bg-white/5'
                      }`}
                    >
                      {level.replace('_', ' ')}
                    </button>
                  ))}
                </div>
                <p className="mt-2 text-[11px] text-white/50">{POLICY_HELP[policyLevel]}</p>
              </div>

              <div className="space-y-4 border-t border-white/5 pt-4">
                <label className="mb-1 flex items-center gap-2 text-xs font-bold text-white/50 uppercase">
                  <Clock className="h-4 w-4" /> Política de uso
                </label>
                <div>
                  <label className="mb-2 flex cursor-pointer items-center gap-3">
                    <input
                      type="checkbox"
                      checked={daysRestriction}
                      onChange={(e) => setDaysRestriction(e.target.checked)}
                      className="h-4 w-4 rounded bg-white/5 text-pink-500"
                    />
                    <span className="text-sm">Caducidad (reloj del Oracle)</span>
                  </label>
                  {daysRestriction && (
                    <div className="ml-7 flex items-center gap-2">
                      <input
                        type="number"
                        min={1}
                        value={days}
                        onChange={(e) => setDays(Number(e.target.value))}
                        className="w-20 rounded border border-pink-500/50 bg-white/5 p-1.5 text-center text-sm font-bold text-pink-300"
                      />
                      <span className="text-xs text-white/50">días</span>
                    </div>
                  )}
                </div>
                <label className="flex cursor-pointer items-center gap-3">
                  <input
                    type="checkbox"
                    checked={viewOnce}
                    onChange={(e) => setViewOnce(e.target.checked)}
                    className="h-4 w-4 rounded bg-white/5 text-emerald-500"
                  />
                  <span className="text-sm font-medium text-emerald-400">Vista única (consumo en Oracle)</span>
                </label>
                <label className="flex cursor-pointer items-center gap-3">
                  <input
                    type="checkbox"
                    checked={allowExtraction}
                    onChange={(e) => setAllowExtraction(e.target.checked)}
                    className="h-4 w-4 rounded bg-white/5 text-emerald-500"
                  />
                  <span className="text-sm text-emerald-400">Permitir EXTRACT con grant específico</span>
                </label>
              </div>
            </div>
          </CollapsibleSection>

          <CollapsibleSection
            title="Avanzado"
            subtitle="Visor · marca forense · formatos"
            accent="indigo"
            defaultOpen={false}
          >
            <div className="space-y-4">
              <label className="flex items-center gap-2 text-xs font-bold text-white/50 uppercase">
                <EyeOff className="h-4 w-4" /> Preferencias de visor (no son autoridad)
              </label>
              <label className="flex cursor-pointer items-center gap-3">
                <input
                  type="checkbox"
                  checked={blurMode}
                  onChange={(e) => setBlurMode(e.target.checked)}
                  className="h-4 w-4 rounded bg-white/5 text-pink-500"
                />
                <span className="text-sm">Modo anti-fisgones (UI)</span>
              </label>
              <label className="flex cursor-pointer items-start gap-3">
                <input
                  type="checkbox"
                  checked={watermark}
                  onChange={(e) => setWatermark(e.target.checked)}
                  className="mt-1 h-4 w-4 rounded bg-white/5 text-emerald-500"
                />
                <span className="text-sm text-emerald-300">Solicitar marca forense de sesión</span>
              </label>

              <div className="border-t border-white/5 pt-4">
                <div className="mb-2 flex items-center gap-2 text-xs font-bold tracking-wider text-indigo-400 uppercase">
                  <Info className="h-4 w-4" /> Render en runtime controlado
                </div>
                <div className="grid grid-cols-1 gap-2 text-[11px] sm:grid-cols-2">
                  <div className="flex items-center gap-1.5 rounded bg-black/20 p-1.5 text-white/80">
                    <FileText className="h-3.5 w-3.5 shrink-0 text-indigo-400" /> PDF, TXT, JSON
                  </div>
                  <div className="flex items-center gap-1.5 rounded bg-black/20 p-1.5 text-white/80">
                    <ImageIcon className="h-3.5 w-3.5 shrink-0 text-emerald-400" /> PNG, JPG, WEBP
                  </div>
                  <div className="flex items-center gap-1.5 rounded bg-black/20 p-1.5 text-white/80">
                    <Music className="h-3.5 w-3.5 shrink-0 text-pink-400" /> MP3, WAV
                  </div>
                  <div className="flex items-center gap-1.5 rounded bg-black/20 p-1.5 text-white/80">
                    <Video className="h-3.5 w-3.5 shrink-0 text-purple-400" /> MP4, WebM
                  </div>
                </div>
                <div className="mt-2 flex items-center gap-1.5 text-[10px] text-white/40">
                  <Archive className="h-3 w-3 shrink-0" />
                  Binarios no renderizables requieren política EXTRACT.
                </div>
              </div>
            </div>
          </CollapsibleSection>

          <button
            disabled={isEncrypting}
            onClick={processEncrypt}
            className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-pink-500/50 bg-pink-500/20 p-4 font-bold tracking-wider text-pink-400 uppercase shadow-[0_0_20px_rgba(244,114,182,0.1)] hover:bg-pink-500/30 disabled:opacity-50"
          >
            <Lock className="h-5 w-5" />
            {isEncrypting ? 'Registrando política y sellando...' : 'Crear TDCPPackage y registrar en Oracle'}
          </button>
        </div>
      </div>

      <div className="glass-card h-28 overflow-y-auto border-l-2 border-l-pink-500 bg-black/40 p-4 font-mono text-xs whitespace-pre-wrap text-white/60">
        {logs}
      </div>
    </div>
  );
}
