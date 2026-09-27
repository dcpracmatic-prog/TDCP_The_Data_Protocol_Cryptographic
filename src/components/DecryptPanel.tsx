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
import { useUiPrefs } from '../lib/ui-prefs.tsx';
import {
  PROTECTION_MODES,
  getProtectionMode,
  type ProtectionModeId,
} from '../protection/protection-modes.ts';
import { createLocalCsgSeal, type CsgLocalSeal } from '../protection/csg-local-seal.ts';
import {
  softSmartTokenProtect,
  readSmartTokenApiConfig,
} from '../protection/smart-token-local.ts';
import { SmartTokenClient } from '../../sdk/typescript/src/smart-token-client.ts';

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
  const [protectionMode, setProtectionMode] = useState<ProtectionModeId>('tdcp');
  const modeMeta = useMemo(() => getProtectionMode(protectionMode), [protectionMode]);
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
    pkg: TDCPPackage | null;
    protectionMode: ProtectionModeId;
    csgSeal: CsgLocalSeal | null;
    sealDownloadUrl: string | null;
  } | null>(null);

  const { developerMode, addPackageHistory } = useUiPrefs();
  const [pwdCopied, setPwdCopied] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
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
    const needsSecret = modeMeta.encrypts || modeMeta.usesSmartToken;
    if (needsSecret && password.length < 8) {
      setLogs(
        modeMeta.usesSmartToken
          ? 'Error: el master Smart Token debe tener al menos 8 caracteres.'
          : 'Error: el factor de contraseña debe tener al menos 8 caracteres. No autoriza por sí sola.'
      );
      return;
    }

    setIsEncrypting(true);
    setEncryptionResult(null);
    setCopiedKey(false);
    setCopiedInstructions(false);
    setSharedStatus(null);
    setLogs(`>_ Modo ${modeMeta.short}: ${modeMeta.label}`);

    try {
      const plaintext = await file.arrayBuffer();
      let packageBlob: Blob;
      let pkgFileName: string;
      let integrityHash: string;
      let monitoringKey = '—';
      let pkg: TDCPPackage | null = null;
      let csgSeal: CsgLocalSeal | null = null;
      const summaryItems: string[] = [`Modo de protección: ${modeMeta.label}`];

      if (modeMeta.usesTdcp) {
        setLogs((prev) => prev + '\n[TDCP] createPackage() + registro de política en Authority/Oracle.');
        const created = await tdcpRuntime.createPackage({
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
        pkg = created.pkg;
        packageBlob = created.blob;
        monitoringKey = created.monitoringKey;
        pkgFileName = `TDCP_${file.name.replace(/\.[^/.]+$/, '')}.pkg`;
        integrityHash = pkg.integrityHash;
        summaryItems.push(
          `TDCPPackage ${pkg.version} · AES-256-GCM + HKDF`,
          `documentId ${pkg.documentId} · packageId ${pkg.packageId}`,
          `Política ${policyLevel} (no viaja en el archivo)`,
          'La contraseña sola no descifra. Apertura vía Gatekeeper.'
        );
        void addPackageHistory({
          fileName: file.name,
          pkgFileName,
          documentId: pkg.documentId,
          password,
        });
      } else if (modeMeta.usesSmartToken) {
        setLogs((prev) => prev + '\n[STP] Protección Smart Token…');
        const api = readSmartTokenApiConfig();
        if (api) {
          const client = new SmartTokenClient({
            baseUrl: api.baseUrl,
            apiKey: api.apiKey,
            fetchImpl: globalThis.fetch.bind(globalThis),
          });
          const result = await client.protect(file, password, file.name);
          const envelope = {
            schema: 'tdcp.stp-remote-ref.v1',
            artifact_id: result.artifact_id,
            filename: result.filename ?? file.name,
            status: result.status,
            api: api.baseUrl,
            developmentOnly: false,
          };
          packageBlob = new Blob([JSON.stringify(envelope, null, 2)], { type: 'application/json' });
          pkgFileName = `STP_${file.name.replace(/\.[^/.]+$/, '')}.stok.json`;
          integrityHash = result.artifact_id;
          monitoringKey = `STP-${result.artifact_id}`;
          summaryItems.push(
            `Smart Token remoto artifact_id=${result.artifact_id}`,
            `API ${api.baseUrl}`,
            'Master no se almacena en TDCP; solo en esta operación.'
          );
        } else {
          const soft = await softSmartTokenProtect(
            plaintext,
            password,
            file.name,
            file.type || 'application/octet-stream'
          );
          packageBlob = new Blob([JSON.stringify(soft, null, 2)], { type: 'application/json' });
          pkgFileName = `STP_${file.name.replace(/\.[^/.]+$/, '')}.soft.stok.json`;
          integrityHash = soft.artifactId;
          monitoringKey = `STP-SOFT-${soft.artifactId}`;
          summaryItems.push(
            `Soft Smart Token (demo AES-GCM) artifactId=${soft.artifactId}`,
            soft.note,
            'Configure VITE_SMART_TOKEN_API_URL para API real ML-KEM.'
          );
          void addPackageHistory({
            fileName: file.name,
            pkgFileName,
            documentId: soft.artifactId,
            password,
          });
        }
      } else {
        // csg_only: no encryption — package is original bytes
        packageBlob = new Blob([plaintext], { type: file.type || 'application/octet-stream' });
        pkgFileName = file.name;
        integrityHash = 'pending-csg';
        summaryItems.push(
          'Sin cifrado: el archivo permanece en claro.',
          'Solo se adjunta sello de integridad CSG local.'
        );
      }

      if (modeMeta.usesCsg) {
        setLogs((prev) => prev + '\n[CSG] Creando sello de integridad…');
        const bytes = new Uint8Array(await packageBlob.arrayBuffer());
        const seal = await createLocalCsgSeal(bytes, {
          label: modeMeta.id,
          attributes: {
            mode: modeMeta.id,
            fileName: file.name,
            integrityHash: integrityHash.slice(0, 32),
          },
        });
        csgSeal = seal;
        integrityHash = seal.contentDigest;
        summaryItems.push(
          `CSG local sealId=${seal.sealId}`,
          `digest SHA-256 ${seal.contentDigest.slice(0, 16)}…`,
          seal.note
        );
        setLogs((prev) => prev + `\n[CSG] Sello ${seal.sealId} OK`);
      }

      const blobUrl = URL.createObjectURL(packageBlob);
      let sealDownloadUrl: string | null = null;
      if (csgSeal) {
        sealDownloadUrl = URL.createObjectURL(
          new Blob([JSON.stringify(csgSeal, null, 2)], { type: 'application/json' })
        );
      }

      setEncryptionResult({
        downloadUrl: blobUrl,
        fileName: file.name,
        monitoringKey,
        summary: summaryItems,
        packageBlob,
        pkgFileName,
        integrityHash,
        pkg,
        protectionMode,
        csgSeal,
        sealDownloadUrl,
      });

      setLogs(
        (prev) =>
          prev +
          `\n[ÉXITO] Modo ${modeMeta.short} completado.` +
          (pkg ? `\n[TDCP] DOC=${pkg.documentId}` : '') +
          (csgSeal ? `\n[CSG] ${csgSeal.sealId}` : '')
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
documentId: ${encryptionResult.pkg?.documentId ?? encryptionResult.integrityHash}
packageId: ${encryptionResult.pkg?.packageId ?? encryptionResult.protectionMode}
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
      if (encryptionResult.pkg) {
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
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : String(err));
    } finally {
      setIsUploadingToDrive(false);
    }
  };

  if (encryptionResult) {
    return (
      <div className="flex h-full min-h-0 flex-col gap-2">
        <div className="glass-panel flex min-h-0 flex-1 flex-col overflow-y-auto p-3 md:p-4">
          <div className="mb-3 flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-emerald-500/50 bg-emerald-500/20">
              <CheckCircle className="h-5 w-5 text-emerald-400" />
            </div>
            <div className="min-w-0">
              <h2 className="text-base font-bold text-white">TDCPPackage sellado</h2>
              <p className="truncate font-mono text-xs text-emerald-400">{encryptionResult.pkgFileName}</p>
            </div>
          </div>

          <div className="mb-3 grid w-full grid-cols-1 gap-3 lg:grid-cols-2 lg:items-start">
            <div className="flex flex-col space-y-4">
              <div className="glass-card flex-1 border-l-2 border-l-emerald-500 p-3">
                <h3 className="mb-2 flex items-center gap-2 text-[11px] font-bold tracking-wider text-white/60 uppercase">
                  <ShieldAlert className="h-3.5 w-3.5 text-emerald-400" /> Política registrada
                </h3>
                <ul className="space-y-1.5">
                  {encryptionResult.summary.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-[11px] text-white/80">
                      <span className="mt-0.5 font-bold text-emerald-400">•</span>
                      <span className="leading-relaxed">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="glass-card border-l-2 border-l-pink-500 p-3">
                <h3 className="mb-1 flex items-center gap-2 text-[11px] font-bold tracking-wider text-white/60 uppercase">
                  <Activity className="h-3.5 w-3.5 text-pink-400" /> Clave de monitoreo (epoch / kill-switch)
                </h3>
                <p className="mb-2 text-[10px] leading-snug text-white/50" title="Revoca el documento en el Oracle. Incrementa epoch. No usa localStorage.">
                  Revoca en Oracle · epoch++ · no localStorage
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
              <div className="glass-card flex flex-1 flex-col justify-between border-l-2 border-l-indigo-500 p-3">
                <div>
                  <h3 className="mb-1.5 flex items-center gap-2 text-[11px] font-bold tracking-wider text-indigo-400 uppercase">
                    <Share2 className="h-3.5 w-3.5" /> Distribución de ciphertext
                  </h3>
                  <p className="mb-2 text-[10px] leading-snug text-white/55">
                    Drive / descarga / compartir = bytes cifrados. Ninguno autoriza.
                  </p>
                  <div className="space-y-2">
                    {isSignedIn && (
                      <button
                        onClick={handleUploadToDriveFolder}
                        disabled={isUploadingToDrive}
                        className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-indigo-500/60 bg-indigo-500/30 p-2.5 text-[11px] font-bold tracking-wider text-indigo-200 uppercase hover:bg-indigo-500/40 disabled:opacity-50"
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
                      className="flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-500/50 bg-emerald-500/20 p-2.5 text-center text-[11px] font-bold tracking-wider text-emerald-300 uppercase hover:bg-emerald-500/30"
                    >
                      <Download className="h-4 w-4" /> Descargar {encryptionResult.pkgFileName}
                    </a>
                    {encryptionResult.sealDownloadUrl && (
                      <a
                        href={encryptionResult.sealDownloadUrl}
                        download={`${encryptionResult.pkgFileName}.csg.json`}
                        className="flex w-full items-center justify-center gap-2 rounded-lg border border-cyan-500/50 bg-cyan-500/15 p-2.5 text-center text-[11px] font-bold tracking-wider text-cyan-200 uppercase hover:bg-cyan-500/25"
                      >
                        <ShieldCheck className="h-4 w-4" /> Descargar sello CSG
                      </a>
                    )}
                    <button
                      onClick={handleNativeShare}
                      className="flex w-full items-center justify-center gap-2 rounded-lg border border-indigo-500/50 bg-indigo-500/20 p-2.5 text-[11px] font-bold tracking-wider text-indigo-300 uppercase hover:bg-indigo-500/30"
                    >
                      <Share2 className="h-4 w-4" /> Compartir paquete
                    </button>
                    <button
                      onClick={copyDistributionInstructions}
                      className="flex w-full items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/5 p-2.5 text-[11px] font-semibold text-white/90 hover:bg-white/10"
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
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div className="glass-panel flex min-h-0 flex-1 flex-col overflow-y-auto p-3 md:p-4">
        <div className="mb-2 flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="flex items-center gap-2 text-base font-bold text-pink-400">
            <Lock className="h-4 w-4" /> TDCP · Crear paquete
          </h2>
          <div className="flex w-fit items-center gap-1.5 rounded-full border border-pink-500/30 bg-pink-500/10 px-2.5 py-0.5 text-[10px] text-pink-300">
            <ShieldCheck className="h-3 w-3" /> Gatekeeper-only · v2.5-SEC
          </div>
        </div>

        <div className="grid w-full grid-cols-1 gap-3 lg:grid-cols-2 lg:items-start">
          <div className="flex flex-col gap-3">
          <CollapsibleSection
            title="0. Modo de protección"
            subtitle="TDCP · Smart Token · CSG (opcionales)"
            accent="cyan"
            defaultOpen
          >
            <div className="space-y-2">
              <p className="text-[10px] leading-relaxed text-white/50">
                Elija cifrado TDCP, Smart Token, sello CSG solo, o combinaciones. CSG no cifra; solo atestigua integridad.
              </p>
              <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                {PROTECTION_MODES.map((m) => (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => setProtectionMode(m.id)}
                    className={`rounded-lg border px-2.5 py-2 text-left text-[10px] ${
                      protectionMode === m.id
                        ? 'border-cyan-500/60 bg-cyan-500/20 text-cyan-100'
                        : 'border-white/10 bg-black/30 text-white/65 hover:bg-white/5'
                    }`}
                  >
                    <span className="block font-bold tracking-wide uppercase">{m.short}</span>
                    <span className="mt-0.5 block leading-snug opacity-80">{m.label}</span>
                  </button>
                ))}
              </div>
              <p className="text-[10px] leading-relaxed text-white/45">{modeMeta.description}</p>
            </div>
          </CollapsibleSection>

          <CollapsibleSection
            title="1. Origen y factor"
            subtitle={modeMeta.usesSmartToken ? 'Archivo + master Smart Token' : modeMeta.encrypts ? 'Archivo + contraseña — flujo principal' : 'Archivo a sellar (sin cifrado)'}
            accent="pink"
            defaultOpen
          >
            <div className="space-y-3">
              <div>
                <div className="mb-1.5 flex flex-col gap-1.5 sm:flex-row sm:items-center sm:justify-between">
                  <label className="flex items-center gap-2 text-[11px] font-bold text-white/50 uppercase">
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
                    <span className="min-w-0 max-w-[min(100%,14rem)] truncate sm:max-w-xs">{file.name}</span>
                    <span className="font-mono text-white/40">{(file.size / 1024).toFixed(1)} KB</span>
                  </div>
                )}
              </div>

              <div className="space-y-2 border-t border-white/5 pt-3">
                <div className="flex items-center justify-between gap-2">
                  <label className="flex items-center gap-2 text-[11px] font-bold text-white/50 uppercase">
                    <KeyRound className="h-3.5 w-3.5" /> Factor de contraseña (no autoriza sola)
                  </label>
                  <span className={`shrink-0 text-[10px] font-bold tracking-wider uppercase ${pwdStrength.color}`}>
                    {pwdStrength.label}
                  </span>
                </div>
                <div className="flex w-full max-w-full flex-col gap-2 sm:flex-row">
                  <div className="relative min-w-0 flex-1">
                    <input
                      type="text"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Factor adicional de derivación"
                      className="w-full min-w-0 rounded border border-white/10 bg-white/5 p-2.5 pr-10 font-mono text-sm text-white outline-none focus:border-pink-500/50"
                    />
                    <button
                      type="button"
                      title="Copiar contraseña"
                      disabled={!password}
                      onClick={() => {
                        if (!password) return;
                        void navigator.clipboard.writeText(password);
                        setPwdCopied(true);
                        setTimeout(() => setPwdCopied(false), 2000);
                      }}
                      className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-1 text-white/50 hover:bg-white/10 hover:text-white disabled:opacity-30"
                    >
                      {pwdCopied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                  <button
                    type="button"
                    onClick={generatePassword}
                    className="flex w-full shrink-0 items-center justify-center gap-1.5 rounded bg-white/10 px-3 py-2.5 text-[11px] font-bold uppercase hover:bg-white/20 sm:w-auto sm:py-0"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Auto
                  </button>
                </div>
                {pwdCopied && (
                  <p className="text-[10px] font-semibold text-emerald-400">¡Copiado!</p>
                )}
                <p className="text-[10px] text-white/50">{pwdStrength.feedback}</p>
              </div>
            </div>
          </CollapsibleSection>

          <button
            disabled={isEncrypting}
            onClick={processEncrypt}
            className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-pink-500/50 bg-pink-500/20 p-3 text-sm font-bold tracking-wider text-pink-400 uppercase shadow-[0_0_20px_rgba(244,114,182,0.1)] hover:bg-pink-500/30 disabled:opacity-50"
          >
            <Lock className="h-4 w-4" />
            {isEncrypting ? 'Procesando…' : modeMeta.id === 'csg_only' ? 'Crear sello CSG de integridad' : modeMeta.usesSmartToken ? 'Proteger con Smart Token' : modeMeta.usesCsg ? 'Crear paquete TDCP + sello CSG' : 'Crear TDCPPackage y registrar en Oracle'}
          </button>
          </div>

          <div className="flex flex-col gap-3">
          {modeMeta.usesTdcp && (
          <CollapsibleSection
            title="2. Política"
            subtitle="Nivel Oracle · caducidad · EXTRACT"
            accent="amber"
            defaultOpen
          >
            <div className="space-y-3">
              <div>
                <label className="mb-1.5 flex items-center gap-2 text-[11px] font-bold text-white/50 uppercase">
                  <ShieldAlert className="h-3.5 w-3.5" /> Nivel de política (Oracle)
                </label>
                <div className="grid grid-cols-2 gap-1.5">
                  {(['NORMAL', 'STANDARD', 'CRITICAL', 'ULTRA_CRITICAL'] as PolicyLevel[]).map((level) => (
                    <button
                      key={level}
                      type="button"
                      onClick={() => setPolicyLevel(level)}
                      title={POLICY_HELP[level]}
                      className={`rounded-lg border px-2 py-1.5 text-left text-[10px] font-bold ${
                        policyLevel === level
                          ? 'border-pink-500/60 bg-pink-500/20 text-pink-200'
                          : 'border-white/10 bg-black/30 text-white/60 hover:bg-white/5'
                      }`}
                    >
                      {level.replace('_', ' ')}
                    </button>
                  ))}
                </div>
                <p className="mt-1.5 text-[10px] text-white/45">{POLICY_HELP[policyLevel]}</p>
              </div>

              <div className="space-y-2.5 border-t border-white/5 pt-3">
                <label className="mb-0.5 flex items-center gap-2 text-[11px] font-bold text-white/50 uppercase">
                  <Clock className="h-3.5 w-3.5" /> Política de uso
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
          )}

          <CollapsibleSection
            title="Avanzado"
            subtitle="Visor · marca forense · formatos"
            accent="indigo"
            defaultOpen={developerMode}
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

          </div>
        </div>
      </div>

      <div className="glass-card h-16 shrink-0 overflow-y-auto border-l-2 border-l-pink-500 bg-black/40 p-2 font-mono text-[10px] leading-snug whitespace-pre-wrap text-white/55">
        {logs}
      </div>
    </div>
  );
}
