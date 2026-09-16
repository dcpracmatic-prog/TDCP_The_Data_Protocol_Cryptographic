import React, { useState } from 'react';
import { useGoogleAuth, DriveFileItem } from '../lib/googleDriveContext.tsx';
import { useAuth } from '../lib/authContext.tsx';
import { 
  Folder, FileText, Download, ExternalLink, RefreshCw, 
  Search, Shield, KeyRound, HardDrive, AlertCircle, CheckCircle2, Lock, ArrowDownToLine,
  FolderPlus, ChevronDown, Check, Users
} from 'lucide-react';
import SharedFoldersManagerModal from './SharedFoldersManagerModal.tsx';

interface DriveFolderBrowserProps {
  onSelectDriveFileForDecrypt?: (fileBlob: Blob, fileName: string) => void;
}

export default function DriveFolderBrowser({ onSelectDriveFileForDecrypt }: DriveFolderBrowserProps) {
  const { currentUser, setDefaultFolder } = useAuth();
  const { 
    isSignedIn, 
    selectedFolder, 
    folderFiles, 
    isLoadingFolder, 
    fetchFolderContents, 
    openFolderPicker,
    downloadDriveFile 
  } = useGoogleAuth();

  const [searchFilter, setSearchFilter] = useState('');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const [isManagerOpen, setIsManagerOpen] = useState(false);
  const [isFolderDropdownOpen, setIsFolderDropdownOpen] = useState(false);

  const sharedFolders = currentUser?.sharedFolders || (currentUser?.driveFolderId ? [
    {
      id: currentUser.driveFolderId,
      name: currentUser.driveFolderName || 'Carpeta Principal',
      link: currentUser.driveFolderLink || `https://drive.google.com/drive/folders/${currentUser.driveFolderId}`,
      description: 'Carpeta predeterminada',
      isDefault: true,
      addedAt: currentUser.createdAt
    }
  ] : []);

  const handleSelectFolder = (folderId: string) => {
    setDefaultFolder(folderId);
    if (isSignedIn) {
      fetchFolderContents(folderId);
    }
    setIsFolderDropdownOpen(false);
  };

  if (!isSignedIn) {
    return (
      <div className="glass-card p-6 text-center border border-dashed border-white/10 rounded-xl space-y-3">
        <HardDrive className="w-8 h-8 text-white/40 mx-auto" />
        <h4 className="text-sm font-bold text-white">Google Drive Desconectado</h4>
        <p className="text-xs text-white/50 max-w-sm mx-auto">
          Inicia sesión arriba con tu cuenta de correo para vincular y explorar los archivos de tu carpeta compartida de Drive.
        </p>
      </div>
    );
  }

  if (!selectedFolder) {
    return (
      <div className="glass-card p-6 text-center border border-dashed border-indigo-500/30 rounded-xl space-y-3">
        <Folder className="w-8 h-8 text-indigo-400 mx-auto animate-pulse" />
        <h4 className="text-sm font-bold text-white">Ninguna carpeta compartida seleccionada</h4>
        <p className="text-xs text-white/50 max-w-sm mx-auto">
          Utiliza Google Picker para seleccionar la carpeta donde tienes permisos de edición compartida.
        </p>
        <button
          onClick={openFolderPicker}
          className="bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/50 px-4 py-2 rounded-lg text-xs font-bold transition-colors cursor-pointer"
        >
          Seleccionar Carpeta con Google Picker
        </button>
      </div>
    );
  }

  const filteredFiles = folderFiles.filter(f => 
    f.name.toLowerCase().includes(searchFilter.toLowerCase())
  );

  const handleDownloadFile = async (file: DriveFileItem) => {
    setDownloadingId(file.id);
    try {
      const blob = await downloadDriveFile(file.id, file.name);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setActionNotice(`Descargado: ${file.name}`);
      setTimeout(() => setActionNotice(null), 3000);
    } catch (err: any) {
      alert(`Error descargando archivo: ${err.message}`);
    } finally {
      setDownloadingId(null);
    }
  };

  const handleOpenInSandbox = async (file: DriveFileItem) => {
    if (!onSelectDriveFileForDecrypt) return;
    setDownloadingId(file.id);
    try {
      const blob = await downloadDriveFile(file.id, file.name);
      onSelectDriveFileForDecrypt(blob, file.name);
      setActionNotice(`¡Archivo ${file.name} cargado en el Visor Seguro!`);
      setTimeout(() => setActionNotice(null), 3000);
    } catch (err: any) {
      alert(`Error al cargar en visor: ${err.message}`);
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="glass-card p-5 border border-indigo-500/20 rounded-xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-3">
        <div className="flex items-center gap-3">
          <div className="relative">
            <button
              type="button"
              onClick={() => setIsFolderDropdownOpen(!isFolderDropdownOpen)}
              className="flex items-center gap-2 bg-black/40 hover:bg-black/60 px-3 py-1.5 rounded-lg border border-indigo-500/30 text-left transition-colors cursor-pointer"
            >
              <Folder className="w-4 h-4 text-indigo-400 shrink-0" />
              <div className="flex flex-col max-w-[160px] truncate">
                <span className="text-xs font-bold text-white uppercase tracking-wider truncate">
                  {selectedFolder.name}
                </span>
                <span className="text-[9px] text-emerald-400 flex items-center gap-0.5">
                  <Users className="w-2.5 h-2.5" /> Cambiar Carpeta
                </span>
              </div>
              <ChevronDown className={`w-3.5 h-3.5 text-white/50 transition-transform ${isFolderDropdownOpen ? 'rotate-180' : ''}`} />
            </button>

            {/* Selector Desplegable de Carpetas */}
            {isFolderDropdownOpen && (
              <div className="absolute left-0 mt-1.5 w-64 bg-[#0f111a] border border-indigo-500/40 rounded-xl shadow-[0_10px_30px_rgba(0,0,0,0.8)] py-1.5 z-40 animate-fade-in divide-y divide-white/10">
                <div className="px-3 py-1.5 text-[10px] uppercase font-bold text-white/40 flex items-center justify-between">
                  <span>Tus Carpetas</span>
                  <span>{sharedFolders.length} Registradas</span>
                </div>

                <div className="max-h-48 overflow-y-auto py-1 space-y-0.5 custom-scrollbar">
                  {sharedFolders.map(folder => {
                    const isActive = selectedFolder?.id === folder.id;
                    return (
                      <button
                        key={folder.id}
                        type="button"
                        onClick={() => handleSelectFolder(folder.id)}
                        className={`w-full px-3 py-1.5 text-left text-xs flex items-center justify-between gap-2 hover:bg-white/5 transition-colors cursor-pointer ${
                          isActive ? 'bg-indigo-500/20 text-indigo-200 font-bold' : 'text-white/80'
                        }`}
                      >
                        <span className="truncate">{folder.name}</span>
                        {isActive && <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" />}
                      </button>
                    );
                  })}
                </div>

                <div className="pt-1 px-1.5">
                  <button
                    type="button"
                    onClick={() => {
                      setIsFolderDropdownOpen(false);
                      setIsManagerOpen(true);
                    }}
                    className="w-full py-1.5 px-2 text-center text-xs text-indigo-300 hover:text-white bg-indigo-600/30 hover:bg-indigo-600/50 rounded-lg font-bold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <FolderPlus className="w-3.5 h-3.5" />
                    <span>Administrar / Agregar Carpetas</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={() => setIsManagerOpen(true)}
            className="text-[11px] text-indigo-300 hover:text-white bg-indigo-500/10 hover:bg-indigo-500/20 px-2.5 py-1.5 rounded-lg border border-indigo-500/30 font-semibold flex items-center gap-1 transition-colors cursor-pointer hidden sm:flex"
            title="Administrar carpetas compartidas"
          >
            <FolderPlus className="w-3 h-3" />
            <span>Editar / Agregar</span>
          </button>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-white/40" />
            <input 
              type="text"
              value={searchFilter}
              onChange={e => setSearchFilter(e.target.value)}
              placeholder="Buscar en carpeta..."
              className="bg-black/40 border border-white/10 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-white/30 focus:border-indigo-500/50 outline-none w-44"
            />
          </div>

          <button
            onClick={() => fetchFolderContents()}
            disabled={isLoadingFolder}
            title="Refrescar lista"
            className="p-2 hover:bg-white/10 rounded-lg text-white/60 hover:text-white border border-white/5 transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingFolder ? 'animate-spin text-indigo-400' : ''}`} />
          </button>
        </div>
      </div>

      {actionNotice && (
        <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-center gap-2 animate-fade-in">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Lista de Archivos */}
      <div className="max-h-60 overflow-y-auto space-y-2 pr-1">
        {isLoadingFolder ? (
          <div className="py-8 text-center text-xs text-white/50 flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
            Sincronizando archivos con Google Drive...
          </div>
        ) : filteredFiles.length === 0 ? (
          <div className="py-6 text-center text-xs text-white/40">
            {searchFilter ? 'No hay archivos que coincidan con la búsqueda.' : 'Esta carpeta compartida está vacía.'}
          </div>
        ) : (
          filteredFiles.map((file) => {
            const isPkg = file.name.endsWith('.pkg') || file.name.includes('.pkg');
            return (
              <div 
                key={file.id} 
                className="flex items-center justify-between p-2.5 bg-black/30 hover:bg-black/50 rounded-lg border border-white/5 transition-colors text-xs group"
              >
                <div className="flex items-center gap-2.5 min-w-0 pr-2">
                  {isPkg ? (
                    <div className="p-1.5 rounded bg-pink-500/20 text-pink-400 shrink-0">
                      <Lock className="w-3.5 h-3.5" />
                    </div>
                  ) : (
                    <div className="p-1.5 rounded bg-white/5 text-white/60 shrink-0">
                      <FileText className="w-3.5 h-3.5" />
                    </div>
                  )}
                  <div className="flex flex-col min-w-0">
                    <span className="text-white font-mono font-medium truncate">{file.name}</span>
                    <span className="text-[10px] text-white/40">
                      {file.modifiedTime ? new Date(file.modifiedTime).toLocaleDateString() : 'Drive File'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  {/* Si es un .pkg o archivo para descifrar, dar opción directa de inyectar en visor */}
                  {onSelectDriveFileForDecrypt && (
                    <button
                      onClick={() => handleOpenInSandbox(file)}
                      disabled={downloadingId === file.id}
                      className="px-2.5 py-1 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 rounded border border-indigo-500/40 text-[11px] font-semibold flex items-center gap-1 transition-colors cursor-pointer"
                    >
                      <Shield className="w-3 h-3" />
                      <span>{downloadingId === file.id ? 'Descargando...' : 'Descifrar'}</span>
                    </button>
                  )}

                  <button
                    onClick={() => handleDownloadFile(file)}
                    disabled={downloadingId === file.id}
                    title="Descargar a tu máquina"
                    className="p-1.5 hover:bg-white/10 rounded text-white/50 hover:text-white transition-colors cursor-pointer"
                  >
                    <ArrowDownToLine className="w-3.5 h-3.5" />
                  </button>

                  {file.webViewLink && (
                    <a
                      href={file.webViewLink}
                      target="_blank"
                      rel="noreferrer"
                      title="Abrir en Google Drive"
                      className="p-1.5 hover:bg-white/10 rounded text-white/40 hover:text-white transition-colors"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Modal de Gestión de Carpetas Compartidas */}
      <SharedFoldersManagerModal
        isOpen={isManagerOpen}
        onClose={() => setIsManagerOpen(false)}
      />
    </div>
  );
}
