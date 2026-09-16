import React, { useState } from 'react';
import { useGoogleAuth } from '../lib/googleDriveContext.tsx';
import { useAuth } from '../lib/authContext.tsx';
import { 
  LogIn, LogOut, ExternalLink, 
  FolderPlus, FolderCheck, RefreshCw, HardDrive, Users, Cloud, Edit3, ChevronDown, Check, Settings2
} from 'lucide-react';
import SharedFoldersManagerModal from './SharedFoldersManagerModal.tsx';

export default function GoogleDriveBar() {
  const { currentUser, setDefaultFolder } = useAuth();
  const { 
    isSignedIn, 
    userEmail, 
    selectedFolder, 
    signIn, 
    signOut, 
    fetchFolderContents,
    isLoadingFolder,
    isConnectingDrive,
    driveError,
    clearDriveError
  } = useGoogleAuth();

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  const sharedFolders = currentUser?.sharedFolders || (currentUser?.driveFolderId ? [
    {
      id: currentUser.driveFolderId,
      name: currentUser.driveFolderName || 'Carpeta Principal',
      link: currentUser.driveFolderLink || `https://drive.google.com/drive/folders/${currentUser.driveFolderId}`,
      description: 'Carpeta asignada',
      isDefault: true,
      addedAt: currentUser.createdAt
    }
  ] : []);

  const activeFolderName = selectedFolder?.name || currentUser?.driveFolderName || (sharedFolders[0]?.name) || 'Carpeta Asignada';
  const activeFolderLink = selectedFolder?.webViewLink || currentUser?.driveFolderLink || (sharedFolders[0]?.link);

  const handleSelectQuickFolder = (folderId: string) => {
    setDefaultFolder(folderId);
    if (isSignedIn) {
      fetchFolderContents(folderId);
    }
    setIsDropdownOpen(false);
  };

  return (
    <>
      <div className="glass-card p-3 border border-indigo-500/30 bg-indigo-950/40 rounded-xl mb-4 flex flex-wrap items-center justify-between gap-3 text-xs">
        
        {/* Estado de Cuenta & Correo */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400 shrink-0">
            <Cloud className="w-4 h-4" />
          </div>
          
          {isSignedIn ? (
            <div>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-white font-semibold">{userEmail || 'Conectado a Google'}</span>
                <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/30 uppercase font-mono">
                  Drive Sincronizado
                </span>
              </div>
              <div className="text-[11px] text-white/50 flex items-center gap-2 mt-0.5">
                <span>Google Drive API v3</span>
                <span>•</span>
                <span>Almacenamiento Conectado</span>
              </div>
            </div>
          ) : (
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-white/90 font-medium">Almacenamiento Seguro en Google Drive</span>
                <span className="text-[10px] text-indigo-300 bg-indigo-500/20 px-1.5 py-0.5 rounded border border-indigo-500/30 font-bold">
                  {sharedFolders.length} {sharedFolders.length === 1 ? 'Carpeta Registrada' : 'Carpetas Registradas'}
                </span>
              </div>
              <div className="text-[11px] text-white/50">
                {currentUser?.driveFolderLink ? 'Carpetas compartidas configuradas en tu perfil DCP' : 'Conecta tu cuenta para sincronizar con Drive'}
              </div>
            </div>
          )}
        </div>

        {/* Acciones de Carpetas Compartidas & Conexión */}
        <div className="flex items-center gap-2.5 flex-wrap">
          
          {/* Selector y Selector Rápido de Carpeta Activa */}
          <div className="relative">
            <div className="flex items-center gap-1 bg-black/50 p-1 rounded-lg border border-indigo-500/40">
              <button
                type="button"
                onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                className="flex items-center gap-2 px-2 py-1 rounded hover:bg-white/5 text-left transition-colors cursor-pointer"
                title="Cambiar carpeta activa de Google Drive"
              >
                <FolderCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                <div className="flex flex-col max-w-[150px] truncate">
                  <span className="text-[11px] font-bold text-white truncate">{activeFolderName}</span>
                  <span className="text-[9px] text-emerald-300 flex items-center gap-0.5">
                    <Users className="w-2.5 h-2.5" /> Carpeta Activa
                  </span>
                </div>
                <ChevronDown className={`w-3 h-3 text-white/50 transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`} />
              </button>

              {activeFolderLink && (
                <a 
                  href={activeFolderLink} 
                  target="_blank" 
                  rel="noreferrer" 
                  title="Abrir carpeta en Google Drive"
                  className="p-1.5 hover:bg-white/10 rounded text-white/60 hover:text-white transition-colors"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              )}

              {isSignedIn && (
                <button
                  onClick={() => fetchFolderContents()}
                  disabled={isLoadingFolder}
                  title="Sincronizar archivos"
                  className="p-1.5 hover:bg-white/10 rounded text-white/60 hover:text-white transition-colors disabled:opacity-50 cursor-pointer"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isLoadingFolder ? 'animate-spin text-indigo-400' : ''}`} />
                </button>
              )}
            </div>

            {/* Menú Desplegable Rápido de Carpetas */}
            {isDropdownOpen && (
              <div className="absolute left-0 mt-1.5 w-64 bg-[#0f111a] border border-indigo-500/40 rounded-xl shadow-[0_10px_30px_rgba(0,0,0,0.8)] py-1.5 z-40 animate-fade-in divide-y divide-white/10">
                <div className="px-3 py-1.5 text-[10px] uppercase font-bold text-white/40 flex items-center justify-between">
                  <span>Carpetas Compartidas</span>
                  <span>{sharedFolders.length} Total</span>
                </div>

                <div className="max-h-48 overflow-y-auto py-1 space-y-0.5 custom-scrollbar">
                  {sharedFolders.map(folder => {
                    const isActive = (currentUser?.driveFolderId === folder.id) || (selectedFolder?.id === folder.id);
                    return (
                      <button
                        key={folder.id}
                        type="button"
                        onClick={() => handleSelectQuickFolder(folder.id)}
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
                      setIsDropdownOpen(false);
                      setIsModalOpen(true);
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

          {/* Botón Principal: Administrar / Editar / Agregar Carpetas */}
          <button
            type="button"
            onClick={() => setIsModalOpen(true)}
            className="bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-200 border border-indigo-500/50 px-3 py-1.5 rounded-lg font-bold flex items-center gap-1.5 transition-colors cursor-pointer text-xs shadow-[0_0_12px_rgba(99,102,241,0.2)]"
            title="Administrar carpetas compartidas de Google Drive"
          >
            <FolderPlus className="w-3.5 h-3.5 text-indigo-300" />
            <span>Editar / Agregar Carpetas</span>
          </button>

          {/* Autenticación con Google (Opcional / Estado) */}
          {isSignedIn ? (
            <button
              onClick={signOut}
              title="Cerrar sesión de Google"
              className="p-2 hover:bg-white/10 rounded-lg text-white/40 hover:text-red-400 border border-white/5 transition-colors cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          ) : (
            <button
              onClick={signIn}
              disabled={isConnectingDrive}
              className="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/50 px-3 py-1.5 rounded-lg font-bold flex items-center gap-1.5 transition-colors cursor-pointer shadow-[0_0_12px_rgba(16,185,129,0.2)] text-xs"
              title="Autorizar subida directa a Google Drive"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>{isConnectingDrive ? 'Conectando...' : 'Autorizar Subida Directa'}</span>
            </button>
          )}

        </div>
      </div>

      {/* Aviso / Estado de Google Drive */}
      {driveError && (
        <div className="mb-4 p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-300 text-xs flex items-center justify-between gap-2 animate-fade-in">
          <span>{driveError}</span>
          <button
            type="button"
            onClick={clearDriveError}
            className="text-white/50 hover:text-white text-[11px] font-bold px-2 py-0.5 rounded hover:bg-white/10"
          >
            Entendido
          </button>
        </div>
      )}

      {/* Modal de Gestión de Carpetas Compartidas */}
      <SharedFoldersManagerModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
      />
    </>
  );
}
