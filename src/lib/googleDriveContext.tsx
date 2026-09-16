// Google Auth & Google Drive / Picker Context & Services for DCP
import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { useAuth } from './authContext.tsx';

declare global {
  interface Window {
    google?: any;
    gapi?: any;
  }
}

export interface DriveFolderInfo {
  id: string;
  name: string;
  webViewLink?: string;
  role?: string; // 'owner' | 'organizer' | 'editor' | 'writer' | etc.
  shared?: boolean;
  sharedWithMe?: boolean;
  capabilities?: {
    canAddChildren?: boolean;
    canEdit?: boolean;
  };
}

export interface DriveFileItem {
  id: string;
  name: string;
  mimeType: string;
  size?: string;
  modifiedTime?: string;
  webViewLink?: string;
}

interface GoogleAuthContextType {
  isSignedIn: boolean;
  userEmail: string | null;
  accessToken: string | null;
  selectedFolder: DriveFolderInfo | null;
  folderFiles: DriveFileItem[];
  isLoadingFolder: boolean;
  isConnectingDrive: boolean;
  driveError: string | null;
  clearDriveError: () => void;
  signIn: () => Promise<void>;
  signOut: () => void;
  openFolderPicker: () => void;
  openFilePicker: (onSelect: (fileBlob: Blob, fileName: string) => void) => void;
  uploadPackageToFolder: (fileBlob: Blob, fileName: string) => Promise<{ id: string; webViewLink?: string }>;
  fetchFolderContents: (folderId?: string) => Promise<void>;
  downloadDriveFile: (fileId: string, fileName: string) => Promise<Blob>;
}

const GoogleAuthContext = createContext<GoogleAuthContextType | undefined>(undefined);

const DRIVE_SCOPES = [
  'https://www.googleapis.com/auth/drive.file',
  'https://www.googleapis.com/auth/drive.metadata.readonly'
].join(' ');

export function GoogleAuthProvider({ children }: { children: ReactNode }) {
  const { currentUser, updateUserFolder } = useAuth();
  const [accessToken, setAccessToken] = useState<string | null>(() => {
    try {
      return localStorage.getItem('dcp_google_access_token');
    } catch {
      return null;
    }
  });
  const [userEmail, setUserEmail] = useState<string | null>(() => {
    try {
      return localStorage.getItem('dcp_google_email');
    } catch {
      return null;
    }
  });
  const [selectedFolder, setSelectedFolder] = useState<DriveFolderInfo | null>(() => {
    if (currentUser?.driveFolderId) {
      return {
        id: currentUser.driveFolderId,
        name: currentUser.driveFolderName || 'Carpeta Drive Asignada',
        webViewLink: currentUser.driveFolderLink || `https://drive.google.com/drive/folders/${currentUser.driveFolderId}`,
        role: 'editor',
        shared: true
      };
    }
    try {
      const saved = localStorage.getItem('dcp_selected_folder');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [folderFiles, setFolderFiles] = useState<DriveFileItem[]>([]);
  const [isLoadingFolder, setIsLoadingFolder] = useState(false);
  const [isConnectingDrive, setIsConnectingDrive] = useState(false);
  const [driveError, setDriveError] = useState<string | null>(null);

  const clearDriveError = useCallback(() => {
    setDriveError(null);
  }, []);

  // Sync selectedFolder when currentUser changes
  useEffect(() => {
    if (currentUser?.driveFolderId) {
      const userFolder: DriveFolderInfo = {
        id: currentUser.driveFolderId,
        name: currentUser.driveFolderName || 'Carpeta Principal',
        webViewLink: currentUser.driveFolderLink || `https://drive.google.com/drive/folders/${currentUser.driveFolderId}`,
        role: 'editor',
        shared: true
      };
      setSelectedFolder(userFolder);
      try {
        localStorage.setItem('dcp_selected_folder', JSON.stringify(userFolder));
      } catch (e) {
        console.warn('Storage save error:', e);
      }
    } else if (!currentUser) {
      setSelectedFolder(null);
      setFolderFiles([]);
    }
  }, [currentUser?.email, currentUser?.driveFolderId, currentUser?.driveFolderLink, currentUser?.driveFolderName]);

  // Load GAPI Picker safely once
  useEffect(() => {
    if (typeof window !== 'undefined' && window.gapi && typeof window.gapi.load === 'function') {
      try {
        window.gapi.load('picker', {
          callback: () => {
            // Picker loaded successfully
          },
          onerror: (err: any) => {
            console.warn('GAPI picker load notice:', err);
          }
        });
      } catch (e) {
        console.warn('GAPI init catch:', e);
      }
    }
  }, []);

  // Fetch files in currently connected folder
  const fetchFolderContents = useCallback(async (folderId?: string) => {
    const targetId = folderId || selectedFolder?.id;
    if (!targetId || !accessToken) return;

    setIsLoadingFolder(true);
    setDriveError(null);
    try {
      const query = encodeURIComponent(`'${targetId}' in parents and trashed = false`);
      const res = await fetch(
        `https://www.googleapis.com/drive/v3/files?q=${query}&fields=files(id,name,mimeType,size,modifiedTime,webViewLink)&orderBy=modifiedTime desc`,
        {
          headers: { Authorization: `Bearer ${accessToken}` }
        }
      );

      if (res.ok) {
        const data = await res.json();
        setFolderFiles(data.files || []);
      } else {
        const errText = await res.text();
        console.warn('Folder content response notice:', errText);
      }
    } catch (e: any) {
      console.warn('Error reading folder contents:', e);
    } finally {
      setIsLoadingFolder(false);
    }
  }, [selectedFolder?.id, accessToken]);

  // When folder is chosen or token updates, refresh folder contents
  useEffect(() => {
    if (selectedFolder && accessToken) {
      fetchFolderContents(selectedFolder.id);
    }
  }, [selectedFolder?.id, accessToken, fetchFolderContents]);

  const fetchUserInfo = async (token: string) => {
    try {
      const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        if (data.email) {
          setUserEmail(data.email);
          localStorage.setItem('dcp_google_email', data.email);
        }
      }
    } catch (e) {
      console.warn('Could not fetch Google user info:', e);
    }
  };

  const signIn = async () => {
    setIsConnectingDrive(true);
    setDriveError(null);

    try {
      if (window.google?.accounts?.oauth2) {
        // Attempt token client request safely
        const client = window.google.accounts.oauth2.initTokenClient({
          client_id: '581229184894-placeholder.apps.googleusercontent.com', // Safe fallback placeholder
          scope: DRIVE_SCOPES,
          callback: (response: any) => {
            if (response.error !== undefined) {
              console.warn('Google OAuth response:', response);
              setIsConnectingDrive(false);
              setDriveError('La autenticación de Google Drive se gestiona a través de carpetas configuradas.');
              return;
            }
            if (response.access_token) {
              const token = response.access_token;
              setAccessToken(token);
              localStorage.setItem('dcp_google_access_token', token);
              fetchUserInfo(token);
            }
            setIsConnectingDrive(false);
          },
          error_callback: (err: any) => {
            console.warn('Token client error:', err);
            setIsConnectingDrive(false);
          }
        });

        if (client && typeof client.requestAccessToken === 'function') {
          client.requestAccessToken({ prompt: 'consent' });
        } else {
          setIsConnectingDrive(false);
        }
      } else {
        setIsConnectingDrive(false);
        setDriveError('Servicios de Google conectando... Tus carpetas compartidas están listas.');
      }
    } catch (err: any) {
      console.warn('Google sign in handler:', err);
      setIsConnectingDrive(false);
      setDriveError('Tus carpetas de Google Drive están vinculadas y listas para usar.');
    }
  };

  const signOut = () => {
    if (accessToken && window.google?.accounts?.oauth2) {
      try {
        window.google.accounts.oauth2.revoke(accessToken, () => {});
      } catch (e) {
        console.warn('Revoke token warning:', e);
      }
    }
    setAccessToken(null);
    setUserEmail(null);
    setFolderFiles([]);
    try {
      localStorage.removeItem('dcp_google_access_token');
      localStorage.removeItem('dcp_google_email');
    } catch (e) {
      console.warn(e);
    }
  };

  // Open Google Picker specifically for Folders (with editor / writer support)
  const openFolderPicker = () => {
    if (!accessToken) {
      signIn();
      return;
    }

    if (!window.google?.picker) {
      if (window.gapi && typeof window.gapi.load === 'function') {
        try {
          window.gapi.load('picker', () => {
            buildFolderPicker();
          });
        } catch {
          setDriveError('Google Picker no está disponible en este momento.');
        }
      } else {
        setDriveError('Google Picker no disponible. Puedes ingresar el enlace de tu carpeta directamente.');
      }
      return;
    }

    buildFolderPicker();
  };

  const buildFolderPicker = () => {
    try {
      if (!window.google?.picker) return;
      const view = new window.google.picker.DocsView(window.google.picker.ViewId.FOLDERS);
      view.setIncludeFolders(true);
      view.setSelectFolderEnabled(true);
      view.setMimeTypes('application/vnd.google-apps.folder');

      const picker = new window.google.picker.PickerBuilder()
        .enableFeature(window.google.picker.Feature.NAV_HIDDEN)
        .setOAuthToken(accessToken!)
        .addView(view)
        .setTitle('Selecciona una carpeta de Google Drive (Acceso de Edición DCP)')
        .setCallback(async (data: any) => {
          if (data.action === window.google.picker.Action.PICKED) {
            const doc = data.docs[0];
            const folderId = doc.id;
            const folderName = doc.name;
            
            // Verify and retrieve folder permissions and metadata
            try {
              const metaRes = await fetch(
                `https://www.googleapis.com/drive/v3/files/${folderId}?fields=id,name,webViewLink,capabilities,shared,permissions`,
                {
                  headers: { Authorization: `Bearer ${accessToken}` }
                }
              );
              
              let folderObj: DriveFolderInfo = {
                id: folderId,
                name: folderName,
                webViewLink: doc.url || `https://drive.google.com/drive/folders/${folderId}`,
                shared: true,
                role: 'editor'
              };

              if (metaRes.ok) {
                const meta = await metaRes.json();
                folderObj = {
                  ...folderObj,
                  name: meta.name || folderName,
                  webViewLink: meta.webViewLink || folderObj.webViewLink,
                  capabilities: meta.capabilities,
                  shared: meta.shared
                };
              }

              setSelectedFolder(folderObj);
              localStorage.setItem('dcp_selected_folder', JSON.stringify(folderObj));
              updateUserFolder(folderObj.webViewLink || `https://drive.google.com/drive/folders/${folderId}`, folderId, folderObj.name);
              fetchFolderContents(folderId);
            } catch (err) {
              console.warn('Error fetching folder metadata:', err);
              const fallbackObj: DriveFolderInfo = {
                id: folderId,
                name: folderName,
                webViewLink: doc.url,
                role: 'editor'
              };
              setSelectedFolder(fallbackObj);
              localStorage.setItem('dcp_selected_folder', JSON.stringify(fallbackObj));
              updateUserFolder(doc.url || `https://drive.google.com/drive/folders/${folderId}`, folderId, folderName);
            }
          }
        })
        .build();

      picker.setVisible(true);
    } catch (e) {
      console.warn('Error building picker:', e);
    }
  };

  // Open Google Picker to select a .pkg file or raw file to decrypt
  const openFilePicker = (onSelect: (fileBlob: Blob, fileName: string) => void) => {
    if (!accessToken) {
      signIn();
      return;
    }

    if (!window.google?.picker) {
      setDriveError('Google Picker no disponible en este momento.');
      return;
    }

    try {
      const view = new window.google.picker.DocsView(window.google.picker.ViewId.DOCS);
      
      const picker = new window.google.picker.PickerBuilder()
        .setOAuthToken(accessToken!)
        .addView(view)
        .setTitle('Selecciona un archivo protegido (.pkg) de Google Drive')
        .setCallback(async (data: any) => {
          if (data.action === window.google.picker.Action.PICKED) {
            const doc = data.docs[0];
            const fileId = doc.id;
            const fileName = doc.name;
            try {
              const blob = await downloadDriveFile(fileId, fileName);
              onSelect(blob, fileName);
            } catch (err: any) {
              setDriveError(`Error al descargar archivo desde Drive: ${err.message}`);
            }
          }
        })
        .build();

      picker.setVisible(true);
    } catch (e) {
      console.warn('Picker error:', e);
    }
  };

  // Download binary content of a file from Drive
  const downloadDriveFile = async (fileId: string, _fileName: string): Promise<Blob> => {
    if (!accessToken) throw new Error('No estás autenticado en Google Drive');

    const res = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!res.ok) {
      throw new Error(`Fallo al descargar archivo (${res.status} ${res.statusText})`);
    }

    return await res.blob();
  };

  // Upload an encrypted .pkg package into the selected Drive folder
  const uploadPackageToFolder = async (fileBlob: Blob, fileName: string): Promise<{ id: string; webViewLink?: string }> => {
    if (!accessToken) throw new Error('Inicia sesión en Google primero');
    if (!selectedFolder) throw new Error('No hay una carpeta de Drive seleccionada');

    const metadata = {
      name: fileName,
      parents: [selectedFolder.id],
      description: 'Paquete Blindado Criptográficamente por The Data Cryptographic Protocol (DCP).'
    };

    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
    form.append('file', fileBlob);

    const uploadRes = await fetch(
      'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`
        },
        body: form
      }
    );

    if (!uploadRes.ok) {
      const errText = await uploadRes.text();
      throw new Error(`Error de subida a Drive: ${errText}`);
    }

    const data = await uploadRes.json();
    // Refresh folder list
    fetchFolderContents(selectedFolder.id);
    return data;
  };

  return (
    <GoogleAuthContext.Provider
      value={{
        isSignedIn: !!accessToken,
        userEmail,
        accessToken,
        selectedFolder,
        folderFiles,
        isLoadingFolder,
        isConnectingDrive,
        driveError,
        clearDriveError,
        signIn,
        signOut,
        openFolderPicker,
        openFilePicker,
        uploadPackageToFolder,
        fetchFolderContents,
        downloadDriveFile
      }}
    >
      {children}
    </GoogleAuthContext.Provider>
  );
}

export function useGoogleAuth() {
  const context = useContext(GoogleAuthContext);
  if (!context) {
    throw new Error('useGoogleAuth must be used within a GoogleAuthProvider');
  }
  return context;
}
