/** Shared, strict parsing for Google Drive folder references. */
export interface SharedDriveFolder {
  id: string;
  name: string;
  link: string;
  description: string;
  isDefault: boolean;
  addedAt: number;
}

export const CUSTOM_ID_PATTERN = /^DCP-USR-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

export function generateCustomUserId(prefix = 'DCP-USR'): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `${prefix}-${hex.slice(0, 4)}-${hex.slice(4)}`;
}

/** Accept only a folder ID or canonical Google Drive folder URL; never arbitrary URLs. */
export function parseDriveFolderStrict(value: string): { folderId: string; cleanUrl: string } | null {
  const trimmed = value.trim();
  if (/^[A-Za-z0-9_-]{15,}$/.test(trimmed)) {
    return { folderId: trimmed, cleanUrl: `https://drive.google.com/drive/folders/${trimmed}` };
  }
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'https:' || url.hostname !== 'drive.google.com') return null;
    const match = url.pathname.match(/^\/drive\/folders\/([A-Za-z0-9_-]{15,})\/?$/);
    if (!match?.[1]) return null;
    return { folderId: match[1], cleanUrl: `https://drive.google.com/drive/folders/${match[1]}` };
  } catch {
    return null;
  }
}
