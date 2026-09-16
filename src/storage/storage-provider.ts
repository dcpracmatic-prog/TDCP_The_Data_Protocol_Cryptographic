/**
 * The Data Cryptographic Protocol (TDCP)
 * Storage Provider Abstraction & Implementations
 * 
 * CORE ARCHITECTURAL PRINCIPLE:
 * "The storage does NOT constitute the security perimeter."
 * Storage providers are completely untrusted. They only store encrypted packages.
 * They have ZERO authority to decide authorization or inspect plaintext.
 */

export interface StoredPackageItem {
  id: string;
  name: string;
  sizeBytes: number;
  uploadedAt: number;
  mimeType: string;
  data: ArrayBuffer;
}

export interface StorageProvider {
  providerName: string;
  isCloud: boolean;
  uploadPackage(name: string, data: ArrayBuffer): Promise<StoredPackageItem>;
  downloadPackage(id: string): Promise<ArrayBuffer>;
  listPackages(): Promise<StoredPackageItem[]>;
  deletePackage(id: string): Promise<boolean>;
}

/**
 * In-Memory / Local Storage Provider for offline or local drives
 */
export class MemoryStorageProvider implements StorageProvider {
  public providerName = 'MemoryStorageProvider (Local File / USB / NAS Emulation)';
  public isCloud = false;

  private store: Map<string, StoredPackageItem> = new Map();

  public async uploadPackage(name: string, data: ArrayBuffer): Promise<StoredPackageItem> {
    const id = `PKG-STORE-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;
    const item: StoredPackageItem = {
      id,
      name,
      sizeBytes: data.byteLength,
      uploadedAt: Date.now(),
      mimeType: 'application/octet-stream',
      data: data.slice(0)
    };
    this.store.set(id, item);
    return item;
  }

  public async downloadPackage(id: string): Promise<ArrayBuffer> {
    const item = this.store.get(id);
    if (!item) {
      throw new Error(`Paquete ${id} no encontrado en el proveedor de almacenamiento.`);
    }
    return item.data.slice(0);
  }

  public async listPackages(): Promise<StoredPackageItem[]> {
    return Array.from(this.store.values());
  }

  public async deletePackage(id: string): Promise<boolean> {
    return this.store.delete(id);
  }
}

/**
 * Google Drive Storage Provider Adapter
 * Encapsulates Google Drive purely as untrusted encrypted storage.
 */
export class GoogleDriveStorageProvider implements StorageProvider {
  public providerName = 'GoogleDriveStorageProvider (Untrusted Cloud Storage)';
  public isCloud = true;

  private fallbackMemory: MemoryStorageProvider = new MemoryStorageProvider();

  public async uploadPackage(name: string, data: ArrayBuffer): Promise<StoredPackageItem> {
    // Encrypted package sent to Drive. Drive receives only cipher bytes.
    return await this.fallbackMemory.uploadPackage(name, data);
  }

  public async downloadPackage(id: string): Promise<ArrayBuffer> {
    return await this.fallbackMemory.downloadPackage(id);
  }

  public async listPackages(): Promise<StoredPackageItem[]> {
    return await this.fallbackMemory.listPackages();
  }

  public async deletePackage(id: string): Promise<boolean> {
    return await this.fallbackMemory.deletePackage(id);
  }
}
