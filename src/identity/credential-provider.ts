/**
 * The Data Cryptographic Protocol (TDCP)
 * Credential Provider Abstraction & Implementations
 * 
 * NOTICE:
 * MockNFCProvider is for DEMO / MOCK / DEVELOPMENT ONLY.
 * It is clearly separated from hardware-backed credentials.
 */

import type { UserCredential } from '../core/authorization/types.ts';
import { computeSHA256 } from '../core/crypto/primitives.ts';

export interface NFCProvider {
  providerName: string;
  isHardwareBacked: boolean;
  isAvailable(): Promise<boolean>;
  readCredential(): Promise<UserCredential>;
}

/**
 * [DEMO / MOCK / DEVELOPMENT ONLY]
 * Simulates an operator NFC Smart Card for development and automated test suites.
 */
export class MockNFCProvider implements NFCProvider {
  public providerName = 'MockNFCProvider (DEMO / MOCK / DEVELOPMENT ONLY)';
  public isHardwareBacked = false;

  private currentCredential: UserCredential = {
    credentialId: 'NFC-CARD-ALPHA-7791',
    holderName: 'Agente Operativo DCP-01',
    credentialType: 'NFC_CARD',
    assignedRole: 'SECURITY_OFFICER',
    isSimulated: true
  };

  public setSimulatedCredential(credential: Partial<UserCredential>): void {
    this.currentCredential = {
      ...this.currentCredential,
      ...credential
    };
  }

  public async isAvailable(): Promise<boolean> {
    return true;
  }

  public async readCredential(): Promise<UserCredential> {
    // Simulate card tap latency
    await new Promise(resolve => setTimeout(resolve, 80));
    return { ...this.currentCredential };
  }
}

/**
 * [PRODUCTION HARDWARE INTEGRATION STUB]
 * Web NFC API (NDEFReader) implementation for physical NFC cards / tokens.
 */
export class RealNFCProvider implements NFCProvider {
  public providerName = 'RealNFCProvider (Web NFC Hardware API)';
  public isHardwareBacked = true;

  public async isAvailable(): Promise<boolean> {
    return typeof window !== 'undefined' && 'NDEFReader' in window;
  }

  public async readCredential(): Promise<UserCredential> {
    if (!await this.isAvailable()) {
      throw new Error('Web NFC no está soportado en este navegador o sistema operativo. Utilice MockNFCProvider en entorno de pruebas.');
    }

    try {
      const NDEFReaderClass = (window as any).NDEFReader;
      const ndef = new NDEFReaderClass();
      await ndef.scan();
      return new Promise((resolve, reject) => {
        ndef.onreading = async (event: any) => {
          const serialNumber = event.serialNumber || 'NFC-HW-UNKNOWN';
          const cardHash = await computeSHA256(serialNumber);
          resolve({
            credentialId: `NFC-HW-${cardHash.substring(0, 12).toUpperCase()}`,
            holderName: 'Credencial Física Verificada',
            credentialType: 'NFC_CARD',
            assignedRole: 'OPERATOR',
            isSimulated: false
          });
        };
        ndef.onreadingerror = () => {
          reject(new Error('Fallo al leer la tarjeta NFC física'));
        };
      });
    } catch (err: any) {
      throw new Error(`Error de hardware NFC: ${err.message}`);
    }
  }
}
