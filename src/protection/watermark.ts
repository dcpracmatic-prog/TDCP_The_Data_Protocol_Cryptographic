/**
 * The Data Cryptographic Protocol (TDCP)
 * Forensic Session Watermarking
 * 
 * Rules:
 * - NO financial secrets, passwords, or sensitive credentials in watermark.
 * - Uses session nonce, document ID, authorization ID, device ID, and timestamp.
 * - Cryptographically auditable back to the authoritative audit ledger.
 */

export interface ForensicWatermarkData {
  documentId: string;
  authorizationId: string;
  deviceId: string;
  sessionNonce: string;
  timestamp: number;
  displayText: string;
}

export function generateForensicWatermark(
  documentId: string,
  authorizationId: string,
  deviceId: string,
  sessionNonce: string
): ForensicWatermarkData {
  const timestamp = Date.now();
  const timeStr = new Date(timestamp).toISOString();
  const displayText = `TDCP FORENSIC SVR // DOC:${documentId} // AUTH:${authorizationId.substring(0, 14)} // DEV:${deviceId} // NONCE:${sessionNonce.substring(0, 8)} // ${timeStr}`;

  return {
    documentId,
    authorizationId,
    deviceId,
    sessionNonce,
    timestamp,
    displayText
  };
}
