/**
 * Hardware-attested anti-replay export sealing.
 * When USB HSM anti-replay is enabled in prefs, durable export payloads
 * are accompanied by a digest + soft-USB signature. Verification does not
 * replace AntiReplayRegistry in-memory checks — it attests exported snapshots.
 */

import { AntiReplayRegistry, type ConsumedOperationRecord } from '../core/replay/replay-cache.ts';
import { UsbHsmSigningBackend } from './usb-binding.ts';
import {
  loadSecurityDevicePrefs,
  type SecurityDevicePrefs,
} from '../lib/security-device-prefs.ts';

export interface SealedAntiReplaySnapshot {
  exportedAt: number;
  operations: ConsumedOperationRecord[];
  digest: string;
  signatureBase64: string | null;
  sealedBy: 'none' | 'usb-hsm-soft';
  developmentOnly: boolean;
}

export async function exportSealedAntiReplay(
  registry: AntiReplayRegistry,
  prefs: SecurityDevicePrefs = loadSecurityDevicePrefs()
): Promise<SealedAntiReplaySnapshot> {
  const operations = registry.exportConsumed();
  const payload = JSON.stringify({
    v: 1,
    operations: operations.map((o) => ({
      operationId: o.operationId,
      challenge: o.challenge,
      grantId: o.grantId,
      documentId: o.documentId,
      deviceId: o.deviceId,
      consumedAt: o.consumedAt,
    })),
  });

  if (prefs.hsmProvider === 'usb' && prefs.usbHsmAntiReplayEnabled) {
    const usb = new UsbHsmSigningBackend();
    const sealed = await usb.sealAntiReplayExport(payload);
    return {
      exportedAt: Date.now(),
      operations,
      digest: sealed.digest,
      signatureBase64: sealed.signatureBase64,
      sealedBy: 'usb-hsm-soft',
      developmentOnly: true,
    };
  }

  const digestBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
  const digest = [...new Uint8Array(digestBuf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return {
    exportedAt: Date.now(),
    operations,
    digest,
    signatureBase64: null,
    sealedBy: 'none',
    developmentOnly: true,
  };
}
