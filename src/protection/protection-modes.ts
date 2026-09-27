/**
 * Optional protection planes beyond core TDCP AES + Gatekeeper.
 * Users may combine planes; none bypasses Gatekeeper for TDCP packages.
 */

export type ProtectionModeId =
  | 'tdcp'
  | 'tdcp_csg'
  | 'smart_token'
  | 'smart_token_csg'
  | 'csg_only';

export interface ProtectionModeOption {
  id: ProtectionModeId;
  label: string;
  short: string;
  description: string;
  encrypts: boolean;
  usesTdcp: boolean;
  usesSmartToken: boolean;
  usesCsg: boolean;
}

export const PROTECTION_MODES: ProtectionModeOption[] = [
  {
    id: 'tdcp',
    label: 'TDCP (AES + Gatekeeper)',
    short: 'TDCP',
    description:
      'Cifrado AES-256-GCM del protocolo actual. Apertura solo vía Gatekeeper + Authority. Copia ≠ autorización.',
    encrypts: true,
    usesTdcp: true,
    usesSmartToken: false,
    usesCsg: false,
  },
  {
    id: 'tdcp_csg',
    label: 'TDCP + sello CSG',
    short: 'TDCP+CSG',
    description:
      'Paquete TDCP cifrado y sello de integridad CSG sobre el sobre. Detecta manipulación del ciphertext.',
    encrypts: true,
    usesTdcp: true,
    usesSmartToken: false,
    usesCsg: true,
  },
  {
    id: 'smart_token',
    label: 'Smart Token',
    short: 'STP',
    description:
      'Protección larga duración (API Smart Token o soft-local demo). Master solo por operación; no es grant TDCP.',
    encrypts: true,
    usesTdcp: false,
    usesSmartToken: true,
    usesCsg: false,
  },
  {
    id: 'smart_token_csg',
    label: 'Smart Token + CSG',
    short: 'STP+CSG',
    description:
      'Artifact Smart Token más sello CSG de integridad sobre el identificador y el ciphertext.',
    encrypts: true,
    usesTdcp: false,
    usesSmartToken: true,
    usesCsg: true,
  },
  {
    id: 'csg_only',
    label: 'Solo CSG (integridad)',
    short: 'CSG',
    description:
      'Sin cifrado: adjunta un sello de integridad técnica al archivo. Útil para auditoría de no-manipulación.',
    encrypts: false,
    usesTdcp: false,
    usesSmartToken: false,
    usesCsg: true,
  },
];

export function getProtectionMode(id: ProtectionModeId): ProtectionModeOption {
  return PROTECTION_MODES.find((m) => m.id === id) ?? PROTECTION_MODES[0]!;
}
