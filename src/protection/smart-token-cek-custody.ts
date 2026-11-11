/**
 * Smart Token como custodio de la CEK (P2-6).
 *
 * En el modo `smart-token` la CEK del documento NO se envuelve con el
 * secreto del Oracle: se entrega como un artefacto a Smart Token
 * (ML-KEM + AES-256-GCM en el servicio Smart-Token-Prod, bajo la
 * contraseña maestra que decide el emisor). El paquete TDCP solo guarda
 * la referencia al artefacto (`artifactId`); la CEK en claro nunca se
 * guarda en el paquete, nunca viaja a servidores externos fuera de la
 * llamada `open` al servicio Smart Token, y solo se reconstruye en
 * memoria del proceso que descifra, tras un grant válido del Gatekeeper.
 *
 * Reglas que este módulo NO cambia:
 * - El Gatekeeper sigue siendo el único camino de desbloqueo. Smart Token
 *   solo libera la CEK después de que el Gatekeeper validó y consumió un
 *   grant de un solo uso (revocación por épocas y anti-replay intactos).
 * - Sin grant válido, Smart Token no se contacta siquiera.
 * - Sin custodio configurado, sin master, con DENIED del servicio o con
 *   el servicio caído, la apertura FALLA CERRADA: nunca hay fallback al
 *   wrap del Oracle en este modo (no hay nada que desenvolver: el
 *   paquete en custodia no contiene CEK envuelta por el Oracle).
 * - La contraseña maestra la decide el emisor, se entrega por operación
 *   y TDCP nunca la guarda: ni en el paquete, ni en logs, ni en estado.
 *
 * El cliente HTTP real NO se reescribe aquí: `HttpSmartTokenCekCustodian`
 * es un adaptador fino sobre el `SmartTokenClient` existente
 * (`sdk/typescript/src/smart-token-client.ts`, fetch-only, master por
 * petición). No se inventa ningún endpoint: solo `POST /v1/artifacts`
 * (protect) y `POST /v1/artifacts/{id}/open` (open), el contrato que ya
 * habla ese cliente.
 *
 * El doble en memoria (`createInMemorySmartTokenCekCustodyFake`) es SOLO
 * PARA TESTS: guarda la CEK en memoria del proceso de test, sin cifrado
 * real. No es un sustituto del servicio y nunca debe usarse en producción.
 */

import {
  SmartTokenClient,
  smartTokenClientFromEnv,
} from '../../sdk/typescript/src/smart-token-client.ts';
import { generateRandomId, wipeBuffer } from '../core/crypto/primitives.ts';

/** Modo de custodia de la CEK. Default en toda la API: `'oracle'`. */
export type SmartTokenCekCustodyMode = 'oracle' | 'smart-token';

/**
 * Referencia de custodia que vive dentro del paquete TDCP. Solo un
 * identificador opaco: sin ella no se puede pedir la CEK, y con ella sola
 * tampoco (falta el grant del Gatekeeper + la contraseña maestra).
 */
export interface SmartTokenCekCustodyRef {
  artifactId: string;
  version: 1;
}

export type SmartTokenCekRelease =
  | { ok: true; cek: Uint8Array }
  | { ok: false; status: number };

/**
 * Superficie mínima que necesita la custodia. Tanto el adaptador HTTP
 * real como el doble de tests la implementan; la factoría y el Gatekeeper
 * solo conocen esta interfaz, nunca el servicio concreto.
 */
export interface SmartTokenCekCustodian {
  protectCek(cek: Uint8Array, masterSecret: string): Promise<{ artifactId: string }>;
  openCek(artifactId: string, masterSecret: string): Promise<SmartTokenCekRelease>;
}

/**
 * Adaptador fino sobre el SmartTokenClient existente. La CEK (32 bytes) se
 * protege como un archivo `cek.bin`; al abrir, el servicio devuelve los
 * 32 bytes en claro por HTTPS al proceso que descifra.
 */
export class HttpSmartTokenCekCustodian implements SmartTokenCekCustodian {
  private readonly client: SmartTokenClient;

  public constructor(client: SmartTokenClient) {
    this.client = client;
  }

  public async protectCek(
    cek: Uint8Array,
    masterSecret: string
  ): Promise<{ artifactId: string }> {
    if (cek.byteLength !== 32) {
      throw new Error('HttpSmartTokenCekCustodian.protectCek: la CEK debe tener 32 bytes');
    }
    if (!masterSecret) {
      throw new Error('HttpSmartTokenCekCustodian.protectCek: masterSecret es obligatorio');
    }
    const result = await this.client.protect(
      new Blob([cek.slice()], { type: 'application/octet-stream' }),
      masterSecret,
      'cek.bin'
    );
    if (!result.artifact_id) {
      throw new Error('HttpSmartTokenCekCustodian.protectCek: el servicio no devolvió artifact_id');
    }
    return { artifactId: result.artifact_id };
  }

  public async openCek(
    artifactId: string,
    masterSecret: string
  ): Promise<SmartTokenCekRelease> {
    if (!artifactId) {
      throw new Error('HttpSmartTokenCekCustodian.openCek: artifactId es obligatorio');
    }
    if (!masterSecret) {
      throw new Error('HttpSmartTokenCekCustodian.openCek: masterSecret es obligatorio');
    }
    const result = await this.client.open(artifactId, masterSecret);
    if (!result.ok) {
      return { ok: false, status: result.status };
    }
    return { ok: true, cek: new Uint8Array(result.plaintext) };
  }
}

/**
 * Custodio desde entorno. Reutiliza `SMART_TOKEN_API_URL` /
 * `SMART_TOKEN_API_KEY` (ya existen); NO se añade ninguna variable nueva.
 * La contraseña maestra NO se lee del entorno: se entrega por operación.
 * Devuelve null si el servicio no está configurado (URL o key vacías):
 * quien lo recibe debe fallar cerrado, nunca seguir sin custodio.
 */
export function smartTokenCekCustodianFromEnv(
  env: Record<string, string | undefined> = typeof process !== 'undefined' ? process.env : {}
): SmartTokenCekCustodian | null {
  if (!env.SMART_TOKEN_API_URL?.trim() || !env.SMART_TOKEN_API_KEY?.trim()) return null;
  const client = smartTokenClientFromEnv(env);
  if (!client) return null;
  return new HttpSmartTokenCekCustodian(client);
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as unknown as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export interface InMemorySmartTokenCekCustodyFake extends SmartTokenCekCustodian {
  /** Pone el servicio "caído": protect/open lanzan en vez de responder. */
  setDown(down: boolean): void;
  isDown(): boolean;
  /** Contadores para afirmar que sin grant no se contacta al custodio. */
  protects: number;
  opens: number;
}

/**
 * Doble en memoria SOLO PARA TESTS. Imita el contrato observable del
 * servicio real (artifact_id opaco, 403 DENIED con master incorrecto o
 * artefacto desconocido, excepción si está caído) pero guarda la CEK en
 * memoria sin cifrar. Del master solo guarda su SHA-256, nunca el valor.
 */
export function createInMemorySmartTokenCekCustodyFake(): InMemorySmartTokenCekCustodyFake {
  const store = new Map<string, { cek: Uint8Array; masterHash: string }>();
  let down = false;
  const fake: InMemorySmartTokenCekCustodyFake = {
    protects: 0,
    opens: 0,
    setDown(value: boolean): void {
      down = value;
    },
    isDown(): boolean {
      return down;
    },
    async protectCek(cek: Uint8Array, masterSecret: string): Promise<{ artifactId: string }> {
      if (down) throw new Error('SMART_TOKEN_FAKE_UNAVAILABLE: servicio Smart Token caído (doble de test)');
      if (cek.byteLength !== 32) {
        throw new Error('SmartTokenFake.protectCek: la CEK debe tener 32 bytes');
      }
      if (!masterSecret) {
        throw new Error('SmartTokenFake.protectCek: masterSecret es obligatorio');
      }
      const artifactId = generateRandomId('STK');
      store.set(artifactId, {
        cek: cek.slice(),
        masterHash: await sha256Hex(new TextEncoder().encode(masterSecret)),
      });
      fake.protects += 1;
      return { artifactId };
    },
    async openCek(artifactId: string, masterSecret: string): Promise<SmartTokenCekRelease> {
      fake.opens += 1;
      if (down) throw new Error('SMART_TOKEN_FAKE_UNAVAILABLE: servicio Smart Token caído (doble de test)');
      const entry = store.get(artifactId);
      if (!entry) return { ok: false, status: 403 };
      const masterHash = await sha256Hex(new TextEncoder().encode(masterSecret));
      if (masterHash !== entry.masterHash) return { ok: false, status: 403 };
      return { ok: true, cek: entry.cek.slice() };
    },
  };
  return fake;
}

/** Borra bytes sensibles en memoria (CEK liberada tras importarla). */
export function wipeCek(cek: Uint8Array | null | undefined): void {
  wipeBuffer(cek);
}
