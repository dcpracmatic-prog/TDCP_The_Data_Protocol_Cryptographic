/**
 * Software USB-HSM authenticator used only by Authority integration tests.
 *
 * This is intentionally a test authenticator, not a production HSM. It emits
 * real WebAuthn registration/authentication structures so the Authority tests
 * exercise the same verification path used by physical security keys.
 */
 
type SoftUsbHsmOptions = {
  origin?: string;
  rpId?: string;
  synced?: boolean;
  transports?: string[];
  userVerification?: boolean;
  aaguid?: string;
};

type SignOptions = {
  counter?: number;
};

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {\n  const copy = new Uint8Array(bytes.byteLength);\n  copy.set(bytes);\n  return copy.buffer;\n}\n\nfunction utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function uintBE(value: number, bytes: number): Uint8Array {
  const out = new Uint8Array(bytes);
  let n = Math.max(0, Math.floor(value));
  for (let i = bytes - 1; i >= 0; i -= 1) {
    out[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return out;
}

function parseAaguid(value: string): Uint8Array {
  const hex = value.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
    throw new Error("Invalid AAGUID");
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Minimal deterministic CBOR encoder for the WebAuthn maps used here. */
function cborHead(major: number, length: number): Uint8Array {
  if (length < 24) return new Uint8Array([(major << 5) | length]);
  if (length < 0x100) return new Uint8Array([(major << 5) | 24, length]);
  if (length < 0x10000) return new Uint8Array([
    (major << 5) | 25,
    (length >>> 8) & 0xff,
    length & 0xff,
  ]);
  if (length < 0x100000000) return new Uint8Array([
    (major << 5) | 26,
    (length >>> 24) & 0xff,
    (length >>> 16) & 0xff,
    (length >>> 8) & 0xff,
    length & 0xff,
  ]);
  throw new Error("CBOR length too large");
}

function cborEncode(value: unknown): Uint8Array {
  if (typeof value === "number" && Number.isInteger(value)) {
    if (value >= 0) {
      return cborHead(0, value);
    }
    return cborHead(1, -1 - value);
  }
  if (typeof value === "string") {
    const bytes = utf8(value);
    return concat(cborHead(3, bytes.byteLength), bytes);
  }
  if (value instanceof Uint8Array) {
    return concat(cborHead(2, value.byteLength), value);
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const entries = Object.entries(value as Record<string, unknown>);
    const parts: Uint8Array[] = [cborHead(5, entries.length)];
    for (const [key, nested] of entries) {
      const numericKey = /^-?\d+$/.test(key) ? Number(key) : key;
      parts.push(cborEncode(numericKey), cborEncode(nested));
    }
    return concat(...parts);
  }
  throw new Error("Unsupported CBOR value");
}

function clientData(
  type: "webauthn.create" | "webauthn.get",
  challenge: string,
  origin: string,
): Uint8Array {
  return utf8(
    JSON.stringify({
      type,
      challenge,
      origin,
      crossOrigin: false,
    }),
  );
}

export class SoftUsbHsm {
  public id = "";
  public readonly origin: string;
  public readonly rpId: string;
  public readonly synced: boolean;
  public readonly transports: string[];
  public readonly userVerification: boolean;
  public readonly aaguid: string;

  private privateKey: CryptoKey | null = null;
  private publicKey: CryptoKey | null = null;
  private credentialId = new Uint8Array();
  private counterValue = 0;

  constructor(options: SoftUsbHsmOptions = {}) {
    this.origin = options.origin ?? "http://localhost:8080";
    this.rpId = options.rpId ?? "localhost";
    this.synced = options.synced === true;
    this.transports = [...(options.transports ?? ["usb"])];
    this.userVerification = options.userVerification !== false;
    this.aaguid =
      options.aaguid ?? "00000000-0000-0000-0000-000000000000";
  }

  private async ensureKeyPair(): Promise<void> {
    if (this.privateKey && this.publicKey) return;
    const pair = (await crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
  }

  private async rpIdHash(): Promise<Uint8Array> {
    return new Uint8Array(
      await crypto.subtle.digest("SHA-256", asArrayBuffer(utf8(this.rpId))),
    );
  }

  private registrationFlags(): number {
    let flags = 0x01; // UP
    if (this.userVerification) flags |= 0x04; // UV
    if (this.synced) flags |= 0x18; // BE + BS
    flags |= 0x40; // AT
    return flags;
  }

  private authenticationFlags(): number {
    let flags = 0x01; // UP
    if (this.userVerification) flags |= 0x04; // UV
    return flags;
  }

  private async authenticatorDataForRegistration(): Promise<Uint8Array> {
    await this.ensureKeyPair();
    if (!this.publicKey) throw new Error("public key unavailable");

    const publicRaw = new Uint8Array(
      await crypto.subtle.exportKey("raw", this.publicKey),
    );

    // COSE_Key for Ed25519:
    // 1 = OKP, 3 = EdDSA (-8), -1 = Ed25519 (6), -2 = x.
    const coseKey = cborEncode({
      "1": 1,
      "3": -8,
      "-1": 6,
      "-2": publicRaw,
    });

    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    this.credentialId = credentialId;
    this.id = base64Url(credentialId);

    return concat(
      await this.rpIdHash(),
      new Uint8Array([this.registrationFlags()]),
      uintBE(0, 4),
      parseAaguid(this.aaguid),
      uintBE(credentialId.byteLength, 2),
      credentialId,
      coseKey,
    );
  }

  /**
   * Simulate navigator.credentials.create() / startRegistration().
   */
  public async register(options: { challenge: string }): Promise<unknown> {
    const authData = await this.authenticatorDataForRegistration();
    const clientDataJSON = clientData(
      "webauthn.create",
      options.challenge,
      this.origin,
    );

    const attestationObject = cborEncode({
      fmt: "none",
      attStmt: {},
      authData,
    });

    return {
      id: this.id,
      rawId: this.id,
      response: {
        clientDataJSON: base64Url(clientDataJSON),
        attestationObject: base64Url(attestationObject),
        transports: this.transports,
      },
      type: "public-key",
      clientExtensionResults: {},
      authenticatorAttachment: "cross-platform",
    };
  }

  /**
   * Simulate navigator.credentials.get() / startAuthentication().
   */
  public async sign(challenge: string, options: SignOptions = {}): Promise<unknown> {
    if (!this.privateKey || !this.id) {
      throw new Error("USB-HSM is not registered");
    }

    const counter =
      options.counter !== undefined
        ? Math.max(0, Math.floor(options.counter))
        : this.counterValue + 1;

    this.counterValue = counter;

    const clientDataJSON = clientData(
      "webauthn.get",
      challenge,
      this.origin,
    );
    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", asArrayBuffer(clientDataJSON)),
    );
    const authenticatorData = concat(
      await this.rpIdHash(),
      new Uint8Array([this.authenticationFlags()]),
      uintBE(counter, 4),
    );
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "Ed25519" },
        this.privateKey,
        asArrayBuffer(concat(authenticatorData, clientDataHash)),
      ),
    );

    return {
      id: this.id,
      rawId: this.id,
      response: {
        clientDataJSON: base64Url(clientDataJSON),
        authenticatorData: base64Url(authenticatorData),
        signature: base64Url(signature),
      },
      type: "public-key",
      clientExtensionResults: {},
      authenticatorAttachment: "cross-platform",
    };
  }
}
