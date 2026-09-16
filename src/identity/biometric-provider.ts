/**
 * The Data Cryptographic Protocol (TDCP)
 * Biometric Provider Abstraction & Implementations
 *
 * NOTICE:
 * MockBiometricProvider is for DEMO / MOCK / DEVELOPMENT ONLY.
 * TDCP rule: Biometrics NEVER store raw fingerprint or face templates.
 * Biometrics only unlock/authenticate a credential through the OS platform authenticator.
 *
 * WebAuthnBiometricProvider MUST call navigator.credentials.get().
 * It MUST NOT return verified: true merely because the method was invoked.
 */

export interface BiometricVerificationResult {
  verified: boolean;
  biometricType: 'FINGERPRINT' | 'FACIAL_RECOGNITION' | 'PIN_UNLOCKED' | 'SIMULATED';
  timestamp: number;
  attestationChallenge?: string;
  stub?: boolean;
  detail?: string;
}

export interface BiometricProvider {
  providerName: string;
  isHardwareBacked: boolean;
  isAvailable(): Promise<boolean>;
  verifyPresence(prompt: string): Promise<BiometricVerificationResult>;
}

/**
 * [DEMO / MOCK / DEVELOPMENT ONLY]
 */
export class MockBiometricProvider implements BiometricProvider {
  public providerName = 'MockBiometricProvider (DEMO / MOCK / DEVELOPMENT ONLY)';
  public isHardwareBacked = false;

  private simulateSuccess: boolean = true;

  public setSimulateSuccess(success: boolean): void {
    this.simulateSuccess = success;
  }

  public async isAvailable(): Promise<boolean> {
    return true;
  }

  public async verifyPresence(_prompt: string): Promise<BiometricVerificationResult> {
    await new Promise((r) => setTimeout(r, 80));
    return {
      verified: this.simulateSuccess,
      biometricType: 'SIMULATED',
      timestamp: Date.now(),
      stub: true,
      detail: 'Simulated presence. Not a hardware biometric assertion.',
    };
  }
}

/**
 * WebAuthn platform authenticator. Calls navigator.credentials.get() with
 * userVerification: "required". Returns verified:true ONLY if the platform
 * actually returns a credential. Without an enrolled credential this fails
 * honestly rather than spoofing success.
 */
export class WebAuthnBiometricProvider implements BiometricProvider {
  public providerName = 'WebAuthnBiometricProvider (Windows Hello / TouchID / FaceID)';
  public isHardwareBacked = true;

  public async isAvailable(): Promise<boolean> {
    if (typeof window === 'undefined' || !window.PublicKeyCredential) return false;
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }
    return false;
  }

  public async verifyPresence(prompt: string): Promise<BiometricVerificationResult> {
    const available = await this.isAvailable();
    if (!available) {
      throw new Error('El autenticador biométrico de plataforma no está disponible.');
    }
    if (typeof navigator === 'undefined' || !navigator.credentials?.get) {
      throw new Error('navigator.credentials.get() no está disponible en este entorno.');
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    try {
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          timeout: 60_000,
          userVerification: 'required',
          rpId: typeof window !== 'undefined' ? window.location.hostname : undefined,
          allowCredentials: [],
        },
      });

      if (!assertion) {
        return {
          verified: false,
          biometricType: 'FINGERPRINT',
          timestamp: Date.now(),
          detail: 'WebAuthn returned no assertion. Presence not verified.',
        };
      }

      return {
        verified: true,
        biometricType: 'FINGERPRINT',
        timestamp: Date.now(),
        attestationChallenge: Array.from(challenge)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(''),
        detail: prompt,
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        verified: false,
        biometricType: 'FINGERPRINT',
        timestamp: Date.now(),
        detail: `WebAuthn get() failed: ${message}. No spoofed success.`,
      };
    }
  }
}
