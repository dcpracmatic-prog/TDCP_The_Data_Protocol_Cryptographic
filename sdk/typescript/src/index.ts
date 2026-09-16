/**
 * @tdcp/sdk — minimal integrator surface.
 * Unlock only via Gatekeeper. See docs/INTEGRATOR_API.md.
 */

export type {
  TDCPRequestedOperation,
  AuthorizationGrant,
  AuthorizationRequest,
  PolicyLevel,
} from '../../../src/core/authorization/types.ts';

export type { TDCPPackage } from '../../../src/core/package/package-format.ts';

export {
  DCPGatekeeper,
  type GatekeeperUnlockOptions,
  type GatekeeperUnlockResult,
} from '../../../src/gatekeeper/gatekeeper.ts';

export type { AuthorizationAuthority } from '../../../src/authority/types.ts';
export {
  InProcessAuthority,
  HttpAuthorityClient,
  resolveAuthorizationAuthority,
  readAuthorityUrlFromEnv,
} from '../../../src/authority/index.ts';

import { DCPGatekeeper, type GatekeeperUnlockOptions, type GatekeeperUnlockResult } from '../../../src/gatekeeper/gatekeeper.ts';

/** Thin alias: integrators call this instead of reaching into AES primitives. */
export async function unlockViaGatekeeper(
  options: GatekeeperUnlockOptions
): Promise<GatekeeperUnlockResult> {
  return DCPGatekeeper.executeUnlock(options);
}
