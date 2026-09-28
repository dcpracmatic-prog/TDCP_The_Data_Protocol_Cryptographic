/**
 * TDCP ↔ Channel Guardian contract (optional additive plane).
 *
 * Re-exports the binding shape expected after a Gatekeeper grant.
 * Full runtime lives in packages/channel-guardian (@tdcp/channel-guardian).
 *
 * Authority should sign ChannelPolicy with the same key family used for grants
 * (ECDSA P-256 in the reference design) and return PolicyBinding alongside grant material.
 */

export type {
  AuditEvent,
  ChannelPolicy,
  EdgeSpec,
  LinkState,
  PolicyBinding,
  SendResult,
} from '../../packages/channel-guardian/src/types.ts';

/**
 * Suggested Authority response extension (conceptual — wire when remote Authority
 * supports channel policy issuance).
 */
export interface GrantWithChannelBinding {
  grantId: string;
  documentId: string;
  expiresAt: number;
  /** Optional. Present when the operation includes a signed channel policy. */
  channelPolicyBinding?: import('../../packages/channel-guardian/src/types.ts').PolicyBinding;
}
