/**
 * Channel plane types — see channel-budget.ts (implemented).
 * packages/channel-guardian remains a Node reference package with parallel tests.
 */
export type {
  AuditEvent,
  ChannelPolicy,
  EdgeSpec,
  LinkState,
  PolicyBinding,
  SendResult,
} from './channel-budget.ts';

export {
  ChannelBudget,
  canonicalizePolicy,
  defaultOperationEdges,
  edgeKey,
  signPolicyBinding,
  validateChannelPolicy,
  verifyPolicyBinding,
} from './channel-budget.ts';

import type { PolicyBinding } from './channel-budget.ts';
import type { AuthorizationGrant } from '../core/authorization/types.ts';

/** Authority authorize response may include a signed channel binding for this grant. */
export interface GrantWithChannelBinding {
  grant: AuthorizationGrant;
  channelPolicyBinding?: PolicyBinding;
}
