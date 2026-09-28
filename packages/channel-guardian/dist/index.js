/**
 * @tdcp/channel-guardian
 * Channel Guardian for TDCP — egress protection with Authority-signed policy binding.
 */
export { EgressLink } from "./egress-link.js";
export {
  canonicalizePolicy,
  edgeKey,
  generateAuthorityKeyPair,
  policyHash,
  signPolicyBinding,
  validateChannelPolicy,
  verifyPolicyBinding,
} from "./policy.js";
export { ChannelGuardian } from "./guardian.js";
