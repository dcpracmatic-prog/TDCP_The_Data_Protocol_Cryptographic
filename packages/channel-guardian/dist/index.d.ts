/**
 * @tdcp/channel-guardian
 *
 * Channel Guardian for TDCP — egress protection with Authority-signed
 * policy binding.
 *
 * Role boundary (strict):
 * - Protects the communication channel between sensitive data and
 *   encryption/authorization processes.
 * - Does NOT issue grants, evaluate business policy, or hold wrap secrets.
 * - Policy bindings are produced by the TDCP Authority and verified here.
 *
 * Integration point: after Gatekeeper grants an operation, the Authority
 * (or a trusted control-plane step) issues a PolicyBinding. The application
 * materialises a ChannelGuardian.fromBinding(...) and routes all subsequent
 * data-plane frames through guardian.send(edge, frame, chunkIdx).
 *
 * See docs/INTEGRATION.md for the recommended wiring with TDCP.
 */
export type { AuditEvent, ChannelPolicy, EdgeSpec, LinkState, PolicyBinding, SendResult, } from "./types.js";
export { EgressLink } from "./egress-link.js";
export { canonicalizePolicy, edgeKey, generateAuthorityKeyPair, policyHash, signPolicyBinding, validateChannelPolicy, verifyPolicyBinding, } from "./policy.js";
export { ChannelGuardian } from "./guardian.js";
//# sourceMappingURL=index.d.ts.map