/**
 * Channel policy canonicalization and binding verification.
 *
 * Closes Family-D vectors (D1, D1b, D2):
 * - Policy is immutable once bound.
 * - Links can only be built from a verified PolicyBinding.
 * - Mutation of edges after binding is impossible because the Guardian
 *   never exposes a mutable edges map; it only holds the verified binding.
 */
import { KeyObject } from "node:crypto";
import type { ChannelPolicy, EdgeSpec, PolicyBinding } from "./types.js";
/** Deterministic canonical serialization of a ChannelPolicy. */
export declare function canonicalizePolicy(policy: ChannelPolicy): string;
export declare function policyHash(canonical: string): string;
/**
 * Verify a PolicyBinding against an Authority public key.
 * Returns the parsed ChannelPolicy if valid; throws otherwise.
 *
 * This is the sole entry point for materializing links — closes D1/D1b/D2.
 */
/** Validate ChannelPolicy shape and reject duplicate edges. */
export declare function validateChannelPolicy(policy: ChannelPolicy): void;
export declare function verifyPolicyBinding(binding: PolicyBinding, authorityPublicKey: KeyObject | string): ChannelPolicy;
/**
 * Helper used by the TDCP Authority (or tests) to produce a PolicyBinding.
 * The Guardian never calls this; it only verifies.
 */
export declare function signPolicyBinding(policy: ChannelPolicy, authorityPrivateKey: KeyObject, authorityKid: string): PolicyBinding;
/** Generate an ephemeral P-256 key pair for tests / local Authority stub. */
export declare function generateAuthorityKeyPair(): {
    publicKey: KeyObject;
    privateKey: KeyObject;
};
/** Convenience: edge key "source->destination". */
export declare function edgeKey(e: EdgeSpec): string;
//# sourceMappingURL=policy.d.ts.map