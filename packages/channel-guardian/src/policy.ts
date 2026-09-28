/**
 * Channel policy canonicalization and binding verification.
 *
 * Closes Family-D vectors (D1, D1b, D2):
 * - Policy is immutable once bound.
 * - Links can only be built from a verified PolicyBinding.
 * - Mutation of edges after binding is impossible because the Guardian
 *   never exposes a mutable edges map; it only holds the verified binding.
 */

import { createHash, createVerify, createSign, generateKeyPairSync, KeyObject } from "node:crypto";
import type { ChannelPolicy, EdgeSpec, PolicyBinding } from "./types.js";

/** Deterministic canonical serialization of a ChannelPolicy. */
export function canonicalizePolicy(policy: ChannelPolicy): string {
  const edges = [...policy.edges]
    .map((e) => ({
      source: e.source,
      destination: e.destination,
      expectedBytes: e.expectedBytes,
      allowed: e.allowed,
    }))
    .sort((a, b) => {
      const ka = `${a.source}->${a.destination}`;
      const kb = `${b.source}->${b.destination}`;
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });

  return JSON.stringify({
    documentId: policy.documentId,
    grantId: policy.grantId,
    expiry: policy.expiry,
    edges,
  });
}

export function policyHash(canonical: string): string {
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

/**
 * Verify a PolicyBinding against an Authority public key.
 * Returns the parsed ChannelPolicy if valid; throws otherwise.
 *
 * This is the sole entry point for materializing links — closes D1/D1b/D2.
 */
export function verifyPolicyBinding(
  binding: PolicyBinding,
  authorityPublicKey: KeyObject | string,
): ChannelPolicy {
  const now = Date.now();

  // Recompute hash
  const expectedHash = policyHash(binding.policyCanonical);
  if (expectedHash !== binding.policyHash) {
    throw new Error("policy_binding_rejected: hash mismatch");
  }

  // Verify signature (ECDSA P-256 / SHA-256 — matches TDCP grant curve)
  const key =
    typeof authorityPublicKey === "string"
      ? authorityPublicKey
      : authorityPublicKey;
  const verifier = createVerify("SHA256");
  verifier.update(binding.policyCanonical);
  verifier.end();
  const ok = verifier.verify(key, binding.signature, "base64");
  if (!ok) {
    throw new Error("policy_binding_rejected: invalid signature");
  }

  const policy = JSON.parse(binding.policyCanonical) as ChannelPolicy;

  if (typeof policy.expiry !== "number" || policy.expiry < now) {
    throw new Error("policy_binding_rejected: expired");
  }

  if (!Array.isArray(policy.edges) || policy.edges.length === 0) {
    throw new Error("policy_binding_rejected: empty edges");
  }

  return policy;
}

/**
 * Helper used by the TDCP Authority (or tests) to produce a PolicyBinding.
 * The Guardian never calls this; it only verifies.
 */
export function signPolicyBinding(
  policy: ChannelPolicy,
  authorityPrivateKey: KeyObject,
  authorityKid: string,
): PolicyBinding {
  const policyCanonical = canonicalizePolicy(policy);
  const hash = policyHash(policyCanonical);
  const signer = createSign("SHA256");
  signer.update(policyCanonical);
  signer.end();
  const signature = signer.sign(authorityPrivateKey, "base64");

  return {
    policyCanonical,
    policyHash: hash,
    signature,
    authorityKid,
    issuedAt: Date.now(),
  };
}

/** Generate an ephemeral P-256 key pair for tests / local Authority stub. */
export function generateAuthorityKeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  return { publicKey, privateKey };
}

/** Convenience: edge key "source->destination". */
export function edgeKey(e: EdgeSpec): string {
  return `${e.source}->${e.destination}`;
}
