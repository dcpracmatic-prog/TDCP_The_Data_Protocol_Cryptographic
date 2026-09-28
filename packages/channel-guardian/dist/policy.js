/**
 * Channel policy canonicalization and binding verification.
 * Closes Family-D vectors (D1, D1b, D2).
 */
import { createHash, createVerify, createSign, generateKeyPairSync } from "node:crypto";

/** @param {import('../src/types.ts').ChannelPolicy} policy */
export function canonicalizePolicy(policy) {
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

/** @param {string} canonical */
export function policyHash(canonical) {
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

/**
 * @param {import('../src/types.ts').PolicyBinding} binding
 * @param {import('node:crypto').KeyObject | string} authorityPublicKey
 */

export function validateChannelPolicy(policy) {
    if (!policy || typeof policy !== "object") {
        throw new Error("policy_binding_rejected: invalid policy object");
    }
    if (typeof policy.documentId !== "string" || policy.documentId.length === 0) {
        throw new Error("policy_binding_rejected: documentId required");
    }
    if (typeof policy.grantId !== "string" || policy.grantId.length === 0) {
        throw new Error("policy_binding_rejected: grantId required");
    }
    if (typeof policy.expiry !== "number" || !Number.isFinite(policy.expiry)) {
        throw new Error("policy_binding_rejected: expiry must be a finite number");
    }
    if (!Array.isArray(policy.edges) || policy.edges.length === 0) {
        throw new Error("policy_binding_rejected: empty edges");
    }
    const seen = new Set();
    for (const e of policy.edges) {
        if (!e || typeof e.source !== "string" || typeof e.destination !== "string") {
            throw new Error("policy_binding_rejected: edge source/destination required");
        }
        if (typeof e.expectedBytes !== "number" || e.expectedBytes < 0 || !Number.isFinite(e.expectedBytes)) {
            throw new Error("policy_binding_rejected: expectedBytes must be a non-negative finite number");
        }
        if (typeof e.allowed !== "boolean") {
            throw new Error("policy_binding_rejected: allowed must be boolean");
        }
        const k = edgeKey(e);
        if (seen.has(k)) {
            throw new Error(`policy_binding_rejected: duplicate edge ${k}`);
        }
        seen.add(k);
    }
}

export function verifyPolicyBinding(binding, authorityPublicKey) {
  const now = Date.now();
  const expectedHash = policyHash(binding.policyCanonical);
  if (expectedHash !== binding.policyHash) {
    throw new Error("policy_binding_rejected: hash mismatch");
  }

  const verifier = createVerify("SHA256");
  verifier.update(binding.policyCanonical);
  verifier.end();
  const ok = verifier.verify(authorityPublicKey, binding.signature, "base64");
  if (!ok) {
    throw new Error("policy_binding_rejected: invalid signature");
  }

  let policy;
  try {
    policy = JSON.parse(binding.policyCanonical);
  } catch {
    throw new Error("policy_binding_rejected: canonical JSON parse failed");
  }
  validateChannelPolicy(policy);
  if (policy.expiry < now) {
    throw new Error("policy_binding_rejected: expired");
  }
  return policy;
}

/**
 * @param {import('../src/types.ts').ChannelPolicy} policy
 * @param {import('node:crypto').KeyObject} authorityPrivateKey
 * @param {string} authorityKid
 */
export function signPolicyBinding(policy, authorityPrivateKey, authorityKid) {
  validateChannelPolicy(policy);
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

export function generateAuthorityKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  return { publicKey, privateKey };
}

/** @param {{ source: string, destination: string }} e */
export function edgeKey(e) {
  return `${e.source}->${e.destination}`;
}
