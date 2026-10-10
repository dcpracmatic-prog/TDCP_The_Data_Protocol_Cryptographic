/**
 * Channel policy canonicalization and binding verification.
 *
 * Closes Family-D vectors (D1, D1b, D2):
 * - Policy is immutable once bound.
 * - Links can only be built from a verified PolicyBinding.
 * - Mutation of edges after binding is impossible because the Guardian
 *   never exposes a mutable edges map; it only holds the verified binding.
 */
import { createHash, createVerify, createSign, generateKeyPairSync, timingSafeEqual } from "node:crypto";
function safeEqualHex(a, b) {
    if (typeof a !== "string" || typeof b !== "string")
        return false
  jules/audit-report-and-code-quality-fixes-6928040402572855229
    const bufA = Buffer.from(a, "hex");
    const bufB = Buffer.from(b, "hex");
    if (bufA.length !== bufB.length)

    if (!/^[0-9a-fA-F]{64}$/.test(a) || !/^[0-9a-fA-F]{64}$/.test(b))
        return false;
    const bufA = Buffer.from(a, "hex");
    const bufB = Buffer.from(b, "hex");
    if (bufA.length !== 32 || bufB.length !== 32)
      main
        return false;
    return timingSafeEqual(bufA, bufB);
}
/** Deterministic canonical serialization of a ChannelPolicy. */
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
export function policyHash(canonical) {
    return createHash("sha256").update(canonical, "utf8").digest("hex");
}
/**
 * Verify a PolicyBinding against an Authority public key.
 * Returns the parsed ChannelPolicy if valid; throws otherwise.
 *
 * This is the sole entry point for materializing links — closes D1/D1b/D2.
 */
/** Validate ChannelPolicy shape and reject duplicate edges. */
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
    // Recompute hash
    const expectedHash = policyHash(binding.policyCanonical);
    if (!safeEqualHex(expectedHash, binding.policyHash)) {
        throw new Error("policy_binding_rejected: hash mismatch");
    }
    // Verify signature (ECDSA P-256 / SHA-256 — matches TDCP grant curve)
    const key = typeof authorityPublicKey === "string"
        ? authorityPublicKey
        : authorityPublicKey;
    const verifier = createVerify("SHA256");
    verifier.update(binding.policyCanonical);
    verifier.end();
    const ok = verifier.verify(key, binding.signature, "base64");
    if (!ok) {
        throw new Error("policy_binding_rejected: invalid signature");
    }
    let policy;
    try {
        policy = JSON.parse(binding.policyCanonical);
    }
    catch {
        throw new Error("policy_binding_rejected: canonical JSON parse failed");
    }
    validateChannelPolicy(policy);
    if (policy.expiry < now) {
        throw new Error("policy_binding_rejected: expired");
    }
    return policy;
}
/**
 * Helper used by the TDCP Authority (or tests) to produce a PolicyBinding.
 * The Guardian never calls this; it only verifies.
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
/** Generate an ephemeral P-256 key pair for tests / local Authority stub. */
export function generateAuthorityKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync("ec", {
        namedCurve: "P-256",
    });
    return { publicKey, privateKey };
}
/** Convenience: edge key "source->destination". */
export function edgeKey(e) {
    return `${e.source}->${e.destination}`;
}
