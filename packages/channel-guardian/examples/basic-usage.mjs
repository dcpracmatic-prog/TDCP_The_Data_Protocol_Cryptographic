/**
 * Minimal example: Authority signs a channel policy; Guardian enforces it.
 * Run from package root after `npm run build`:
 *   node examples/basic-usage.mjs
 */

import {
  ChannelGuardian,
  generateAuthorityKeyPair,
  signPolicyBinding,
} from "../dist/index.js";

const { publicKey, privateKey } = generateAuthorityKeyPair();

const policy = {
  documentId: "doc-001",
  grantId: "grant-abc",
  expiry: Date.now() + 60_000,
  edges: [
    { source: "A", destination: "B", expectedBytes: 2048, allowed: true },
    { source: "B", destination: "C", expectedBytes: 2048, allowed: true },
    { source: "C", destination: "D", expectedBytes: 2048, allowed: true },
    { source: "B", destination: "X", expectedBytes: 0, allowed: false },
  ],
};

const binding = signPolicyBinding(policy, privateKey, "authority-kid-1");
const guardian = ChannelGuardian.fromBinding(binding, publicKey);

const frame = Buffer.from("hello-sensitive-payload");

// Allowed path
const r1 = guardian.send("A->B", frame, 0);
console.log("A->B accepted:", r1.accepted);

// Forbidden edge — blocked and quarantined
const r2 = guardian.send("B->X", frame, 1);
console.log("B->X accepted:", r2.accepted);

// Retry after quarantine — still blocked
const r3 = guardian.send("B->X", frame, 2);
console.log("B->X retry accepted:", r3.accepted);

console.log("Blocked traffic:", guardian.hasBlockedTraffic());
console.log("Audit events:", guardian.auditEvents().length);
console.log("Delivered snapshot:", guardian.deliveredSnapshot());
