/**
 * Self-contained tests (Node built-in test runner).
 * Run: npm run build && node --test test/guardian.test.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ChannelGuardian,
  generateAuthorityKeyPair,
  signPolicyBinding,
  verifyPolicyBinding,
  canonicalizePolicy,
  policyHash,
} from "../dist/index.js";

function makePolicy(overrides = {}) {
  return {
    documentId: "doc-test",
    grantId: "grant-test",
    expiry: Date.now() + 120_000,
    edges: [
      { source: "A", destination: "B", expectedBytes: 100, allowed: true },
      { source: "B", destination: "C", expectedBytes: 100, allowed: true },
      { source: "C", destination: "D", expectedBytes: 100, allowed: true },
      { source: "B", destination: "X", expectedBytes: 0, allowed: false },
    ],
    ...overrides,
  };
}

describe("PolicyBinding", () => {
  it("round-trips sign and verify", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const policy = makePolicy();
    const binding = signPolicyBinding(policy, privateKey, "kid-1");
    const verified = verifyPolicyBinding(binding, publicKey);
    assert.equal(verified.documentId, policy.documentId);
    assert.equal(verified.grantId, policy.grantId);
    assert.equal(verified.edges.length, 4);
  });

  it("rejects tampered canonical payload (D1-class)", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const binding = signPolicyBinding(makePolicy(), privateKey, "kid-1");
    // Mutate the canonical string after signing
    const tampered = {
      ...binding,
      policyCanonical: binding.policyCanonical.replace('"allowed":false', '"allowed":true'),
    };
    assert.throws(() => verifyPolicyBinding(tampered, publicKey));
  });

  it("rejects expired binding", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const policy = makePolicy({ expiry: Date.now() - 1000 });
    const binding = signPolicyBinding(policy, privateKey, "kid-1");
    assert.throws(() => verifyPolicyBinding(binding, publicKey));
  });
});

describe("ChannelGuardian", () => {
  it("allows traffic on authorized edges within budget", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const binding = signPolicyBinding(makePolicy(), privateKey, "kid-1");
    const g = ChannelGuardian.fromBinding(binding, publicKey);
    const frame = Buffer.alloc(50, 0xab);
    const r = g.send("A->B", frame, 0);
    assert.equal(r.accepted, true);
    assert.equal(g.getLink("A->B").deliveredBytes, 50);
  });

  it("blocks and quarantines forbidden edges (A-family)", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const binding = signPolicyBinding(makePolicy(), privateKey, "kid-1");
    const g = ChannelGuardian.fromBinding(binding, publicKey);
    const secret = Buffer.from("CREDENCIALES:usuario=admin;token=SECRET");
    const r = g.send("B->X", secret, 0);
    assert.equal(r.accepted, false);
    assert.equal(g.getLink("B->X").state, "QUARANTINED");
    // Retry still blocked
    const r2 = g.send("B->X", secret, 1);
    assert.equal(r2.accepted, false);
    assert.equal(g.getLink("B->X").deliveredBytes, 0);
  });

  it("blocks over-budget traffic", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const binding = signPolicyBinding(makePolicy(), privateKey, "kid-1");
    const g = ChannelGuardian.fromBinding(binding, publicKey);
    const big = Buffer.alloc(150, 0xcd);
    const r = g.send("A->B", big, 0);
    assert.equal(r.accepted, false);
    assert.equal(g.getLink("A->B").state, "QUARANTINED");
  });

  it("rejects edges not present in the binding (D2-class)", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const binding = signPolicyBinding(makePolicy(), privateKey, "kid-1");
    const g = ChannelGuardian.fromBinding(binding, publicKey);
    const r = g.send("Z->EVIL", Buffer.from("x"), 0);
    assert.equal(r.accepted, false);
    assert.ok(g.hasBlockedTraffic());
  });

  it("does not expose a mutable edges map", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const binding = signPolicyBinding(makePolicy(), privateKey, "kid-1");
    const g = ChannelGuardian.fromBinding(binding, publicKey);
    // No public setter for edges; edgeKeys is a snapshot
    assert.ok(Array.isArray(g.edgeKeys()));
    assert.equal(typeof g.edgeKeys, "function");
  });
});

describe("Canonicalization", () => {
  it("is order-independent for edges", () => {
    const a = makePolicy({
      edges: [
        { source: "B", destination: "C", expectedBytes: 10, allowed: true },
        { source: "A", destination: "B", expectedBytes: 10, allowed: true },
      ],
    });
    const b = makePolicy({
      edges: [
        { source: "A", destination: "B", expectedBytes: 10, allowed: true },
        { source: "B", destination: "C", expectedBytes: 10, allowed: true },
      ],
    });
    assert.equal(canonicalizePolicy(a), canonicalizePolicy(b));
    assert.equal(policyHash(canonicalizePolicy(a)), policyHash(canonicalizePolicy(b)));
  });
});

describe("Schema and lifecycle hardening", () => {
  it("rejects duplicate edges at sign/verify", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const policy = makePolicy({
      edges: [
        { source: "A", destination: "B", expectedBytes: 10, allowed: true },
        { source: "A", destination: "B", expectedBytes: 20, allowed: true },
      ],
    });
    assert.throws(() => signPolicyBinding(policy, privateKey, "kid"), /duplicate edge/);
  });

  it("rejects invalid schema (missing grantId)", () => {
    const { privateKey } = generateAuthorityKeyPair();
    const policy = makePolicy({ grantId: "" });
    assert.throws(() => signPolicyBinding(policy, privateKey, "kid"), /grantId/);
  });

  it("rejects send after expiry", () => {
    const { publicKey, privateKey } = generateAuthorityKeyPair();
    const policy = makePolicy({ expiry: Date.now() + 30 });
    const binding = signPolicyBinding(policy, privateKey, "kid");
    const g = ChannelGuardian.fromBinding(binding, publicKey);
    // Force expiry by waiting — use a policy already near-expired via reflection
    // Instead: construct binding with expiry in the past is blocked at fromBinding;
    // for send-path, use short expiry and mock time is hard — call with expired
    // by rebuilding: sign with future, then we need internal clock.
    // Practical test: sign with expiry = now+5ms, busy-wait, then send.
    const policy2 = makePolicy({ expiry: Date.now() + 5 });
    const binding2 = signPolicyBinding(policy2, privateKey, "kid");
    const g2 = ChannelGuardian.fromBinding(binding2, publicKey);
    const start = Date.now();
    while (Date.now() - start < 15) { /* spin */ }
    const r = g2.send("A->B", Buffer.from("x"), 0);
    assert.equal(r.accepted, false);
    assert.ok(g2.auditEvents().some((e) => e.reason === "binding_expired_at_send"));
  });
});
