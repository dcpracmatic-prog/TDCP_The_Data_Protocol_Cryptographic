# ATL Edge bridge (design note only)

**Status:** Design only. This repository does **not** implement ATL Edge (or any agent runtime).

Product constraint: agents unlock TDCP packages **only via Gatekeeper**, never by holding long-lived content keys.

## Goal

Allow agent / edge runtimes (e.g. ATL Edge) to perform operation-scoped work on TDCP packages without becoming a second control plane.

## Trust model

| Actor | May hold | Must not hold |
|-------|----------|----------------|
| Authorization Authority | Signing keys, wrap secrets, revoke/replay | Plaintext, CEK |
| Gatekeeper (in agent host) | Ephemeral session material for one operation | Long-lived content keys across tasks |
| Agent / tool code | Operation result under policy (READ/RENDER/EXTRACT) | Durable CEK, wrap secret, Authority private key |
| Package store | Ciphertext `.pkg` | Authorization |

Invariant: **copying ciphertext ≠ authorization.** An agent with blob access still needs a fresh one-time grant for a named operation.

## Grant scope for agents

1. Agent requests unlock through Gatekeeper with `requestedOperation` (`READ` / `RENDER_RAM` / `EXTRACT` / …).
2. Gatekeeper obtains challenge + grant from Authority (remote in production).
3. Wrap secret released once; CEK unwrapped ephemerally; session registers buffers for apoptosis/wipe.
4. Agent consumes result within session TTL; no export of raw CEK to tool memory stores.

## Revoke implications

- Authority revoke / epoch rotation invalidates new grants immediately.
- In-flight sessions should fail subsequent Gatekeeper calls; agents must not cache grants or wrap secrets beyond the Gatekeeper session.
- View-Once and one-time grants remain Authority-owned; agents cannot “refresh” without a new challenge.

## Non-goals (this note)

- Implementing ATL Edge SDK bindings here
- Letting agents call Authority wrap-secret APIs bypassing Gatekeeper
- Claiming agent sandbox = HSM

Link from `PRODUCT.md` / `ROADMAP.md` P3.
