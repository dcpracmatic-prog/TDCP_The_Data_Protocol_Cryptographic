# Threat model — Channel Guardian

## Assets protected

- Byte budgets on authorized edges.
- Prevention of egress on non-authorized edges during an authorized TDCP operation.

## Assets NOT protected by this component

- Content integrity (handled by TDCP envelope AES-GCM AAD + optional CSG Sello).
- Authorization decisions (handled by TDCP Authority / Gatekeeper).
- Long-lived secrets (wrap keys, CSG damage master, Smart Token master).

## Adversary capabilities considered

| Vector family | Mitigated by |
|---------------|--------------|
| A – Classic exfil on forbidden edges (B→X, unknown) | Edge allow-list + quarantine |
| B – Content tampering on allowed path | Out of scope (Sello / envelope) |
| C – Budget slack / low-and-slow on forbidden edges | Byte budget + quarantine |
| D – Policy mutation / link mismatch | Authority-signed PolicyBinding |
| E – Collusion rewriting content | Out of scope (Sello); quarantine reuse handled |

## Trust assumptions

1. The Authority public key used in `fromBinding` is authentic (distributed out-of-band or via TDCP’s existing key distribution).
2. The process that holds the Guardian instance is the same process that received the grant (no cross-process link injection without a fresh binding).
3. Clock skew for `expiry` is bounded by the same operational assumptions as TDCP challenge expiry (60 s class).

## Non-goals

- Replacing Gatekeeper.
- Detecting steganography or content mutation on allowed edges.
- Providing availability guarantees under resource exhaustion (DoS is an operational concern).
