# Attestation scheme — review findings

Untracked scratch doc capturing the shortcomings surfaced from a read-through of
`packages/contracts/{attestation,attestor_registry,schnorr}.compact`,
`packages/core/src/claim.ts`, `packages/attestor/src/index.ts`, and `docs/DESIGN.md`.
Not yet triaged into issues — decide keep/reject/how per claim before ticketing.

## 1. Trust externalization, not elimination

The circuit proves "N of M attestors signed this," nothing about whether the
underlying fact is true. All truth-guarantee rests on off-chain attestor
honesty/liveness. Acknowledged in `DESIGN.md` ("attestors certify facts, not
decisions") but worth stating as the scheme's ceiling, not just a footnote.

## 2. Registry is frozen forever at deploy

`attestor_registry.compact:17` — `keys` is a `sealed ledger`, set once by the
constructor, immutable. No rotation, no revocation. A compromised or
permanently-offline attestor forces a full redeploy (losing `claimsVault` /
nullifier history). `N`/`M` are compile-time module params
(`attestation<#K,#V,#N,#M>`) — changing threshold policy also means a new
contract.

## 3. No accountability for attestors

No staking, no slashing, no on-chain consequence for a false signature. Pure
off-chain reputation. Sits oddly next to DESIGN.md explicitly ruling out
"judgment/voting" as out-of-scope — unstaked signature-threshold has a similar
failure mode.

## 4. Holder pseudonym linkability (sharpest finding)

`attestation.compact` `deriveHolder` hashes the holder secret against one
fixed global domain string, `"thoth:holder:v1"`. That pseudonym is stored
**unencrypted** in the public `claimsVault` Map. Per-claim commitment ids are
unlinkable (random `rand` per `persistentCommit`), but `holder` is the same
Field across every claim the same secret ever submits, to every app using the
module. An indexer can correlate one user's claims across unrelated apps even
though claim *values* stay private. Not mentioned in DESIGN.md's privacy
section. Needs contract-address (or app-id) domain separation if
cross-app portability of identity isn't intentional.

## 5. Nullifier set only grows

`nullifiers: Set<Bytes<32>>` has no pruning path — permanent storage/proving
cost growth. Standard for nullifier schemes generally, but no mitigation
currently designed.

## 6. `openClaim` is repeatable by design

Comment in `attestation.compact`: "consumes no nullifier... apps that need
'use once' enforce it with their own holder-keyed state." Pushes a
correctness-critical invariant onto every downstream app author — miss it and
a claim can be spent against your predicate unlimited times.

## 7. Hand-rolled, "temporary" crypto

`schnorr.compact` header: *"Temporary: will be replaced by
jubjubSchnorrVerify from CompactStandardLibrary when it becomes available...
extracted from midnightntwrk/example-zkloan."* Security-critical primitive
the whole N-of-M threshold rests on, currently an example-project extraction
with manual range-check bit-twiddling. Already tracked as issue #17.

**Resolved (#17):** `schnorr.compact` is gone; the registry now verifies with
the stdlib `jubjubSchnorrVerify` (compiler 0.34.0, compact-runtime 0.19.0).

## 8. Fixed numeric-only claim shape

5-field header + `Vector<V, Boolean>` presence mask + `Vector<V, Uint<64>>`.
No strings/structured/variable-length data; `V` fixed at specialization time.

## 9. Freshness checks the claim's self-reported timestamp, not attestation time

Only checks claim.timestamp vs block time — not "evidence was fresh when
attestors signed." A claim can sit and be replayed with a fresh nonce any
time inside the window.

## 10. Band attestors quietly downgrade the security model

DESIGN.md: band attestors give "independent corroboration... rather than
cryptographic proof." Contract treats a band-attestor signature identically
to a zkFetch-attestor signature in the threshold count — no way for an app to
distinguish "N cryptographic proofs" from "N attestors eyeballing their own
feed within tolerance" at the verification layer.

---

Already tracked upstream: #17 (stdlib signatures — covers #7),
#18 (claim version as ledger field — related to #8's rigidity).
