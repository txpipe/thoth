> Origin: witness-fitness/docs/PRIVATE-N-OF-M-ATTESTATIONS.md — hackathon repo; this copy is authoritative for Thoth.
# Private N-of-M Attestations for Midnight — feasibility report

**Status:** Feasible. One limit is fundamental (runtime-generic N is impossible in any ZK
circuit); the rest is solved design, most of it already proven in Witness Fitness.

---

## 1. The idea

Independent off-chain attestors certify a claim; the user collects N signatures over the same
canonical claim; Midnight proves — privately — that N authorized attestors signed it, that the
claim matches its commitment, that freshness/replay checks pass, and that an application-defined
predicate over the claim holds. The attested data itself never leaves the user's machine.

Key property: **the attestation layer certifies facts, not application decisions.** The same
attested value feeds different predicates in different apps without the attestors knowing or
caring. zkFetch/TLSNotary/API/sensor/human are interchangeable *evidence adapters*; the contract
only ever sees the attestors' signatures.

## 2. How it works

```
 evidence adapter (zkFetch, TLSNotary, API, sensor, …)
        │  attestor independently establishes truth of claim X
        ▼
 attestors A, B, C …  (each: verify evidence → sign X with Jubjub-Schnorr key)
        │  sig_A(X)  sig_B(X)  sig_C(X)
        ▼
      user (private witness data: X + N signatures)
        │
        ▼
 Midnight circuit:
   • N signatures verify (Schnorr-on-Jubjub, in-circuit)
   • each signer pk is a member of the current attestor registry (Merkle proof)
   • signers are distinct (N distinct leaves)
   • claim X == the value the predicate P(X) operates on  (canonical encoding)
   • freshness window + nullifier (no replay)
   • P(X)  → application outcome (wager settles, badge mints, …)
```

The claim encoding is the interface contract: `X` is a fixed `Vector<L, Field>` (or a struct
serialized to one), and every signature commits to that exact encoding. This mirrors
`assertion.compact`'s frozen 22-field encoding and the signature-parity rule in
`ARCHITECTURE.md` §4 — already proven working in this repo.

## 3. The fundamental limit: why "generic N" can't mean "runtime N"

This is a property of zero-knowledge circuits, not a Midnight gap:

- A ZK circuit has a **fixed shape** compiled into a fixed verifier key. The number of
  signature verifications performed is baked in at compile time — you cannot loop "until N
  signatures verify" because `for` loops are fully unrolled and branch conditions are
  constrained, not executed.
- So a single deployed circuit cannot accept *any* N chosen at transaction time.

**What "generic N" does mean, and what is achievable:**

| Interpretation of "generic" | Feasible? | How |
|---|---|---|
| N chosen at runtime by the transaction | **No** | Impossible in any ZK system; verifier key is fixed per circuit |
| N as a compile-time parameter (library/deploy-time choice) | **Yes** | Compact type-level generics (`#n`), or codegen — instantiate a module `attestations<#N, #D, #L>` per threshold |
| "At least N" over a bounded maximum | **Yes** | Fixed K slots + count-valid pattern (Witness Fitness `countValidSignatures`: 3 slots, require ≥2) |
| Attestor set M dynamic / unbounded | **Yes** | MerkleTree registry — cost is O(N·depth), independent of M (below) |

The right mental model: **N is a deployment parameter, not a transaction parameter.** An
application picks its threshold (2-of-3 for money, 1-of-1 for convenience, 3-of-5 for high
stakes) when it deploys; that choice is part of the contract's configuration, exactly like the
2-of-3 registry is today.

## 4. Addressing the limits — four levers

### 4.1 N as a compile-time parameter

The generic mechanism is a Compact **module** parameterized by `#N` (threshold), `#D`
(registry Merkle depth), `#L` (claim length):

```compact
module attestations<#N, #D, #L> {
    export circuit verifyAttestation(
        claim: Vector<#L, Field>,
        sigs: Vector<#N, SchnorrSignature>,
        pks: Vector<#N, JubjubPoint>,          // each proven in-registry below
        paths: Vector<#N, MerkleTreePath<#D, Bytes<32>>>
    ): Boolean { … }
}
```

The compiler unrolls the fixed-`#N` verification loop at compile time. Different thresholds =
different instantiations = different verifier keys, chosen at deploy. Nothing about the
witness, prover, or off-chain signer changes — they already produce exactly-N signatures.

### 4.2 "At least N" with bounded slots

When a range of thresholds must be accepted by one circuit, fix a maximum K and count valid
signatures — the pattern `stride.compact` already uses (`countValidSignatures`, `verifySlot`
with empty-slot semantics for rotation/blacklisting). Cost is O(K), independent of the
threshold. N=1..K all work from one circuit.

### 4.3 Dynamic attestor set via MerkleTree — the real fix for M

The current registry is a positional `Vector<3, JubjubPoint>` (sig[i] ↔ registry[i]); that caps
M at the vector size. Replacing it with a Merkle tree decouples M from circuit cost:

- Ledger: `registry: MerkleTree<#D, Bytes<32>>` (or `HistoricMerkleTree` to accept proofs
  against past roots). Depth 2..32 → up to 2^D attestors (depth 10 = 1024).
- Enroll/rotate: `insertHash(pk_hash)` / `insertHashIndex(…, i)` / `insertIndexDefault(i)` for
  removal — the tree hides the leaf value on-chain (the only ledger op that does), so the
  registry itself is privacy-preserving.
- Verify: for each signature, prove `checkRoot(merkleTreePathRootNoLeafHash<#D>(path))` with
  the pre-hashed pk as leaf — the documented "restrict a circuit to a group" pattern from the
  Midnight guides, which also shows the mandatory binding step (`path.leaf == derived identity`)
  so a witnessed path can't be replayed.
- Distinctness: the N leaves must differ — pairwise `path.leaf != other.leaf` asserts (or
  disclosed distinct leaf indices). Cheap.

Cost per signature: D two-to-one Poseidon hashes (~hundreds of constraints) — **adding an
attestor costs the circuit nothing; only the tree grows.** This is the answer to "efficient
signer-set membership". Governance of who may insert/remove leaves is orthogonal: admin key
(like `adminSecret` today) or a threshold of existing signers (recursive use of the same
mechanism).

### 4.4 Aggregation / batching — evaluated, rejected for now

- **BLS aggregation**: elegant (linear aggregation, no interactivity) but requires pairings —
  Compact's stdlib has no pairing; the contract verifies Jubjub-Schnorr natively. Out.
- **MuSig / multi-signatures**: aggregate k signatures into one verification, but require the
  attestors to *coordinate* a signing session — breaks the independence property that makes
  N-of-M meaningful. Out as a primary mechanism.
- **Batch verification**: linear-combination batching of Schnorr still costs ~N scalar
  multiplications in-circuit; the fixed-base mul for the response term is the only
  optimizable piece. Marginal, adds a public random challenge. Deferred.
- **Stdlib `jubjubSchnorrVerify`**: confirmed absent in current stdlib (compile probe in
  `schnorr.compact`); the zk-loan tutorial states it is in development. When it ships, the
  polyfill is replaced by one builtin — likely cheaper than the hand-built msm, but the
  scaling story (N small, membership via Merkle) is unchanged.

## 5. Cost picture (order-of-magnitude estimates)

Per signature: 2 Jubjub scalar multiplications + 1 Poseidon challenge ≈ low thousands of
constraints (dominant cost); plus a depth-D Merkle path ≈ D × ~100–300 constraints.
A 3-of-M instance at depth 10 ≈ ~10–25k constraints total — well within the envelope already
demonstrated: the current contract runs 3 Schnorr verifications per attestation and the
2-of-3 flow passes in the simulator, so the cost story is validated at N=3 today.

Exact gate counts need a compile probe on the generic module (`compact compile` output); the
order of magnitude above is the engineering expectation, not measured numbers.

## 6. What carries over from Witness Fitness unchanged

- **Freshness**: timestamp window vs `blockTimeGte` (already done; demo window 30 days).
- **Replay protection**: assertion nonce → `nullifiers: Set<Bytes<32>>` (already done).
- **Claim-commitment binding**: `persistentCommit(claim, rand)` stored as a vaulted credential
  (already done); the generic module's `verifyAttestation` replaces the fixed-22 encoding with
  `Vector<#L, Field>` but keeps the same challenge-hash discipline.
- **Signing parity**: off-chain signers import the compiled `pureCircuits` for the challenge
  hash; roundtrip sign→verify simulator test before anything else (ARCHITECTURE.md §4).
- **Holder binding**: `hashToCurve` pseudonymous identity for spending credentials.

## 7. Bottom line

| Question | Answer |
|---|---|
| Is private N-of-M attestation feasible on Midnight? | **Yes** — with N as a compile-time/deployment parameter |
| Is runtime-generic N possible? | **No** — impossible in any ZK circuit; fixed verifier keys |
| Is dynamic M (attestor set) possible? | **Yes** — MerkleTree registry, cost O(N·depth), M up to 2^depth |
| Is signature aggregation needed? | No — BLS needs pairings (absent); MuSig breaks attestor independence |
| What's the work? | Extract `attestations<#N,#D,#L>` module from `schnorr.compact`/`assertion.compact`, swap the fixed registry for `MerkleTree`, add a compile probe for real gate counts |

The "generic" mechanism is real and the hard-looking limit (generic N) dissolves into a
deployment-time constant — the standard ZK answer, already half-built in this repo.
