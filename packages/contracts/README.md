# @thoth/contracts

The Compact modules a Midnight contract embeds to verify N-of-M attestations
in-circuit, for dApp developers who consume Thoth claims on-chain.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Use the modules from a checkout of this repo: point
`COMPACT_PATH` at `packages/contracts`, or vendor `attestation.compact` and
`attestor_registry.compact` unchanged into your project (they import each
other as siblings). Compile with Compact `0.34.0` and pin
`@midnight-ntwrk/compact-runtime` to `0.19.0` in the driver: the off-chain
message encoder matches the circuit only at that version.

## Usage

| File | Module | Role |
|------|--------|------|
| `attestation.compact` | `attestation<#K, #V, #B, #N, #M>` | Verifies at least `N` of `M` signatures over the signed message, rejects replays and out-of-window claims, and vaults the claim for the app's predicates to open. |
| `attestor_registry.compact` | `attestor_registry<#M, #K>` | Seals the `M` pinned attestor keys at deploy and counts the signatures that verify, each against its own slot. |

Embed both modules in your top-level contract, seal the deploy-time values in
the constructor, and export `verifyAttestation` as the entry point:

```compact
pragma language_version >= 0.22;

import CompactStandardLibrary;

//           K=22 msg fields  V=3 values  B=2 byte halves  N=2 threshold  M=3 signatures
import "attestation"<22, 3, 2, 2, 3> prefix A_;

import "attestor_registry"<3, 22> prefix R_;

export { A_Claim, A_ClaimEntry };

export { A_freshnessWindow, A_maxWindow, A_policyHashes, A_claimsVault, A_nullifiers };

witness seedPolicies(): Vector<1, Bytes<32>>;

constructor() {
  A_freshnessWindow = disclose(3600); // submittable up to an hour after the window ends
  A_maxWindow = disclose(300); // an observation spans at most five minutes
  for (const h of seedPolicies()) {
    A_policyHashes.insert(disclose(h));
  }
  R_initRegistry(); // pins the M keys from the registry's `seedKeys` witness
}

export circuit verifyAttestation(): [] {
  A_verifyAttestation();
}

// The signed message, so the attestor side and tests can reproduce it.
export pure circuit message(a: A_Claim): Vector<22, Field> {
  return A_buildMessage(a);
}

// An app predicate: open a vaulted claim and read it in-circuit.
export circuit requireStars(id: Bytes<32>, min: Uint<64>): [] {
  const c = A_openClaim(id);
  assert(c.present[0], "slot 0 not measured");
  assert(c.values[0] >= min, "too few stars");
}
```

[`examples/example_app.compact`](https://github.com/txpipe-shop/thoth/blob/main/packages/contracts/examples/example_app.compact)
is this contract without the predicate; the mocks in `test/mocks/` show more predicates,
including source binding and reading a byte value.

The module parameters, fixed when you embed:

- `#V` numeric value slots and `#B` byte halves, two per 32-byte byte value,
  so `#B` is even (`B = 0` is the numeric-only layout).
- `#K`, the signed-message length; the `attestation.compact` header gives the formula.
- `#N` of `#M` signatures must verify; `#M` is also the registry's key count.

The header of
[`attestation.compact`](https://github.com/txpipe-shop/thoth/blob/main/packages/contracts/attestation.compact)
documents each parameter and the wire layout `buildMessage` produces;
[docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md#wire-order)
has the same layout as a table. Attestors sign that exact field vector.

## Concepts

From the [glossary](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md):

- [Claim](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim):
  the signed statement, with its `policyHash`, `subjectHash`, `holder`,
  window, `present` mask, numeric values and byte slots.
- [Registry](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain)
  and [registry slot](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection): the pinned keys, checked positionally; `signatures[i]`
  is verified against `keys[i]`.
- [Threshold](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the `N` in N-of-M.
- [Nullifier](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the hash of the observation identity that blocks replay.
- [Claims vault](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the accepted claims, keyed by `persistentCommit(claim, rand)`.

## Guarantees and limits

`verifyAttestation` rejects a claim unless all of these hold:

- `version` is `1` (`"Unsupported claim version"`).
- `policyHash` is in the sealed `policyHashes` set (`"Unaccepted policy"`).
  The membership check discloses which accepted policy the claim used.
- At least `N` of the `M` signatures verify, each against its own registry
  slot (`"Insufficient valid signatures"`). Empty slots never count, and the
  registry cannot see `N`: pin at least `N` distinct keys or no claim is ever
  accepted. `initRegistry` rejects duplicate keys (`"Duplicate registry keys"`)
  and a second call (`"Registry already initialized"`).
- Every slot whose flag is false carries zero, numeric slots and byte halves
  alike (`"Absent slot has nonzero value"`). A measured zero is valid with its
  flag true, including a short byte value whose padding leaves a half all
  zeros.
- The window is not inverted (`"Window inverted"`), is at most `maxWindow`
  long (`"Window too long"`), and the block time is at or after `windowStart`
  (`"Window in the future"`) and before `windowEnd + freshnessWindow`
  (`"Window too old"`). A zero `freshnessWindow` does not disable the check.
- The caller's secret matches `holder` (`"Holder mismatch"`).
- The observation identity has not been accepted before (`"Observation
  replay"`), and the claim is not already vaulted under the same randomness
  (`"Claim already accepted"`).

What the module does not check, and what your app does itself:

- `appId` is signed but not compared. Each contract keeps its own replay set;
  an app that must refuse claims made for another app compares `appId` in its
  predicate.
- `subjectHash` is signed but not compared. To accept only one source, take the
  subject as private input, recompute the hash, and compare it to the opened
  claim's `subjectHash`, pinning only the fields you need (the mock's
  `openAndBindHost` pins the host and keeps the path private). The claim does
  not commit to the evidence behind it (ADR 0007).
- The two halves of a byte value are checked against zero one by one, not for
  a matching flag. Honest attestors give both halves the slot's flag; a claim
  with unpaired flags carries at least `N` dishonest signatures, which are out
  of scope (ADR 0003).
- The window is when the attestor's witness looked, not when the fact
  happened, and a zkFetch fetch may precede `windowStart` by about 10 minutes.
  Do not read it as the time of the fact
  ([Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim)
  explains why).
- Claim values stay private witness data, but they are not hidden from
  guessing: the nullifier is a public, unsalted hash of the observation whose
  other inputs are public or guessable, so anyone can confirm a guessed value
  by recomputing it. This is easy for an enumerable identifier in a byte slot,
  and it is one of the [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). The ledger also stores
  each claim's commitment, holder pseudonym and window in public.
- Holder secrets are not checked for freshness. Use a fresh, high-entropy
  secret per claim and keep it to open that claim; reusing one links its
  commitments and vault entries.
- `openClaim` consumes no nullifier, so opening is repeatable. "Use once"
  rules are your own holder-keyed state. Never re-export `openClaim` as a
  top-level entry point: its return value is tainted and would force a
  `disclose()` that publishes every value.
- Key provenance is your trust decision; the registry checks only that the
  pinned keys are distinct. The keys are fixed at deploy: to rotate an
  attestor, deploy a new contract.

## Design decisions

- **The claim is the entire message.** Everything the contract inspects is a
  field of the signed vector, so a kind cannot pass the contract data through
  an unsigned side channel.
- **Replay protection keys on the observation identity.** The nullifier hashes
  `appId`, `policyHash`, `subjectHash`, the window, the values and the flags,
  and excludes `holder` and `version`. Re-attesting the same observation for a
  fresh holder still fails ([ADR 0006](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0006-nullifier-keys-on-the-observation-identity.md)).
- **No kind on-chain; the policy hash is the commitment.** A requester cannot
  substitute a laxer policy, and a new kind needs no change here: you accept
  it by sealing its policy hash ([ADR 0002](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0002-no-kind-on-chain-policy-hash.md)).
- **A contract seals a set of policy hashes.** One contract serves several
  policies, and so several kinds ([ADR 0008](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0008-contract-accepts-a-set-of-policy-hashes.md)).
- **Source binding is your in-circuit check.** `subjectHash` is a circuit hash
  so your predicate can recompute it from private subject fields
  ([ADR 0001](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0001-source-binding-by-in-circuit-subject-hash.md)).
- **The holder is a per-claim commitment, not an identity.** The pure
  `holderCommitment(secret)` circuit derives it, and `holderCommitmentOf` in
  `@thoth/core/claim-context` matches it off-chain. Cross-claim or per-user
  state is your app's ([ADR 0004](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0004-holder-is-per-claim-not-an-identity.md)).
- **The window is when the attestor observed.** The contract checks it against
  block time; a fact's own time is a claim value ([ADR 0005](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0005-window-is-when-the-attestor-observed.md)).
- **A byte value is two adjacent 16-byte halves.** Reassemble it in-circuit
  with `Bytes[...c.byteHalves[2 * i], ...c.byteHalves[2 * i + 1]]`; the header
  signs `B` so a claim signed for another layout of the same `K` is rejected
  ([ADR 0009](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0009-byte-value-slots-in-the-claim.md)).
  How a source string becomes those 32 bytes is the kind's parse rule, not the
  contract's ([ADR 0010](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0010-encoded-byte-rules.md)).
- **Registry slots are positional and the keys are sealed.** You assign each
  attestor its slot and place its signature there; the module never reorders.
  `keys` is unexported and only `initRegistry` writes it, so the distinctness
  check cannot be skipped.

## Links

- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): the claim, its wire order and the flow
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md): adding an attestor kind
- [docs/adr/](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/): the decisions behind the modules
- [CONTEXT.md](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md): the glossary
- [CONTRIBUTING.md](https://github.com/txpipe-shop/thoth/blob/main/CONTRIBUTING.md): dev setup and commands
