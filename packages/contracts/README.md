# @txpipe/thoth-contracts

The Compact modules a Midnight contract embeds to verify N-of-M attestations
in-circuit, for dApp developers who consume Thoth claims on-chain.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Use the modules from a checkout of this repo: point
`COMPACT_PATH` at `packages/contracts`. Once it is published, it installs as
`@txpipe/thoth-contracts`, and `COMPACT_PATH` points at
`node_modules/@txpipe/thoth-contracts`. Depend on the package instead of
copying the modules: a copy forks the attestation semantics. Compile with
Compact `0.36.1` and pin `@midnight-ntwrk/compact-runtime` to `0.21.0` in the
driver: the off-chain message encoder matches the circuit only at that version.

## Usage

| File                        | Module                            | Role                                                                                                                                                                                      |
| --------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `attestation.compact`       | `attestation<#K, #V, #B, #N, #M>` | Verifies at least `N` of `M` signatures over the signed message, rejects claims for another app, replays and out-of-window claims, and vaults the claim for the app's predicates to open. |
| `attestor_registry.compact` | `attestor_registry<#M, #K>`       | Seals the `M` pinned attestor keys at deploy and counts the signatures that verify, each against its own slot.                                                                            |

Embed both modules in your top-level contract, seal the deploy-time values in
the constructor, and export `verifyAttestation` as the entry point:

```compact
pragma language_version >= 0.22;

import CompactStandardLibrary;

//           K=24 msg fields  V=3 values  B=2 byte halves  N=2 threshold  M=3 signatures
import "attestation"<24, 3, 2, 2, 3> prefix A_;

import "attestor_registry"<3, 24> prefix R_;

export { A_Claim, A_ClaimEntry };

export { A_appId, A_freshnessWindow, A_maxWindow, A_policyHashes, A_claimsVault, A_nullifiers };

witness seedPolicies(): Vector<1, Bytes<32>>;

// appId names this app; the contract rejects claims signed for any other.
constructor(appId: Bytes<32>) {
  A_appId = disclose(appId);
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
export pure circuit message(a: A_Claim): Vector<24, Field> {
  return A_buildMessage(a);
}

// An app predicate: open a vaulted claim and read it in-circuit.
export circuit requireStars(id: Bytes<32>, min: Uint<64>): [] {
  const c = A_openClaim(id);
  assert(c.present[0], "slot 0 not measured");
  assert(c.values[0] >= min, "too few stars");
}
```

[`examples/example_app.compact`](https://github.com/txpipe/thoth/blob/main/packages/contracts/examples/example_app.compact)
is this contract without the predicate; the mocks in `test/mocks/` show more predicates,
including source binding and reading a byte value.

The module parameters, fixed when you embed:

- `#V` numeric value slots and `#B` byte halves, two per 32-byte byte value,
  so `#B` is even (`B = 0` is the numeric-only layout).
- `#K`, the signed-message length; the `attestation.compact` header gives the formula.
- `#N` of `#M` signatures must verify; `#M` is also the registry's key count.

The header of
[`attestation.compact`](https://github.com/txpipe/thoth/blob/main/packages/contracts/attestation.compact)
documents each parameter and the wire layout `buildMessage` produces;
[docs/DESIGN.md](https://github.com/txpipe/thoth/blob/main/docs/DESIGN.md#wire-order)
has the same layout as a table. Attestors sign that exact field vector.

## Concepts

From the [glossary](https://github.com/txpipe/thoth/blob/main/CONTEXT.md):

- [Claim](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim):
  the signed statement, with its `policyHash`, `subjectHash`, `holder`,
  [salt](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim),
  window, `present` mask, numeric values and byte slots.
- [Registry](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#on-chain)
  and [registry slot](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#signing-and-collection):
  the pinned keys, checked positionally; `signatures[i]` is verified against
  `keys[i]`.
- [Threshold](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#on-chain):
  the `N` in N-of-M.
- [Nullifier](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#on-chain):
  the hash of the observation identity that blocks replay.
- [Claims vault](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#on-chain):
  the accepted claims, keyed by `persistentCommit(claim, rand)`.

## Guarantees and limits

`verifyAttestation` rejects a claim unless all of these hold:

- `version` is `1` (`"Unsupported claim version"`).
- `appId` equals the sealed `appId` (`"App id mismatch"`), so a claim signed
  for another app is rejected even when that app pins the same attestors and
  policy.
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
  replay"`). This also rejects the same claim resubmitted under the same vault
  randomness, so the vault needs no check of its own.

What the module does not check, and what your app does itself:

- `subjectHash` is signed but not compared. To accept only one source, take the
  subject as private input, recompute the hash, and compare it to the opened
  claim's `subjectHash`, pinning only the fields you need (the mock's
  `openAndBindHost` pins the host and keeps the path private). The claim does
  not commit to the evidence behind it (ADR 0007).
- The two halves of a byte value are checked against zero one by one, not for
  a matching flag. Honest attestors give both halves the slot's flag; a claim
  with unpaired flags carries at least `N` dishonest signatures, which are out
  of scope (ADR 0003).
- The kind decides the window. Read it as the time the kind's observation
  happened, not as a universal fact timestamp
  ([Window](https://github.com/txpipe/thoth/blob/main/CONTEXT.md#the-claim)
  explains why).
- The module does not check where the `salt` came from. The kind decides it:
  secret when the values are secret or guessable, so the nullifier cannot
  confirm a guess
  ([ADR 0012](https://github.com/txpipe/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md));
  public when they are public chain data, so the nullifier reveals the event
  ([ADR 0014](https://github.com/txpipe/thoth/blob/main/docs/adr/0014-chain-event-kinds.md)).
  Your attestors must derive it from the evidence and refuse another, so a
  client cannot vary it to replay one observation. Never disclose
  `claim.holder` in your own circuits; where the salt follows the holder, keep
  it secret too and key holder state on the vault pseudonym (`holderOf`).
- The nullifier does not stop one fact from being claimed again under a fresh
  holder when the kind's salt follows the holder, as zkFetch's does: a new
  fetch under a fresh holder gets a new salt and a new nullifier, even in the
  same window. If your app needs one claim per fact (one per account per day,
  say), keep your own set keyed on that fact. That set is public, so it
  confirms guesses at whatever it keys on
  ([ADR 0012](https://github.com/txpipe/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
  The ledger stores each claim's nullifier, commitment, vault pseudonym
  (derived from the holder secret) and window in public, and the transaction
  discloses which accepted policy it used.
- Holder secrets are not checked for freshness. Use a fresh, high-entropy
  secret per claim and keep it to open that claim. Where the salt follows the
  holder, a guessable secret makes the salt guessable too, and the nullifier
  can then confirm guessed values. Reusing a secret links its
  commitments and vault entries.
- `openClaim` consumes no nullifier, so opening is repeatable. "Use once"
  rules are your own state, keyed on the vault pseudonym. Never re-export
  `openClaim` as a top-level entry point: its return value is tainted and
  would force a `disclose()` that publishes every value.
- Key provenance is your trust decision; the registry checks only that the
  pinned keys are distinct. The keys are fixed at deploy: to rotate an
  attestor, deploy a new contract.

## Design decisions

- **The claim is the entire message.** Everything the contract inspects is a
  field of the signed vector, so a kind cannot pass the contract data through
  an unsigned side channel.
- **Replay protection keys on the observation identity.** The nullifier hashes
  `appId`, `policyHash`, `subjectHash`, `salt`, the window, the values and the
  flags. It does not hash `holder` or `version`. In zkFetch the holder can
  reach it through the kind's salt, so a fresh holder may get a fresh
  nullifier; what stops a fresh holder from re-claiming an observation is the
  kind's evidence binding: a new holder needs new evidence, which gets a new
  nullifier when the salt follows the holder ([Guarantees and limits](#guarantees-and-limits))
  ([ADR 0006](https://github.com/txpipe/thoth/blob/main/docs/adr/0006-nullifier-keys-on-the-observation-identity.md),
  [ADR 0011](https://github.com/txpipe/thoth/blob/main/docs/adr/0011-evidence-binds-the-claim-context.md)).
- **In zkFetch the nullifier hashes a secret salt.** The salt never reaches the
  ledger, so only those who hold the evidence, such as the witnesses and
  attestors, can confirm a guessed value by recomputing the nullifier; they
  already see the values. The
  attestors derive it from the evidence, so a client cannot vary it to replay
  one observation ([ADR 0012](https://github.com/txpipe/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
- **No kind on-chain; the policy hash is the commitment.** A requester cannot
  substitute a laxer policy, and a new kind needs no change here: you accept
  it by sealing its policy hash ([ADR 0002](https://github.com/txpipe/thoth/blob/main/docs/adr/0002-no-kind-on-chain-policy-hash.md)).
- **A contract seals its app id.** You pass it to the constructor, and the
  contract accepts only claims signed for it. Each contract keeps its own
  replay set, so the nullifier alone would not stop a claim stored in one app
  from being stored again in another
  ([ADR 0013](https://github.com/txpipe/thoth/blob/main/docs/adr/0013-contract-seals-its-app-id.md)).
- **A contract seals a set of policy hashes.** One contract serves several
  policies, and so several kinds ([ADR 0008](https://github.com/txpipe/thoth/blob/main/docs/adr/0008-contract-accepts-a-set-of-policy-hashes.md)).
- **Source binding is your in-circuit check.** `subjectHash` is a circuit hash
  so your predicate can recompute it from private subject fields
  ([ADR 0001](https://github.com/txpipe/thoth/blob/main/docs/adr/0001-source-binding-by-in-circuit-subject-hash.md)).
- **The holder is a per-claim commitment, not an identity.** The pure
  `holderCommitment(secret)` circuit derives it, and `holderCommitmentOf` in
  `@txpipe/thoth-core/claim-context` matches it off-chain. Cross-claim or per-user
  state is your app's ([ADR 0004](https://github.com/txpipe/thoth/blob/main/docs/adr/0004-holder-is-per-claim-not-an-identity.md)).
- **The window is when the attestor observed.** The contract checks it against
  block time; a fact's own time is a claim value ([ADR 0005](https://github.com/txpipe/thoth/blob/main/docs/adr/0005-window-is-when-the-attestor-observed.md)).
- **A byte value is two adjacent 16-byte halves.** Reassemble it in-circuit
  with `Bytes[...c.byteHalves[2 * i], ...c.byteHalves[2 * i + 1]]`; the header
  signs `B` so a claim signed for another layout of the same `K` is rejected
  ([ADR 0009](https://github.com/txpipe/thoth/blob/main/docs/adr/0009-byte-value-slots-in-the-claim.md)).
  How a source string becomes those 32 bytes is the kind's parse rule, not the
  contract's ([ADR 0010](https://github.com/txpipe/thoth/blob/main/docs/adr/0010-encoded-byte-rules.md)).
- **Registry slots are positional and the keys are sealed.** You assign each
  attestor its slot and place its signature there; the module never reorders.
  `keys` is unexported and only `initRegistry` writes it, so the distinctness
  check cannot be skipped.

## Links

- [docs/DESIGN.md](https://github.com/txpipe/thoth/blob/main/docs/DESIGN.md): the claim, its wire order and the flow
- [docs/kind-author-guide.md](https://github.com/txpipe/thoth/blob/main/docs/kind-author-guide.md): adding an attestor kind
- [docs/adr/](https://github.com/txpipe/thoth/blob/main/docs/adr/): the decisions behind the modules
- [CONTEXT.md](https://github.com/txpipe/thoth/blob/main/CONTEXT.md): the glossary
- [CONTRIBUTING.md](https://github.com/txpipe/thoth/blob/main/CONTRIBUTING.md): dev setup and commands
