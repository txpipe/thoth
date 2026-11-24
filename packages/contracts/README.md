# @thoth/contracts

The Compact modules a Midnight contract embeds to verify N-of-M attestations
in-circuit, for dApp developers who consume Thoth claims on-chain.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Use the modules from a checkout of this repo: point
`COMPACT_PATH` at `packages/contracts`, or vendor `attestation.compact` and
`attestor_registry.compact` unchanged into your project (they import each
other as siblings). Compile with Compact `0.36.1` and pin
`@midnight-ntwrk/compact-runtime` to `0.21.0` in the driver: the off-chain
message encoder matches the circuit only at that version.

## Usage

| File                        | Module                        | Role                                                                                                                                                                                                   |
| --------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `attestation.compact`       | `attestation<#V, #W, #N, #M>` | Verifies `N` signatures from distinct registry slots over the signed message, rejects claims for another app, replays and out-of-window claims, and vaults the claim for the app's predicates to open. |
| `attestor_registry.compact` | `attestor_registry<#M, Msg>`  | Seals the `M` pinned attestor keys at deploy and checks each signature against the key of the slot it names. The attestation module embeds it with its `SignedMessage` as `Msg`.                       |

Embed both modules in your top-level contract, seal the deploy-time values in
the constructor, and export `verifyAttestation` as the entry point:

```compact
pragma language_version >= 0.22;

import CompactStandardLibrary;

//           V=3 values  W=1 byte value  N=2 threshold  M=3 registry slots
import "attestation"<3, 1, 2, 3> prefix A_;

// The registry instance the attestation module embeds: same slot count, and
// the module's signed message type.
import "attestor_registry"<3, A_SignedMessage> prefix R_;

export { A_Claim, A_ClaimEntry, A_Observation, A_SignedMessage };

export { A_appId, A_freshnessWindow, A_maxWindow, A_policyHashes, A_claimsVault };

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
export pure circuit message(a: A_Claim): A_SignedMessage {
  return A_buildMessage(a);
}

// An app predicate: open a vaulted claim by its nullifier and read it in-circuit.
export circuit requireStars(id: Bytes<32>, min: Uint<64>): [] {
  const c = A_openClaim(id);
  assert(c.present[0], "slot 0 not measured");
  assert(c.values[0] >= min, "too few stars");
}
```

[`examples/example_app.compact`](https://github.com/txpipe-shop/thoth/blob/main/packages/contracts/examples/example_app.compact)
is this contract without the predicate; the mocks in `test/mocks/` show more predicates,
including source binding and reading a byte value.

Your dApp implements the module witnesses. `getAttestationWitness` returns the
claim, `getHolderSecret` the holder secret, `getHolderScalar` the scalar
`openClaim` proves ownership with (`degradeToTransient(holderSecret)` from
`@midnight-ntwrk/compact-runtime`: the secret's first 31 bytes read
little-endian), and `getSignatures` exactly `N` signatures, each tagged with the
`registryIndex` of the key it verifies against, in increasing slot order:

```ts
// From the threshold set your client collected, already in slot order:
const signatures = collected.map(({ registryIndex, attestation }) => ({
  registryIndex: BigInt(registryIndex),
  signature: attestation.signature, // the runtime's JubjubSchnorrSignature
}));

// Keep them in your private state, and in your witnesses:
getSignatures: ({ privateState }) => [privateState, privateState.signatures],
```

The module parameters, fixed when you embed:

- `#V` numeric value slots and `#W` 32-byte value slots (`W = 0` is the
  numeric-only layout).
- `#N`, the threshold: how many signatures `getSignatures` supplies, all of
  which must verify; `#M`, the registry's key count. Import the registry as
  `attestor_registry<M, A_SignedMessage>`, with the attestation module's
  prefix: other parameters compile to a second registry that the module never
  reads, and no claim verifies.

The header of
[`attestation.compact`](https://github.com/txpipe-shop/thoth/blob/main/packages/contracts/attestation.compact)
documents each parameter and the wire layout: the seven fields `buildMessage`
produces and the bytes `nullifierOf` hashes;
[docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md#wire-order)
has the same layout as tables.

## Concepts

From the [glossary](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md):

- [Claim](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim):
  the signed statement, with its `policyHash`, `subjectHash`, `holder`,
  [salt](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim),
  window, `present` mask, numeric values and byte slots.
- [Registry](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain)
  and [registry slot](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection):
  the pinned keys; each signature names its slot and is verified only against
  that slot's key.
- [Threshold](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the `N` in N-of-M.
- [Nullifier](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the SHA-256 of the observation identity; the attestors sign it, and it
  blocks replay.
- [Claims vault](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the accepted claims, keyed by their nullifier. Compute a claim's key with
  the pure `nullifierOf(claim)` and pass it to `openClaim`.

## Guarantees and limits

`verifyAttestation` rejects a claim unless all of these hold:

- `version` is `1` (`"Unsupported claim version"`).
- `appId` equals the sealed `appId` (`"App id mismatch"`), so a claim signed
  for another app is rejected even when that app pins the same attestors and
  policy.
- `policyHash` is in the sealed `policyHashes` set (`"Unaccepted policy"`).
  The membership check discloses which accepted policy the claim used.
- `N` signatures verify, each against the key of the registry slot it names
  (`"Insufficient valid signatures"`). The slots are strictly increasing, so no
  slot counts twice (`"Registry slots not increasing"`), and each holds a key
  (`"Empty registry slot"`, also for a slot at or past `M`). The registry
  cannot see `N`: pin at least `N` distinct keys or no claim is ever
  accepted. `initRegistry` rejects duplicate keys (`"Duplicate registry keys"`)
  and a second call (`"Registry already initialized"`).
- Every slot whose flag is false carries zero, numeric and byte slots alike
  (`"Absent slot has nonzero value"`). A measured zero is valid with its flag
  true.
- The window is not inverted (`"Window inverted"`), is at most `maxWindow`
  long (`"Window too long"`), and the block time is at or after `windowStart`
  (`"Window in the future"`) and before `windowEnd + freshnessWindow`
  (`"Window too old"`). A zero `freshnessWindow` does not disable the check.
- The caller's secret matches `holder` (`"Holder mismatch"`).
- The observation identity has not been accepted before (`"Observation
  replay"`): its nullifier is not already a vault key.

What the module does not check, and what your app does itself:

- `subjectHash` is signed but not compared. To accept only one source, take the
  subject as private input, recompute the hash, and compare it to the opened
  claim's `subjectHash`, pinning only the fields you need (the mock's
  `openAndBindHost` pins the host and keeps the path private). The claim does
  not commit to the evidence behind it (ADR 0007).
- The window is when the attestor's witness looked, not when the fact
  happened, and a zkFetch fetch may precede `windowStart` by about 10 minutes.
  Do not read it as the time of the fact
  ([Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim)
  explains why).
- The module does not check where the `salt` came from. The nullifier hides
  the values only while the salt is secret, so your kind's attestors must
  derive it from the evidence, keep it off-chain, and include an input an
  outsider cannot guess or enumerate, such as the holder commitment through the
  claim context digest. A hash of public or guessable evidence alone hides
  nothing
  ([ADR 0012](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
  Never disclose the salt or `claim.holder` in your own circuits: a kind may
  derive the salt from the holder, as zkFetch does. Key holder state on the
  vault pseudonym (`holderOf`) instead.
- The nullifier does not stop one fact from being claimed again under a fresh
  holder when the kind's salt follows the holder, as zkFetch's does: a new
  fetch under a fresh holder gets a new salt and a new nullifier, even in the
  same window. If your app needs one claim per fact (one per account per day,
  say), keep your own set keyed on that fact. That set is public, so it
  confirms guesses at whatever it keys on
  ([ADR 0012](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
  The ledger stores each claim's nullifier (the vault key), vault pseudonym
  (derived from the holder secret) and window in public, and the transaction
  discloses which accepted policy it used.
- Holder secrets are not checked for freshness. Use a fresh, high-entropy
  secret per claim and keep it to open that claim. Where the salt follows the
  holder, a guessable secret makes the salt guessable too, and the nullifier
  can then confirm guessed values. Reusing a secret links its
  commitments and vault entries.
- `openClaim` returns the claim's `Observation`: every field the nullifier
  binds, which is all but `holder` and `version`. The caller's tie to the
  claim is the vault pseudonym, checked against the holder scalar it was
  derived from.
- `openClaim` consumes nothing, so opening is repeatable. "Use once"
  rules are your own state, keyed on the vault pseudonym. Never re-export
  `openClaim` as a top-level entry point: its return value is tainted and
  would force a `disclose()` that publishes every value.
- A slot is a `Uint<8>`, so in a registry of more than 256 keys the slots
  past 255 can never sign.
- Key provenance is your trust decision; the registry checks only that the
  pinned keys are distinct. The keys are fixed at deploy: to rotate an
  attestor, deploy a new contract.

## Design decisions

- **The claim is the entire message.** Everything the contract inspects is a
  field of the claim the signatures cover, so a kind cannot pass the contract
  data through an unsigned side channel.
- **Attestors sign the nullifier.** The message is seven fields: the claim's
  version, `V`, `W`, its nullifier and its holder. `verifyAttestation` hashes
  the claim once, for the signatures, replay and the vault key, no byte is
  sliced in-circuit, and a signature costs the same to verify whatever your
  slot counts are. A signature binds every claim byte as far as SHA-256 is
  collision resistant, which the vault already relies on. The observation
  identity is then part of the wire format: changing the `Observation` struct
  or its hash changes what every attestor signs
  ([ADR 0014](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0014-attestors-sign-the-nullifier.md)).
- **Replay protection keys on the observation identity.** The nullifier hashes
  `appId`, `policyHash`, `subjectHash`, `salt`, the window, the values and the
  flags. It does not hash `holder` or `version`, but the holder can reach it
  through the kind's salt, so a fresh holder may get a fresh nullifier. What
  stops a fresh holder from re-claiming an observation is the kind's evidence
  binding: a new holder needs new evidence, which gets a new nullifier when the
  salt follows the holder ([Guarantees and limits](#guarantees-and-limits))
  ([ADR 0006](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0006-nullifier-keys-on-the-observation-identity.md),
  [ADR 0011](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0011-evidence-binds-the-claim-context.md)).
- **The nullifier hashes a secret salt.** The salt never reaches the ledger, so
  only those who hold the evidence, such as the witnesses and attestors, can
  confirm a guessed value by recomputing the nullifier; they already see the
  values. The
  attestors derive it from the evidence, so a client cannot vary it to replay
  one observation ([ADR 0012](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
- **No kind on-chain; the policy hash is the commitment.** A requester cannot
  substitute a laxer policy, and a new kind needs no change here: you accept
  it by sealing its policy hash ([ADR 0002](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0002-no-kind-on-chain-policy-hash.md)).
- **A contract seals its app id.** You pass it to the constructor, and the
  contract accepts only claims signed for it. Each contract keeps its own
  replay set, so the nullifier alone would not stop a claim stored in one app
  from being stored again in another
  ([ADR 0013](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0013-contract-seals-its-app-id.md)).
- **The vault is keyed by the nullifier.** A claim's nullifier is public
  anyway, so a separate vault commitment would hide nothing more and cost
  `verifyAttestation` a second hash of the whole claim. You open a claim with
  `nullifierOf(claim)`, and your witness supplies no commitment randomness
  ([ADR 0016](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0016-claims-vault-keyed-by-the-nullifier.md)).
- **The vault pseudonym survives network upgrades.** It is `x(s * G)` on
  Jubjub for the holder secret `s`, so a hard fork that changes Midnight's
  transient hash does not lock vaulted claims. Use the holder secret only as a
  holder secret, never as a signing key
  ([ADR 0017](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0017-vault-pseudonym-survives-network-upgrades.md)).
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
- **A byte value is one `Bytes<32>`.** Compare `c.byteValues[i]` in your
  predicate directly; the message signs `V` and `W`, so a claim signed for
  another layout is rejected
  ([ADR 0009](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0009-byte-value-slots-in-the-claim.md),
  [ADR 0014](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0014-attestors-sign-the-nullifier.md)).
  How a source string becomes those 32 bytes is the kind's parse rule, not the
  contract's ([ADR 0010](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0010-encoded-byte-rules.md)).
- **Registry slots are positional and the keys are sealed.** You assign each
  attestor its slot and tag its signature with it; the module checks the
  signature only against that slot's key and never reorders. `keys` is
  unexported and only `initRegistry` writes it, so the distinctness check
  cannot be skipped.
- **The contract verifies N signatures, not M.** You pass the threshold set
  and no dummies, so proving cost grows with `N`; each extra registry slot
  costs only a few rows. Which slots signed stays private: the indices are
  witness data and the circuit reads every key
  ([ADR 0015](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0015-contract-verifies-n-named-signatures.md)).
- **The registry verifies Schnorr signatures itself.** It repeats the stdlib
  check over a signature whose response is a `JubjubScalar`, which saves about
  350 rows per signature; attestors sign with the runtime's `jubjubSchnorrSign`
  as before
  ([ADR 0015](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0015-contract-verifies-n-named-signatures.md)).

## Links

- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): the claim, its wire order and the flow
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md): adding an attestor kind
- [docs/adr/](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/): the decisions behind the modules
- [CONTEXT.md](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md): the glossary
- [CONTRIBUTING.md](https://github.com/txpipe-shop/thoth/blob/main/CONTRIBUTING.md): dev setup and commands
