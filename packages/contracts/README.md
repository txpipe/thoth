# @txpipe/thoth-contracts

The Compact modules a Midnight contract embeds to verify N-of-M attestations
in-circuit, for dApp developers who consume Thoth claims on-chain.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Use the modules from a checkout of this repo: point
`COMPACT_PATH` at `packages/contracts`. Once it is published, it installs as
`@txpipe/thoth-contracts`, and `COMPACT_PATH` points at
`node_modules/@txpipe/thoth-contracts`. Depend on the package instead of
copying the modules: a copy forks the attestation semantics. Compile with
Compact `0.36.1` and pin `@midnight-ntwrk/compact-runtime` to `0.21.0` in the
driver: the off-chain message encoder matches the circuit only at that version.

## Usage

| File                        | Module                        | Role                                                                                                                                                                                                   |
| --------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `attestation.compact`       | `attestation<#V, #W, #N, #M>` | Verifies `N` signatures from distinct registry slots over the signed message, rejects claims for another app, replays and out-of-window claims, and vaults the claim for the app's predicates to open. |
| `attestor_registry.compact` | `attestor_registry<#M>`       | Seals the `M` pinned attestor keys at deploy and checks each signature over the seven-field message against the key of the slot it names.                                                              |

Embed both modules in your top-level contract, seal the deploy-time values in
the constructor, and export `verifyAttestation` as the entry point:

```compact
pragma language_version >= 0.22;

import CompactStandardLibrary;

//           V=3 values  W=1 byte slot  N=2 threshold  M=3 registry slots
import "attestation"<3, 1, 2, 3> prefix A_;

import "attestor_registry"<3> prefix R_;

export { A_Claim, A_ClaimEntry };

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
export pure circuit message(a: A_Claim): Vector<7, Field> {
  return A_buildMessage(a);
}

// An app predicate: open a vaulted claim by its nullifier and read it in-circuit.
export circuit requireStars(nullifier: Bytes<32>, min: Uint<64>): [] {
  const c = A_openClaim(nullifier);
  assert(c.present[0], "slot 0 not measured");
  assert(c.values[0] >= min, "too few stars");
}
```

[`examples/example_app.compact`](https://github.com/txpipe-shop/thoth/blob/main/packages/contracts/examples/example_app.compact)
is this contract without the predicate; the mocks in `test/mocks/` show more predicates,
including source binding and reading a byte value.

The module parameters, fixed when you embed:

- `#V` numeric value slots and `#W` byte slots, each one 32-byte value
  (`W = 0` is the numeric-only layout).
- `#N` signatures from distinct registry slots must verify, out of `#M`
  slots; `#M` is also the registry's key count, at most 65,536.

Your dApp implements two witnesses for `verifyAttestation`:
`getAttestationWitness` returns the claim, and `getSignatures` returns exactly
`#N` entries `{ registryIndex, signature }`, in increasing slot order.
`slotSignaturesOf(collected)` from `@txpipe/thoth-client` builds them from a
kind's collected attestations:

```ts
const { claim, collected } = await client.collect(/* ... */);
const witnesses = {
  getAttestationWitness: ({ privateState }) => [privateState, toContractClaim(claim)],
  getSignatures: ({ privateState }) => [privateState, slotSignaturesOf(collected)],
  // getHolderSecret, seedKeys, ...
};
```

The header of
[`attestation.compact`](https://github.com/txpipe-shop/thoth/blob/main/packages/contracts/attestation.compact)
documents each parameter and the wire layout: the seven fields `buildMessage`
produces and the nullifier's preimage;
[docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md#wire-order)
has the same layout as tables. Attestors sign those seven fields.

### Proving cost

What each circuit of the two test mocks costs to prove, measured with
`npm run bench` on an AMD Ryzen 7 5700G (8 cores, 16 threads, 31 GiB) and the
proof server `midnightntwrk/proof-server:9.0.0`, three warm proofs per
circuit. Both mocks are 2-of-3 with `V = 3`: `mock_attestation` has no byte
slot (`W = 0`) and `mock_attestation_bytes` has one (`W = 1`). The proof
server verified every proof against its verifier key.

| Mock                   | Circuit               | k   | Rows   | Proving key (MB) | Proof (B) | First proof (s) | Warm proof (s) | CPU per warm proof (s) | Peak memory (MB) |
| ---------------------- | --------------------- | --- | ------ | ---------------- | --------- | --------------- | -------------- | ---------------------- | ---------------- |
| mock_attestation       | verifyAttestation     | 14  | 12,177 | 24.7             | 5,772     | 1.79            | 1.38           | 11.3                   | 444              |
| mock_attestation       | openAndRead           | 13  | 6,639  | 12.3             | 5,772     | 0.84            | 0.65           | 6.0                    | 229              |
| mock_attestation       | openAndReadPresence   | 13  | 6,609  | 12.3             | 5,772     | 0.84            | 0.66           | 6.0                    | 235              |
| mock_attestation       | openAndRequireMetric0 | 13  | 6,599  | 12.3             | 5,772     | 0.84            | 0.66           | 6.0                    | 235              |
| mock_attestation       | openAndBindHost       | 14  | 12,662 | 24.6             | 5,772     | 1.59            | 1.21           | 10.8                   | 448              |
| mock_attestation_bytes | verifyAttestation     | 14  | 14,123 | 24.7             | 5,772     | 1.78            | 1.43           | 11.5                   | 462              |
| mock_attestation_bytes | openAndReadBytes      | 14  | 8,608  | 24.6             | 5,772     | 1.57            | 1.16           | 10.4                   | 426              |

How to read it:

- A circuit of `k` is proved as `2^k` rows, so each step in `k` roughly
  doubles the time and the proving key: a `verifyAttestation` proof (`k = 14`)
  takes about twice as long as opening a numeric claim (`k = 13`).
- The first proof of a circuit parses its proving key, so it takes about a
  third longer. The server keeps the last five keys it parsed; a later proof
  of a cached circuit takes the warm time.
- Your dApp ships each circuit's proving key and uploads it with every proof.
- CPU time is the server's, summed over its threads. Peak memory is the
  server container's high-water mark, page cache included, while it proves
  that circuit alone. A server that proves `verifyAttestation` or opens a
  byte value (`k = 14`) needs about 0.5 GB, and one that only opens numeric
  claims about 0.25 GB.

`CONTRIBUTING.md` explains how to
[run the benchmark](https://github.com/txpipe-shop/thoth/blob/main/CONTRIBUTING.md#proving-benchmark).

## Concepts

From the [glossary](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md):

- [Claim](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim):
  the signed statement, with its `policyHash`, `subjectHash`, `holder`,
  [salt](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim),
  window, `present` mask, numeric values and byte slots.
- [Registry](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain)
  and [registry slot](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection):
  the pinned keys, one per slot; each signature names its slot and is
  verified against `keys[registryIndex]`.
- [Threshold](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the `N` in N-of-M, and the exact number of signatures the contract takes.
- [Nullifier](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the SHA-256 of the observation identity. Attestors sign it, and it blocks
  replay.
- [Claims vault](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#on-chain):
  the accepted claims, keyed by their nullifier.

## Guarantees and limits

`verifyAttestation` rejects a claim unless all of these hold:

- `version` is `1` (`"Unsupported claim version"`).
- `appId` equals the sealed `appId` (`"App id mismatch"`), so a claim signed
  for another app is rejected even when that app pins the same attestors and
  policy.
- `policyHash` is in the sealed `policyHashes` set (`"Unaccepted policy"`).
  The membership check discloses which accepted policy the claim used.
- `getSignatures` supplies exactly `N` signatures, each named by a registry
  slot. The slots strictly increase (`"Registry slots not increasing"`), so
  none repeats, are below `M` (`"Registry slot out of range"`) and hold a key
  (`"Empty registry slot"`), and every signature verifies against its slot's
  key (`"Insufficient valid signatures"`). One invalid signature fails the
  proof; it is not skipped. Pin at least `N` distinct keys or no claim is ever
  accepted. `initRegistry` rejects duplicate keys (`"Duplicate registry keys"`)
  and a second call (`"Registry already initialized"`).
- Which slots signed stays private. The slots are private inputs, the circuit
  reads every key to select a slot's, and no ledger operation or disclosed
  value depends on a slot.
- Every slot whose flag is false carries zero, numeric slots and byte slots
  alike: an absent byte slot is 32 zero bytes (`"Absent slot has nonzero
  value"`). A measured zero is valid with its flag true.
- The window is not inverted (`"Window inverted"`), is at most `maxWindow`
  long (`"Window too long"`), and the block time is at or after `windowStart`
  (`"Window in the future"`) and before `windowEnd + freshnessWindow`
  (`"Window too old"`). A zero `freshnessWindow` does not disable the check.
- The caller's secret matches `holder` (`"Holder mismatch"`).
- The observation identity has not been accepted before: its nullifier is
  not in the claims vault (`"Observation replay"`). The claim is then vaulted
  under that nullifier.

`openClaim(nullifier)` rejects an unknown nullifier (`"Unknown claim"`), a
caller whose secret does not own the entry (`"Claim not bound to caller"`) and
a witness claim that does not hash to the nullifier (`"Claim does not match
nullifier"`). The holder computes the nullifier off-chain with
`nullifierOf(claim)` from `@txpipe/thoth-core/claim`.

What the module does not check, and what your app does itself:

- `subjectHash` is signed but not compared. To accept only one source, take the
  subject as private input, recompute the hash, and compare it to the opened
  claim's `subjectHash`, pinning only the fields you need (the mock's
  `openAndBindHost` pins the host and keeps the path private). The claim does
  not commit to the evidence behind it (ADR 0007).
- The kind decides the window. Read it as the time the kind's observation
  happened, not as a universal fact timestamp
  ([Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim)
  explains why).
- The module does not check where the `salt` came from. The kind decides it:
  secret when the values are secret or guessable, so the nullifier cannot
  confirm a guess
  ([ADR 0012](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md));
  public when they are public chain data, so the nullifier reveals the event
  ([ADR 0014](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0014-chain-event-kinds.md)).
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
  ([ADR 0012](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
  The ledger stores each claim's nullifier, as its vault key, with its vault
  pseudonym (derived from the holder secret) and window in public, and the transaction
  discloses which accepted policy it used.
- Holder secrets are not checked for freshness. Use a fresh, high-entropy
  secret per claim and keep it to open that claim. Where the salt follows the
  holder, a guessable secret makes the salt guessable too, and the nullifier
  can then confirm guessed values. Reusing a secret links its holder
  commitments and vault entries.
- `openClaim` returns the observation identity, not `holder` or `version`:
  the nullifier does not bind them, so it does not check them, and a predicate
  that reads either one does not compile. Key holder state on the vault
  pseudonym instead.
- The module does not stop your own circuits from writing the claims vault.
  Never insert into or remove from `claimsVault`: an inserted entry is a claim
  no attestor signed, and a removed entry lets the same observation be
  accepted again, because the vault is the replay check. "Use once" rules
  never delete the entry.
- `openClaim` consumes nothing, so opening is repeatable. "Use once"
  rules are your own state, keyed on the vault pseudonym. Never re-export
  `openClaim` as a top-level entry point: its return value is tainted and
  would force a `disclose()` that publishes every value.
- Key provenance is your trust decision; the registry checks only that the
  pinned keys are distinct. The keys are fixed at deploy: to rotate an
  attestor, deploy a new contract.

## Design decisions

- **Attestors sign the nullifier.** The message is the claim's `version`, the
  layout, the nullifier and `holder`; every other field reaches the signature
  through the nullifier. Everything the contract inspects is a field of the
  claim, so a kind cannot pass the contract data through an unsigned side
  channel. A change to the observation identity changes what attestors sign
  ([ADR 0015](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0015-attestors-sign-the-nullifier.md)).
- **Replay protection keys on the observation identity.** The nullifier hashes
  `appId`, `policyHash`, `subjectHash`, `salt`, the window, the values and the
  flags. It does not hash `holder` or `version`. In zkFetch the holder can
  reach it through the kind's salt, so a fresh holder may get a fresh
  nullifier; what stops a fresh holder from re-claiming an observation is the
  kind's evidence binding: a new holder needs new evidence, which gets a new
  nullifier when the salt follows the holder ([Guarantees and limits](#guarantees-and-limits))
  ([ADR 0006](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0006-nullifier-keys-on-the-observation-identity.md),
  [ADR 0011](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0011-evidence-binds-the-claim-context.md)).
- **In zkFetch the nullifier hashes a secret salt.** The salt never reaches the
  ledger, so only those who hold the evidence, such as the witnesses and
  attestors, can confirm a guessed value by recomputing the nullifier; they
  already see the values. The
  attestors derive it from the evidence, so a client cannot vary it to replay
  one observation ([ADR 0012](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
- **The claims vault is keyed by the nullifier.** Vault membership is the
  replay check, and you open a claim with its nullifier and the holder secret,
  so your client keeps no randomness per claim. The vault key reveals no more
  than the nullifier the same transaction publishes; for a chain-event kind
  that is which event the claim attests
  ([ADR 0016](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0016-claims-vault-keyed-by-the-nullifier.md)).
- **No kind on-chain; the policy hash is the commitment.** A requester cannot
  substitute a laxer policy, and a new kind needs no change here: you accept
  it by sealing its policy hash ([ADR 0002](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0002-no-kind-on-chain-policy-hash.md)).
- **A contract seals its app id.** You pass it to the constructor, and the
  contract accepts only claims signed for it. Each contract keeps its own
  replay set, so the nullifier alone would not stop a claim stored in one app
  from being stored again in another
  ([ADR 0013](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0013-contract-seals-its-app-id.md)).
- **A contract seals a set of policy hashes.** One contract serves several
  policies, and so several kinds ([ADR 0008](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0008-contract-accepts-a-set-of-policy-hashes.md)).
- **Source binding is your in-circuit check.** `subjectHash` is a circuit hash
  so your predicate can recompute it from private subject fields
  ([ADR 0001](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0001-source-binding-by-in-circuit-subject-hash.md)).
- **The holder is a per-claim commitment, not an identity.** The pure
  `holderCommitment(secret)` circuit derives it, and `holderCommitmentOf` in
  `@txpipe/thoth-core/claim-context` matches it off-chain. Cross-claim or per-user
  state is your app's ([ADR 0004](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0004-holder-is-per-claim-not-an-identity.md)).
- **The window is when the attestor observed.** The contract checks it against
  block time; a fact's own time is a claim value ([ADR 0005](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0005-window-is-when-the-attestor-observed.md)).
- **A byte value is one `Bytes<32>`.** Compare `c.byteValues[i]` to a
  `Bytes<32>` in-circuit directly; `c.bytePresent[i]` is its flag. The
  message signs `V` and `W`, so a claim signed for another layout is rejected
  even when the two serialize to the same bytes
  ([ADR 0009](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0009-byte-value-slots-in-the-claim.md)).
  How a source string becomes those 32 bytes is the kind's parse rule, not the
  contract's ([ADR 0010](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0010-encoded-byte-rules.md)).
- **The registry checks the N signatures you name.** You send exactly `N`
  signatures, each with the registry slot your trusted set assigned its
  attestor, in slot order, and send no dummy for a slot that did not sign. A
  proof costs `N` signature checks whatever `M` is, and does not reveal which
  attestors signed
  ([ADR 0017](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0017-registry-checks-the-n-named-signatures.md)).
- **The registry's keys are sealed.** `keys` is unexported and only
  `initRegistry` writes it, so the distinctness check cannot be skipped.

## Links

- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): the claim, its wire order and the flow
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md): adding an attestor kind
- [docs/adr/](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/): the decisions behind the modules
- [CONTEXT.md](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md): the glossary
- [CONTRIBUTING.md](https://github.com/txpipe-shop/thoth/blob/main/CONTRIBUTING.md): dev setup and commands
