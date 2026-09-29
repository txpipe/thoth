# @thoth/contracts

The Thoth Compact on-chain layer: the embeddable Compact module set that
verifies N-of-M attestations in-circuit. This is the on-chain counterpart to
the TypeScript packages — `@thoth/core` defines the claim law this layer
verifies, `@thoth/attestor` hosts the signing keys, and `@thoth/client` is how
a dApp addresses the attestors. Distributed as an npm package of **Compact
source modules**. There is nothing compiled here — you embed the modules into
your own `.compact` contracts and compile as part of your own DApp build.

| File | Module | Role |
|------|--------|------|
| `attestation.compact` | `attestation<#K, #V, #N, #M>` | Verifies N-of-M signatures over a flat signed message, controls replay (`nullifiers`) and the observation window (`maxWindow`, `freshnessWindow`), stores a `claimsVault` entry keyed by `persistentCommit(claim, rand)`. The claim can be opened at any time to access the values. |
| `attestor_registry.compact` | `attestor_registry<#M, #K>` | Pinned attestor public keys (sealed) + `countValidSignatures` over a `Vector<K, Field>` message, verified with the stdlib `jubjubSchnorrVerify` (compiler ≥ 0.32; developed against 0.34.0). Counts only — no threshold |

The modules form a single import graph (`attestation` → `attestor_registry`), so
they are always installed as one package. Import them by path from your
contract; do not copy them into your project (you would then be forking the
attestation semantics).

## Installation

```bash
npm install --save-dev @thoth/contracts
```

Or, in a workspace monorepo, add `"@thoth/contracts": "*"` to your package's
`dependencies` and `npm install`.

## Embedding

Compact resolves `import "..."` relative to the importing file's directory
first, then through `--compact-path` / `COMPACT_PATH`. The simplest recipe is a
**path import directly into the package**, which resolves transitively because
the modules live as siblings inside the package directory:

```compact
pragma language_version >= 0.22;

import CompactStandardLibrary;

//            K=17 msg fields  V=3 values  N=2 threshold  M=3 signatures
import "node_modules/@thoth/contracts/attestation"<17, 3, 2, 3> prefix A_;

import "node_modules/@thoth/contracts/attestor_registry"<3, 17> prefix R_;
```

If the package is hoisted elsewhere by your package manager, add the package
directory to the compact path instead and import by module name:

```bash
export COMPACT_PATH="$(node -p 'require.resolve("@thoth/contracts/package.json").replace(/package.json$/, "")')"
```

```compact
import "attestation"<17, 3, 2, 3> prefix A_;
import "attestor_registry"<3, 17> prefix R_;
```

See `examples/example_app.compact` for a complete top-level embedding that
pins registry keys, the accepted policy hashes, the freshness window, and the
maximum observation window in the constructor, re-exports the module types/ledgers/pure circuits, and exports a
`verifyAttestation` entry point.

## Module parameters

`attestation<#K, #V, #N, #M>` — embed as `import "attestation"<K, V, N, M>`:

- `#K` — signed-message length in fields (`K` must equal `2*V + 11`)
- `#V` — number of claim value slots (`Claim.values: Vector<V, Uint<64>>`)
- `#N` — the app's N-of-M threshold
- `#M` — number of attestor signatures supplied / registry key slots

All are fixed when a contract embeds the module.

## The signed message (contract law)

`buildMessage` (`attestation.compact`) flattens a `Claim` into exactly
`Vector<K, Field>` fields, in this order:

```
[ version,
  appId[0..16] as Uint<128>, appId[16..32] as Uint<128>,
  policyHash[0..16] as Uint<128>, policyHash[16..32] as Uint<128>,
  windowStart, windowEnd,
  subjectHash[0..16] as Uint<128>, subjectHash[16..32] as Uint<128>,
  holder[0..16] as Uint<128>, holder[16..32] as Uint<128>,
  present[0] as Field, ..., present[V-1] as Field,
  values[0] as Field, ..., values[V-1] as Field ]
```

[docs/DESIGN.md, "The claim"](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md#the-claim)
gives the same order with field indices.

The attestor MUST reproduce this exact flat field vector to sign the same
message (same order, sizes, presence-flag semantics, and the split of each
32-byte field into two 16-byte halves, so every byte is signed). `present` is a
`Vector<V, Boolean>`: one flag per value slot; `present[i] = true` means
`values[i]` was populated (its value may still be `0`). The message length is `K = 11 + 2*V` (11 header fields, V
presence flags, V values) — fixed when a contract embeds the module.

`verifyAttestation` rejects a claim with `present[i] = false` and `values[i] != 0`
with `"Absent slot has nonzero value"`. Absent slots must carry zero, so their
unused values cannot distinguish observations for replay protection. A measured
zero remains valid with `present[i] = true`.

## Design notes

- **The claim is the entire message.** Everything the contract inspects —
  the observation window (`windowStart`, `windowEnd`), source binding
  (`subjectHash`), caller binding (`holder`), the policy (`policyHash`), the app (`appId`), and the
  version — is inside the signed field vector.
  Kinds must not rely on un-signed side-channels: any data the contract needs
  has to be a field of the message the attestor signs.
- **Replay protection follows the observation identity.** The nullifier is
  `persistentHash` of a struct containing `appId`, `policyHash`, `subjectHash`,
  `windowStart`, `windowEnd`, `values`, and `present`, in that order. It excludes
  `holder` and `version`. The claim carries no nonce. Re-attesting the same
  observation for a fresh holder or using fresh vault commitment randomness
  still fails with `"Observation replay"` (ADR 0006). Presence flags distinguish
  an absent slot from a measured zero.
- **No kind on-chain; the policy is the commitment.** The claim carries no
  kind code. `policyHash` binds it to the policy the attestors enforced, and
  `verifyAttestation` rejects a claim whose `policyHash` is not in the sealed
  `policyHashes` set (`"Unaccepted policy"`), so a requester cannot substitute
  a laxer policy. A contract serves several policies, and so several kinds, by
  sealing one hash per policy. The membership check discloses which accepted
  policy a claim used. `appId` is signed but not checked by the module; an app
  that needs it compares it in its own predicate.
- **The window is when the attestor observed** (ADR 0005), not when the fact
  happened; a fact's own time travels as a claim value. `verifyAttestation`
  checks it against block time, unconditionally: the window must not be
  inverted (`"Window inverted"`) nor longer than the sealed `maxWindow`
  (`"Window too long"`), the block time must be at or after `windowStart`
  (`"Window in the future"`) and before `windowEnd + freshnessWindow`
  (`"Window too old"`). A zero `freshnessWindow` does not disable the check:
  the claim must then land while its window is still open. The vault entry
  stores the window next to the holder.
- **Source binding is the app's in-circuit check.** `subjectHash` is a circuit
  hash (`persistentHash`) of what the claim is about, such as a zkFetch
  request. The module signs it but does not check it. An app that must accept
  only one source takes the subject fields as private input, recomputes the
  hash, compares it to the opened claim's `subjectHash`, and pins only the
  fields its policy needs (the mock's `openAndBindHost` pins the host and keeps
  the path private). The claim does not commit to the evidence behind it, so
  it cannot be audited against the transcript offline (ADR 0007).
- **The holder is a per-claim commitment, not an identity.** The pure
  `holderCommitment(secret)` circuit derives it as a `persistentHash` over a
  tagged holder secret; `@thoth/core/claim-context`'s `holderCommitmentOf`
  matches it off-chain. Its tag differs from the vault pseudonym
  (`deriveHolder`), so one secret yields unrelated values in the two roles. A
  claim signs this commitment as `holder`. `verifyAttestation` requires
  `claim.holder == holderCommitment(getHolderSecret())` or fails with
  `"Holder mismatch"`. The same secret derives the vault pseudonym. Use a fresh,
  high-entropy secret per claim and keep it for opening that claim. Reusing a
  secret links its commitments and vault entries; the module does not enforce
  freshness of secrets or promise cross-claim unlinkability. Cross-claim or
  per-user state belongs to the app (ADR 0004).
- **Registry slots are positional.** `attestor_registry` verifies
  `signatures[i]` against `keys[i]` — a signature is valid *only* in the slot
  holding its signer's public key. Placement is the app's: the client's trusted
  set records each attestor's slot in this registry, and each collected
  signature goes at that slot.
- **A new kind needs no change here** as long as it signs the standard claim:
  an app accepts it by sealing its policy hash. See
  [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md).

## Reading presence in-circuit

`present` is native `Vector<V, Boolean>`, so an app predicate over a vaulted
claim reads any slot directly:

```compact
const c = A_openClaim(id);
assert(c.present[0], "slot 0 must have been measured");
```

Because presence is part of the signed message, a claim whose `present[i]`
flag disagrees with an asserted predicate can never pass signature verification.

## Deploy wiring

`freshnessWindow`, `maxWindow` and `policyHashes` (Attestation) and `keys` (Registry) are
**sealed** ledgers set exactly once in the top-level constructor. Fill
`policyHashes` by inserting each accepted policy hash there; no circuit can add
one after deploy. See `examples/example_app.compact`
for the full wiring.

## Opening a vaulted claim

`attestation.openClaim(id): Claim` proves the caller owns a vaulted claim
(claimsVault membership + holder match + `persistentCommit(claim, commitRand)
== id`) and re-hydrates the `Claim` in-circuit. Apps compose predicates over the
returned `Claim` inside their own circuits — one open, read any subset of
`values[i]` (attestors signed the whole claim).

- **Never re-export `openClaim` as a top-level contract entry point.** Its
  return value is witness/ledger tainted; a top-level export would force a
  `disclose()` that publishes every value on-chain. Compose it in-circuit only.
- **Consumes no nullifier** — opening is repeatable. "Use once" rules (e.g. the
  same claim can mint a given badge at most once) are enforced by the **app's
  own state** (`Set`/`Counter`/map), not by claim nullification.
  Observation replay (depositing the same attested fact twice) is already prevented by `verifyAttestation`.

## Notes / open questions

- Reusability across apps: the claim shape is positional (`values: Vector<V, Uint<64>>`)
  plus per-slot `present` flags. It is simple enough that any app can parse it, but the
  *meaning* of each slot is app-defined. There is no per-value tag in the signed
  message; the policy that produced the claim is identified by `policyHash`.

## Development

```bash
npm install                 # from the repo root (workspace)
npm test                    # compiles the mock (--skip-zk), runs vitest
npm run check               # biome + compact format
```

The package's own test suite uses the mock top-level embedding in
`test/mocks/MockAttestation.compact`; it exercises the modules and is not
shipped with the package.
