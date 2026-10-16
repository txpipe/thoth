# @thoth/core

Core types and definitions for the Thoth N-of-M attestation system.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/core` is the shared, **keyless** contract law: the claim shape,
the attestor definition schemas, and the client-facing attestor descriptor. It
carries no signing key and no host machinery, those live in
[`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor).

## Install

```bash
npm install @thoth/core
```

## What's in it

The package exposes three entry points:

- **`@thoth/core`**:
  - `AttestationInput<P, E, C>` — the raw policy / evidence / claim submitted to an attestor
  - `AttestorDefinition<K, P, E, C>` — the shareable, keyless law a kind of attestor implements: zod schemas for `policy`/`evidence`/`claim`, plus `verify` (decide whether to attest) and `message` (encode a claim into the message type)
  - `AttestorDescriptor<D, PK>` — the client-facing face of an attestor: everything a client needs to address it
  - `Attestation<C, PK, S>` — the signed artifact an attestor produces and a client collects
- **`@thoth/core/claim`**:
  - `Claim<V, W>` / `ClaimInput<V, W>` — the canonical claim: header (version, appId, policyHash, windowStart, windowEnd, subjectHash, holder), a `present` mask (`V` numeric slots then `W` byte slots), `V` numeric `values`, and `W` 32-byte `byteValues`. `W` defaults to `0`
  - `claimSchema<V, W>` — a zod schema that validates and coerces a raw claim payload into the canonical claim shape (`W` defaults to `0`; an omitted `byteValues` defaults to `[]`). Call it with no arguments when `V`/`W` are unknown at parse time: the exact-length constraints are then skipped, but `present` must still have one flag per value
  - `bytes32Schema` — a zod schema for the claim's 32-byte `appId`, `policyHash` and `subjectHash`
  - `claimToMessage` — encode a parsed `Claim` into the exact `FlatMessage` the contract's `buildMessage` verifies
  - `toContractClaim` / `ContractClaim` — convert a parsed `Claim` into the contract's `Claim` struct, the shape a dApp's `getAttestationWitness` returns
  - `FlatMessage` — a Compact `Vector<K, Field>` as a `readonly bigint[]`
- **`@thoth/core/claim-context`**:
  - `policyHashOf(law, policy, version?)` — hash a kind's policy, tagged with its law and the wire version
  - `subjectHashOf(fields)` — hash a kind's subject struct; equals the circuit's `persistentHash` of that struct
  - `holderCommitmentOf(secret)` — the per-claim holder commitment of a holder secret; equals the circuit's `holderCommitment`
  - `claimContextDigestOf(context)` — the hash of a `ClaimContext` that every witness signs into its context

Kind identity belongs to `AttestorDefinition`. An attestation carries the
claim, message, public key, and signature; callers already have the definition
of the attestor they queried. For standard claims, `policyHashOf` commits to
the law tag, policy, and wire version inside the signed claim.

### The flat message type

`FlatMessage` is the **default** signed-message type. It's the default for a
`Msg` generic threaded through `AttestorDefinition`, `AttestorSigner`, `KeyPair`
and `Attestation`, so a standard kind never mentions it. A kind that needs a
different message shape opts in by giving its `message()` another return type
(derived via `MessageOf<D>`), and the whole host stack agrees with the
definition. `claimToMessage` is the canonical encoder for the standard shape —
it mirrors the contract's `buildMessage` byte-for-byte, guarded by the parity
test in the contracts suite.

```ts
import { claimSchema, claimToMessage } from '@thoth/core/claim';
import type { AttestorDefinition } from '@thoth/core';

// A kind's definition uses the claim schema as its claim law.
const def: AttestorDefinition<'my-kind@1', z.ZodType, z.ZodType, z.ZodType> = {
  kind: 'my-kind@1', // the kind's versioned law tag
  policy: /* … */,
  evidence: /* … */,
  claim: claimSchema<8>(8),
  verify: () => {},
  message: (claim) => claimToMessage(claim),
};
```

### The claim shape vs the wire shape

The front-facing claim and the contract's stored claim are deliberately
different shapes. A `Claim` addresses every slot with **one** `present` mask of
length `V+W` — numeric slots first, byte slots after — because that is the seam
a kind reasons about. The contract instead stores each byte value as two
adjacent 16-byte halves and carries a flag per half (`bytePresent`, `B = 2W`);
the per-half flag exists because a `W = 0` specialization must still compile and
Compact cannot index a zero-length vector
([ADR 0009](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0009-byte-value-slots-in-the-claim.md)).
`claimToMessage` bridges the two on the wire and `toContractClaim` in the
witness: both duplicate each byte slot's flag onto both halves and split each
`byteValues[i]` into bytes 0–15 / 16–31, so the contract's `buildMessage` over
the converted claim equals `claimToMessage`'s output (guarded by the parity
tests). A `Claim` is not the witness shape even with `W = 0`, so a dApp always
converts it before handing it to the contract. The same
whole-vs-split pattern already applies to the header fields, which are whole in
the claim and split into halves on the wire. Two invariants follow: honest
claims always give a byte slot's two halves the same flag, and no production
path converts a stored (contract-shaped) claim back into a `Claim` — apps read a
stored claim via `openClaim` and use its halves directly.

### The claim context

The claim-context helpers are shared by every kind; each kind supplies its own
policy and subject structs. `policyHashOf` is SHA-256 of the canonical
serialization of `[law, version, policy]`; `claimContextDigestOf` is SHA-256 of
`['thoth:claim-context', context]`. Both use the same canonical serialization:
JSON with sorted keys and no whitespace, a `bigint` as a quoted decimal string,
and bytes as lowercase hex. Another implementation reproduces them from those
rules alone. `subjectHashOf` is a circuit hash instead, because an app
recomputes the subject hash in-circuit from private fields. It requires a
subject struct whose fields are all `Bytes<32>`. `holderCommitmentOf` is a
circuit hash for the same reason: the contract re-derives the holder from the
caller's secret. Its tag keeps it apart from the vault pseudonym the contract
derives from the same secret. A claim carries this commitment as `holder`;
the contract requires the caller to know its secret. Use a fresh high-entropy
secret per claim. Secret reuse links claims; the layer makes no cross-claim
identity or unlinkability promise.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — design overview, the claim and its wire order
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md) — how to add an attestor kind on top of this package
- [`@thoth/attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor) — the host (key boundary, instances)
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain Compact modules the claim shape mirrors
