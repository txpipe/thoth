# @txpipe/thoth-core

The keyless types a kind of attestor implements and the claim its attestors sign, for kind authors.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Build it from a checkout of this repo and install it by path, with `zod`:

```bash
git clone https://github.com/txpipe-shop/thoth && cd thoth
npm install && npm run build
cd /path/to/your-app && npm install /path/to/thoth/packages/core zod
```

Once it is published, it installs as `@txpipe/thoth-core`. It needs `zod@^4.6.7` as a peer dependency.

## Usage

A kind is a law: zod schemas for its policy, evidence and claim, a `verify`
step, and a `message` encoding. You write that law against `@txpipe/thoth-core` and
pair it with a key in [`@txpipe/thoth-attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor).

```ts
import type { AttestorDefinition } from '@txpipe/thoth-core';
import { claimSchema, claimToMessage } from '@txpipe/thoth-core/claim';
import { policyHashOf } from '@txpipe/thoth-core/claim-context';
import { z } from 'zod';

const LAW = 'my-kind@1';
const policySchema = z.object({ allowedHosts: z.array(z.string()) });
// `salt`: hex of a secret your source signs with the observation (ADR 0012).
const evidenceSchema = z.object({ host: z.string(), value: z.number(), salt: z.string() });
const claim = claimSchema(1); // one numeric slot, no byte slots

export const definition = {
  kind: LAW,
  policy: policySchema,
  evidence: evidenceSchema,
  claim,
  verify({ policy, evidence, claim }) {
    if (!policy.allowedHosts.includes(evidence.host)) {
      throw new Error(`host ${evidence.host} is not allowed`);
    }
    if (!Buffer.from(claim.policyHash).equals(policyHashOf(LAW, policy))) {
      throw new Error('claim does not commit to this policy');
    }
    if (!claim.present[0] || claim.values[0] !== BigInt(evidence.value)) {
      throw new Error('claim does not match the evidence');
    }
    // A salt the client could choose would let it mint several claims from one observation.
    if (Buffer.from(claim.salt).toString('hex') !== evidence.salt) {
      throw new Error('claim salt is not the one the evidence fixes');
    }
  },
  message: (claim) => claimToMessage(claim),
} satisfies AttestorDefinition<typeof LAW, typeof policySchema, typeof evidenceSchema, typeof claim>;
```

A dApp sends an `AttestationInput` (policy, evidence, claim proposal); the
attestor parses it with the schemas, runs `verify`, signs `message(claim)`, and
returns an `Attestation`. `AttestorDescriptor` is the client-side view of an
attestor: its definition and public key, without key material.

The three entry points:

- **`@txpipe/thoth-core`**: `AttestorDefinition`, `AttestationInput`, `Attestation`, `AttestorDescriptor`, `MessageOf`.
- **`@txpipe/thoth-core/claim`**: `Claim`, `ClaimInput`, `claimSchema`, `bytes32Schema`, `claimToMessage`, `toContractClaim`, `ContractClaim`, `FlatMessage`, `CLAIM_VERSION`.
- **`@txpipe/thoth-core/claim-context`**: `policyHashOf`, `subjectHashOf`, `holderCommitmentOf`, `claimContextDigestOf`, `ClaimContext`, `CanonicalValue`.

## Concepts

- [Kind and law](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds): a kind is a family of attestors sharing one law; the law's versioned tag (`my-kind@1`) is the definition's `kind`.
- [Claim](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the header (version, app id, policy hash, window, subject hash, holder, salt), the `present` mask, and the numeric and byte values. `Claim<V, W>` has `V` numeric slots and `W` byte slots; `W` defaults to `0`.
- [Policy and policyHash](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the rules an attestor enforced; the claim commits to them through `policyHashOf`.
- [Subject and subjectHash](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): what the claim is about, a struct of 32-byte fields hashed by `subjectHashOf`.
- [Holder](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): a per-claim commitment of a secret, from `holderCommitmentOf`.
- [Salt](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): 32 secret bytes the nullifier hashes, derived by your kind from the evidence.
- [Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): when the attestor observed, in Unix seconds.
- [Claim context](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): policy hash, subject hash, holder and window, the part every attestor derives the same claim from.
- [Message and wire layout](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection): the flat field vector the attestors sign and the contract rebuilds; the layout is in the [`attestation.compact`](https://github.com/txpipe-shop/thoth/blob/main/packages/contracts/attestation.compact) header and the [design doc](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md#the-claim).

## Guarantees and limits

What the package checks:

- `claimSchema(v, w)` validates the claim shape and lengths, checks each numeric field fits its contract type (`values` are `Uint<64>`, `windowStart` and `windowEnd` are `Uint<32>`, `version` is `Uint<8>`), coerces numeric fields to `bigint`, and defaults an omitted `byteValues` to `[]`. Without `v` it skips the exact-length checks but still requires one `present` flag per value.
- `claimToMessage` produces the exact message the contract's `buildMessage` rebuilds; the contracts suite checks the parity.
- `toContractClaim` produces the contract's `Claim` struct from a `Claim`. A dApp always converts, even with `W = 0`.
- `policyHashOf` and `claimContextDigestOf` are SHA-256 over a canonical JSON serialization: sorted keys, no whitespace, a `bigint` as a quoted decimal string, bytes as lowercase hex. Another implementation reproduces them from those rules alone.
- `subjectHashOf` and `holderCommitmentOf` are circuit hashes, equal to the circuit's `persistentHash` of the subject struct and its `holderCommitment`, so an app can recompute them in-circuit.

What it does not do:

- It verifies no evidence and signs nothing. `verify` is the kind's job; signing is `@txpipe/thoth-attestor`'s.
- It does not check `appId`. The contract checks it against the app id it seals at deploy.
- It does not derive or check the salt. Your kind's law derives it from the evidence and keeps it secret ([kind author guide](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md#5-the-claim)).
- It does not bind a claim context to evidence. `claimContextDigestOf` only hashes it; your kind has its [witness](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles) sign the digest and its `verify` check it ([kind author guide](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md#5-the-claim)).

What your app must do:

- Use a fresh high-entropy secret per claim. Reusing a secret links claims; the layer promises no cross-claim identity or unlinkability.
- Read the window as when the attestor observed, not as the time of the fact.
- Give a byte slot's two halves the same flag. `toContractClaim` and `claimToMessage` do this from one `present` flag; the contract does not check the pairing.

## Design decisions

- **Claim types are keyless.** `@txpipe/thoth-core` carries no signing key; anything that commits to a message calls the kind's `message()`. Key-holding instances live in `@txpipe/thoth-attestor`.
- **The claim carries no kind.** The policy hash, tagged with the law and wire version, is what the contract checks, so a second kind is a new policy hash served by the same module ([ADR 0002](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0002-no-kind-on-chain-policy-hash.md)).
- **The holder is a per-claim commitment, not an identity.** Only the owner of that claim's secret can vault it; per-user state is yours to build ([ADR 0004](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0004-holder-is-per-claim-not-an-identity.md)).
- **The window is when the attestor observed.** A fact's own time travels as a claim value, and your predicate bounds it ([ADR 0005](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0005-window-is-when-the-attestor-observed.md)).
- **Evidence binds the claim context.** Your kind's witness signs the `claimContextDigestOf` digest with its evidence and your `verify` recomputes it from the proposal, so the holder and window are fixed before the witness observes ([ADR 0011](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0011-evidence-binds-the-claim-context.md)).
- **The nullifier hashes a secret salt your kind fixes.** Your `verify` derives `claim.salt` from the evidence and refuses any other, so a client cannot vary it to mint several claims from one observation. Derive it from something outsiders cannot guess, or the public nullifier confirms guessed values ([ADR 0012](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
- **A `Claim` is not the contract's struct.** A `Claim` has one `present` mask over `V + W` slots; the contract carries each byte value as two 16-byte halves with a flag per half, so you convert with `toContractClaim` before handing it to a witness ([ADR 0009](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0009-byte-value-slots-in-the-claim.md)).
- **`FlatMessage` is the default message type.** A kind that needs another shape gives `message()` another return type; `MessageOf<D>` carries it through the signer, key pair and attestation.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth)
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): the claim and its wire order
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md): how to add an attestor kind
- [CONTEXT.md](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md): the glossary
- [`@txpipe/thoth-attestor`](https://github.com/txpipe-shop/thoth/tree/main/packages/attestor): pairs a definition with a signing key
- [`@txpipe/thoth-contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts): the Compact modules the claim mirrors
