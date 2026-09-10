# @thoth/attestor

Attestor host types and helpers for the Thoth N-of-M attestation system.

Thoth lets Midnight contracts accept externally attested information with ZK
privacy. `@thoth/attestor` is the *host* side: the interfaces and helpers an
attestor implements and consumes. It is where the signing key lives.

## Install

```bash
npm install @thoth/attestor
```

## What's in it

- `AttestorSigner<S>` — the **key boundary**: a minimal `sign(message)` contract
  for whoever holds the private key. The key itself never leaves an
  implementation (it can be captured in a closure).
- `KeyPair<PK, S>` — the public key paired with its signing boundary, produced
  together from the same private key so they can't be cross-wired.
- `Attestor<D, PK, S>` — a deployable, identifiable instance: `id`, the kind's
  shareable `definition`, its `signer`, its `publicKey`, its `registryIndex`
  (registry slot), and the `attest` lifecycle that verifies then signs.
- `defineAttestor` — keeps `kind` and the schema types as precise literals
  inferred from the object literal.
- `buildAttestor` — a consistency-preserving constructor: takes an `id`, a
  definition, a `KeyPair`, a `registryIndex`, and the kind's `attest` lifecycle,
  and returns the `Attestor`.
- `descriptorOf` — projects an `Attestor` to its client-facing
  [`AttestorDescriptor`](https://github.com/txpipe-shop/thoth/tree/main/packages/core)
  (drops `signer`/`attest`).

## Usage

Concrete attestor kinds are built with `buildAttestor`:

```ts
import { buildAttestor, defineAttestor, descriptorOf } from '@thoth/attestor';
import { claimSchema } from '@thoth/core/claim';

const kindLaw = defineAttestor({
  kind: 'zkTLS',
  policy: /* … */,
  evidence: /* … */,
  claim: claimSchema<8>(8),
  verify: async (input) => { /* throw to reject */ },
  message: (claim) => claimToMessage(claim),
});

const attestor = buildAttestor({
  id: 'zkTLS',
  definition: kindLaw,
  keyPair,                        // produced by the kind's key package
  registryIndex: 0,
  attest: async (definition, signer, input) => {
    const parsed = {
      policy: definition.policy.parse(input.policy),
      evidence: definition.evidence.parse(input.evidence),
      claim: definition.claim.parse(input.claim),
    };
    await definition.verify(parsed);
    const message = definition.message(parsed.claim);
    const signature = await signer.sign(message);
    return {
      kind: definition.kind,
      claim: parsed.claim,
      message,
      publicKey: /* the key pair's public key */,
      signature,
    };
  },
});

// Project to the client-safe descriptor:
descriptorOf(attestor);
```

## Attest function

The attestation lifecycle — parse schemas, `verify`, sign `message(claim)` — is
owned by each kind's package: core and host declare only the interface contract
(*verify before sign, throw to reject*), and each kind supplies its `attest`.

## Design rationale

- **Composition, not inheritance.** A kind is three pieces — the keyless
  `AttestorDefinition` law, the `AttestorSigner` key boundary, and the
  deployable `Attestor` instance — instead of one inherited class. Definitions
  stay plain, stubbable, and serializable, and a single law is reused by many
  deployed instances.
- **The instance and its public key.** The public key is the value the client
  maps to an on-chain registry slot; the `id` is a separate, plain identifier
  for client-side addressing. The keyed machinery (signer + public key) is
  paired into one `KeyPair` at construction, so a wrong public-key pairing is
  impossible rather than caught late at N-of-M verification.
- **KeyPair is host-side; the producer lives in the kind.** `KeyPair<PK, S>`
  describes how the attestor host is put together — it is not a wire shape
  (`@thoth/signatures` holds those). The concrete key producer (`derivePublicKey`,
  the signer, `makeKeyPair(sk)`) belongs to the attestor **kind** package,
  which instantiates these generics with the scheme's wire types.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth) — overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md) — architecture overview, flow, and out-of-scope
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core) — the keyless law this package instantiates alongside keys
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts) — the on-chain registry that verifies the signatures positionally
- [`@thoth/signatures`](https://github.com/txpipe-shop/thoth/tree/main/packages/signatures) — the wire signature scheme types (in progress)