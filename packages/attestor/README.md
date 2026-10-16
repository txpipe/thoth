# @thoth/attestor

The attestor side of Thoth: the interfaces a kind author implements to hold a
signing key and turn verified evidence into a signed claim.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm yet. Build it from a checkout of this repo and install it by path:

```bash
git clone https://github.com/txpipe-shop/thoth && cd thoth
npm install && npm run build
cd /path/to/your-app && npm install /path/to/thoth/packages/attestor
```

It will publish as `@thoth/attestor`; that name may change until the npm scope is settled.

## Usage

You write a kind in three pieces: the keyless law with `defineAttestor`, a
`KeyPair` from your key package, and the instance with `buildAttestor`.

```ts
import { buildAttestor, defineAttestor, descriptorOf } from '@thoth/attestor';
import { claimSchema, claimToMessage } from '@thoth/core/claim';

const law = defineAttestor({
  kind: 'my-kind@1', // the versioned law tag
  policy: myPolicySchema,
  evidence: myEvidenceSchema,
  claim: claimSchema<8>(8),
  verify: async (input) => {
    if (!accepts(input)) throw new Error('rejected');
  },
  message: (claim) => claimToMessage(claim),
});

const attestor = buildAttestor({
  id: 'my-kind-operator-1',
  definition: law,
  keyPair, // from your key package: { publicKey, signer }
  attest: async (definition, signer, input) => {
    const parsed = {
      policy: definition.policy.parse(input.policy),
      evidence: definition.evidence.parse(input.evidence),
      claim: definition.claim.parse(input.claim),
    };
    await definition.verify(parsed);
    const message = definition.message(parsed.claim);
    const signature = await signer.sign(message);
    return { claim: parsed.claim, message, publicKey: keyPair.publicKey, signature };
  },
});

// What you hand to dApps: no signer, no attest.
const descriptor = descriptorOf(attestor);
```

`attest` is yours to write: parse, `verify`, then sign `message(claim)`. Throw
to reject. [`@thoth/zk-tls`](https://github.com/txpipe-shop/thoth/tree/main/packages/zk-tls)
is the reference kind.

## Concepts

- [**Attestor**](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles):
  an entity that verifies evidence under a policy and signs a claim if
  satisfied. `Attestor` is one deployable instance.
- [**Kind** and **law**](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds):
  a family of attestors sharing one law. The law is the keyless
  `AttestorDefinition` from [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core);
  many instances run it.
- [**Claim** and **message**](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim):
  the claim is what the attestor signs; the message is its flat encoding,
  produced by the law's `message(claim)`.
- [**Attestation**](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection):
  what `attest` returns: the claim, the message, the public key and the
  signature.
- [**Registry slot**](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection):
  the position of an attestor's key in an app's registry. The app assigns it
  in its trusted set ([`@thoth/client`](https://github.com/txpipe-shop/thoth/tree/main/packages/client));
  the attestor never knows it.

## Guarantees and limits

- The package runs no checks at runtime. Its one guarantee is by construction:
  `buildAttestor` takes `publicKey` and `signer` from one `KeyPair`, so an
  instance cannot sign under a key that is not its own.
- `descriptorOf` drops `signer` and `attest`; the key material stays behind
  `AttestorSigner.sign`.
- Verifying evidence is the law's `verify`; calling it before signing is your
  `attest`.
- Key generation, storage and the signature scheme belong to the kind's key
  package, not to this one.
- An attestor is trusted individually. If N or more attestors in an app's
  trusted set collude, nothing on-chain stops them
  ([ADR 0003](https://github.com/txpipe-shop/thoth/blob/main/docs/adr/0003-colluding-attestors-out-of-scope.md)).
  The app pins honest, independent operators.

## Design decisions

- **Composition, not inheritance.** A kind is a keyless law, a key boundary
  and an instance, not one class. The law stays plain and serializable, and one
  law serves many deployed instances.
- **`KeyPair` holds a live signer, not serializable key data.** The key
  producer lives in the kind package, which instantiates `PK` and `S` with the
  scheme's wire types (for example `JubjubPoint` from
  `@midnight-ntwrk/compact-runtime`).
- **`attest` belongs to the kind.** This package fixes only the contract:
  parse, `verify`, sign; throw to reject.
- **An instance carries no registry slot.** The signed message binds none, so
  one instance serves any number of registries; each app places it in its own
  trusted set.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth)
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): architecture, the claim and its wire order
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md): how to add an attestor kind
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core): the keyless law this package instantiates with a key
- [`@thoth/client`](https://github.com/txpipe-shop/thoth/tree/main/packages/client): the dApp side that collects attestations
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts): the on-chain registry that verifies signatures by slot
