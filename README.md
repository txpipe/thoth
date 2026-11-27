# Thoth

Private N-of-M attestation for Midnight: your contract accepts an off-chain fact only when N of the M attestors it pinned have signed it, and the fact reaches the contract as private input.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## What it is

Thoth is a set of Compact modules and TypeScript packages. Your Midnight
contract embeds the modules, and your dApp uses the packages to collect
signatures from independent [attestors](CONTEXT.md#roles) and hand them to the
contract as private input.

Thoth fits your app if:

- your contract needs a fact from outside the chain, such as a value from a
  web API;
- you want several independent operators to vouch for it, not one;
- your contract should test the fact in-circuit without publishing it.

It does not fit if a single authority's signature is enough, if you need a
vote or a judgment rather than an observed fact, or if you need verifiable
computation. [docs/DESIGN.md](docs/DESIGN.md#out-of-scope) lists what is out
of scope and why.

## How it works

1. Your dApp obtains evidence of a fact. With the zkFetch
   [kind](CONTEXT.md#kinds), that is a Reclaim zkFetch proof of an HTTPS
   response.
2. Each attestor in your app's [trusted set](CONTEXT.md#signing-and-collection)
   checks the evidence and signs a canonical [claim](CONTEXT.md#the-claim)
   derived from it.
3. Your dApp submits the claim and N signatures to your contract as private
   witness data. The contract checks the signatures against its pinned
   registry, the [policy](CONTEXT.md#the-claim), the window, the
   [holder](CONTEXT.md#the-claim) and replay through the
   [nullifier](CONTEXT.md#on-chain)
   ([full list](packages/contracts/README.md#guarantees-and-limits)).
4. Your contract's predicate runs over the claim values.

Attestors certify facts, not decisions: a claim states what was observed, and
your app defines the predicate over it.

Claim values are private witness data and are not stored on-chain. The public
nullifier hashes them with a [salt](CONTEXT.md#the-claim). In zkFetch the salt is
secret, so an outsider cannot confirm a guessed value from it; a chain-event
kind's salt is public instead, since its values already sit on the chain
([ADR 0014](docs/adr/0014-chain-event-kinds.md)). The contracts README
[says what is public and who holds the salt](packages/contracts/README.md#guarantees-and-limits).

## Which package to use

| Package                                                   | Use it to                                                                    |
| --------------------------------------------------------- | ---------------------------------------------------------------------------- |
| [`@txpipe/thoth-contracts`](packages/contracts/README.md) | Embed N-of-M verification in your Midnight contract                          |
| [`@txpipe/thoth-zk-tls`](packages/zk-tls/README.md)       | Attest a web fact with zkFetch, as a dApp or as an attestor operator         |
| [`@txpipe/thoth-cardano`](packages/cardano/README.md)     | Attest a Cardano chain event, as a dApp or as an attestor operator           |
| [`@txpipe/thoth-client`](packages/client/README.md)       | Write a kind's client: the trusted set and the attestation checks            |
| [`@txpipe/thoth-attestor`](packages/attestor/README.md)   | Write a kind's attestor: pair its [law](CONTEXT.md#kinds) with a signing key |
| [`@txpipe/thoth-core`](packages/core/README.md)           | Write a kind's law against the shared claim types                            |

If you are building a dApp on web data, start with `@txpipe/thoth-contracts` and
`@txpipe/thoth-zk-tls`; on chain data, start with `@txpipe/thoth-contracts` and
`@txpipe/thoth-cardano`. To add a new kind of attestor, follow
[docs/kind-author-guide.md](docs/kind-author-guide.md).

## Quickstart

There is no deploy script; the closest thing to a quickstart is
[`packages/contracts/test/acceptance.test.ts`](packages/contracts/test/acceptance.test.ts):
it runs two zkFetch attestors, collects a 2-of-3 claim, and submits it to the
contract simulator. Run it with the [dev setup](CONTRIBUTING.md#dev-setup) in
place:

```bash
npm install
npm test -- acceptance
```

The path it covers, in short:

```ts
// 1. Each operator runs an attestor that trusts its own Reclaim witness.
const attestors = [
  zkFetchAttestor({ id: 'attestor-0', keyPair: keyPair0, witnessAddress: witness0 }),
  zkFetchAttestor({ id: 'attestor-1', keyPair: keyPair1, witnessAddress: witness1 }),
];

// 2. You deploy your contract: its registry pins the attestors' public keys
//    (seedKeys) and it seals your appId and zkFetchPolicyHashOf(policy)
//    (policyHashes).

// 3. Your dApp collects 2 signatures and places each at its registry slot.
const client = zkFetchClient.init({
  trusted: buildTrustedSet({
    registrySize: 3,
    attestors: attestors.map((a, registryIndex) => ({ attestor: descriptorOf(a), registryIndex })),
  }),
  transport,
  verifier: jubjubVerifier,
  policy,
  appId,
  valueSlots: 3,
  byteSlots: 1,
  provers,
});
const { claim, collected } = await client.collect(request, {
  holder: holderCommitmentOf(holderSecret),
  windowStart,
  windowEnd,
  expiresAt,
  threshold: 2,
  attestorTimeoutMs: 5_000,
});

// 4. Your contract's getAttestationWitness returns toContractClaim(claim), the
//    signatures by slot and a commitment randomness; getHolderSecret returns
//    holderSecret. Then you call verifyAttestation.
```

[`examples/example_app.compact`](packages/contracts/examples/example_app.compact)
is a 2-of-3 contract and the
[test mocks](packages/contracts/test/mocks/) add predicates; the
[dApp guide](packages/zk-tls/docs/dapp-integration.md) and the
[attestor guide](packages/zk-tls/docs/attestor-guide.md) cover each side in
full.

## Midnight City demo

Midnight City is a proof of concept built on Thoth, preserved on the
[`midnight-city-demo`](https://github.com/txpipe/thoth/tree/midnight-city-demo)
branch. It is a demo, not supported code. It is pinned to an older Thoth that
parses identifiers with a temporary `bytes8` rule, which the byte value slots
replace.

## Roadmap

- [`v0`](https://github.com/txpipe/thoth/milestone/1): the work before the first tag.
- [`Next`](https://github.com/txpipe/thoth/milestone/2): what comes after.
- [`frozen`](https://github.com/txpipe/thoth/issues?q=is%3Aissue+label%3Afrozen): ideas for later.

## Links

- [docs/DESIGN.md](docs/DESIGN.md): the architecture, the claim and its wire order
- [docs/kind-author-guide.md](docs/kind-author-guide.md): how to add an attestor kind
- [docs/adr/](docs/adr/): the design decisions and their reasons
- [CONTEXT.md](CONTEXT.md): the glossary
- [CONTRIBUTING.md](CONTRIBUTING.md): dev setup, repo layout and commands
- License: [Apache-2.0](LICENSE), except [`@txpipe/thoth-zk-tls`](packages/zk-tls), which is [AGPL-3.0-only](packages/zk-tls/LICENSE) because it links Reclaim Protocol's AGPL-licensed attestor-core
