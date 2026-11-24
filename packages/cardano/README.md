# @thoth/cardano

The cardano@1 [chain-event kind](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds) for Thoth, which attests one lovelace output at a watched Cardano address, for dApp developers who act on Cardano deposits and for the operators who run their attestors.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is not on npm. Build it from a checkout of this repo and install it by path:

```bash
git clone https://github.com/txpipe-shop/thoth && cd thoth
npm install && npm run build
cd /path/to/your-app && npm install /path/to/thoth/packages/cardano
```

Its package name is `@thoth/cardano`; that name may change until the npm scope is settled.

## Usage

Describe the output you watch as a policy, then hash it. The hash is the `policyHash` your contract seals:

```ts
import { cardanoPolicyHashOf, type CardanoPolicy } from '@thoth/cardano';

const policy: CardanoPolicy = {
  kind: 'output',
  network: 'preprod',
  networkMagic: 1, // preprod's fixed magic; preview is 2, mainnet 764824073
  confirmationDepth: 30,
  address: 'addr_test1…', // the script address you watch
  slots: [
    { name: 'blockTime', slot: 0 },
    { name: 'slot', slot: 1 },
    { name: 'blockNumber', slot: 2 },
    { name: 'lovelace', slot: 3 },
    { name: 'outputIndex', slot: 4 },
  ],
};

const policyHash = cardanoPolicyHashOf(policy); // 32 bytes
```

The `slots` list says which claim slot each fact fills: numeric facts fill the contract's numeric slots, the byte facts (`txHash`, `blockHash`, `addressHash`) the byte slots after them. Each fact and each slot index may be declared once.

To run an attestor, give it a signing key and a reader bound to your own Cardano endpoint:

```ts
import { cardanoAttestor } from '@thoth/cardano/attestor';
import { createDolosSource, readRawEvent } from '@thoth/cardano/dolos';

const source = createDolosSource({ uri: 'http://localhost:50051' }); // your UTxO-RPC endpoint

const attestor = cardanoAttestor({
  id: 'cardano-preview-1',
  keyPair, // the attestor's signing key
  read: (locator) => readRawEvent({ source, ...locator }),
});
```

`readRawEvent` returns the observation the attestor expects, and checks the response's transaction hash against the locator before reading anything else. The source is still trusted to describe its own chain; the block it reports is bound into the subject (ADR 0003).

The evidence a client sends is only a [locator](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds), `{ txHash, outputIndex }`. The attestor re-reads the output and its block and derives every field that describes the event from that read; the app id, holder and slot counts come from the proposal.

A dApp reads the event once and collects a threshold of attestations. The [dApp integration guide](./docs/dapp-integration.md) covers the client setup, the read's trust boundary, the policy slot map, the failure reasons `collect` reports, and the contract side.

## Concepts

- [Policy](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the network, its magic, depth, address and slot map. `cardanoPolicyHashOf(policy)` is the claim's `policyHash`.
- [Policy variant](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds): one event shape the policy can describe, tagged by `kind`. `cardano@1` has one variant today, `output`.
- [Law](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds): `cardano@1`, the kind's tag. It covers one chain, Cardano, and its hashes include the tag.
- [Observation](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the output and block an attestor read. The claim is derived from it; the client never supplies it.
- [Evidence](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#roles): the locator `{ txHash, outputIndex }`. It points at the event without carrying its values.
- [Subject](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the event's identity: the network magic, the transaction hash, the output index and the block hash. The watched address is pinned by the policy; its hash can fill an `addressHash` byte slot.
- [Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the event's block time.
- [Confirmation depth](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the number of blocks the event's block must sit below the chain tip before the attestor signs. It is part of the policy.
- [Holder](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): a per-claim commitment from `holderCommitmentOf(secret)`.

## Guarantees and limits

What the policy checks:

- `kind` names a known variant. An unknown kind fails and lists the valid kinds.
- `network` is one of `mainnet`, `preview`, `preprod`, `devnet`.
- `networkMagic` is a positive integer up to 2^32−1. For `mainnet`, `preview` and `preprod` it must be the fixed magic: 764824073, 2 and 1. For `devnet` it must not be one of those public magics.
- `address` is a bech32 payment address for that network: `addr1…` for mainnet, `addr_test1…` for the testnets and devnet. The prefix and charset are checked, and the address is lowercased.
- Each slot index and each fact name is used once in the policy.
- The policy hash commits to every field, including `network` and `confirmationDepth`.

What the attestor checks:

- The observed output's `txHash` and `outputIndex` equal the client's locator, its `address` and `networkMagic` equal the policy, and its block sits at least `confirmationDepth` blocks below the tip at read time.
- The claim's `policyHash` is the policy's hash, its version is `1`, its window is the block's time, and its subject, salt, values and `present` flags are the ones derived from the observation.
- Evidence is a strict `{ txHash, outputIndex }`; an `observation` key is refused before the attestor reads anything.
- A claim carries at most 64 numeric and 64 byte slots (`CARDANO_LIMITS`); a larger proposal is refused before its arrays are parsed.

What the client checks:

- It reads the event once and checks its own read against the locator and the policy before it asks any attestor, so a wrong event fails fast with that reason.
- It does not check depth: that is the attestors' alone, since two tips can differ without a fork.
- A collection returns as soon as the threshold signs, reports each failed attestor with a safe reason (`attestation` or `timeout`, never remote error text), and bounds each attempt by `attestorTimeoutMs` and the deadline, not the read.

What the policy does not check, and what your app must do:

- **The claim certifies an observation, not ownership.** Any observer can request an attestation for the same event. If your predicate grants something per event, bind the claimant in your circuit.
- **The address must match the network.** The policy checks the prefix, not the network behind it.
- **A testnet address does not say which testnet it is.** Preview and preprod use the same prefix, so an address cannot tell them apart. The attestor compares the node's network magic with `network` before it signs (preview 2, preprod 1, mainnet 764824073).
- **A devnet policy works only on an undeployed network.** Its magic is set by that network, so no public network can serve it. Don't seal a devnet hash on a public contract, and point your attestors at the network the policy names. The policy can't enforce either.
- **The attestor trusts its own read.** `read` is operator configuration; point it at your own independent Cardano source (ADR 0003).
- **Attestors are assumed to serve every public chain for now.** How an attestor advertises the networks it serves is deferred to the attestor work.
- **`confirmationDepth: 0` is accepted.** An attestation at depth 0 can later be rolled back, and the claim stays on the ledger. Set a depth that covers the risk you accept, and bound the block number or slot in your predicate.
- **The window is the block time, not the attestation time.** Set your `freshnessWindow` to cover the depth wait, the attestation round trips, proof generation and Midnight inclusion, or the claim expires before submission.
- **The salt is public.** Anyone can recompute it from the event, so an observer who suspects an event can confirm the link to a nullifier.
- **One event mints one claim per app and policy.** Replays are stopped by the nullifier. A reorged event is a new fact, so key once-per-event state on `txHash` and `outputIndex`, not on `subjectHash`.

## Design decisions

- **Depth is policy, not law.** Each app sets its own confirmation depth in the policy, so the law does not change when apps need different finality ([ADR 0014](../../docs/adr/0014-chain-event-kinds.md)).
- **One law per chain, one policy variant per event shape.** Adding an event shape adds a variant, not a law, so other chains' hashes never change ([ADR 0014](../../docs/adr/0014-chain-event-kinds.md)).
- **The salt is public, which diverges from ADR 0012.** Chain values are public, so a secret salt would only hide the event linkage ([ADR 0014](../../docs/adr/0014-chain-event-kinds.md), [ADR 0012](../../docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
- **The watched address is a policy pin and an `addressHash` fact.** The policy hash seals the address the attestors enforce; the `addressHash` fact carries the same address into the claim, so an app's predicate can read it in-circuit.
- **The window is the event's block time, which diverges from ADR 0005.** Every attestor derives the same window from the block, so they sign the same message ([ADR 0014](../../docs/adr/0014-chain-event-kinds.md), [ADR 0005](../../docs/adr/0005-window-is-when-the-attestor-observed.md)).
- **No witness binds the claim context, which diverges from ADR 0011.** The attestor reads the chain itself, and the window follows from the event, so nothing the client chooses can move it ([ADR 0014](../../docs/adr/0014-chain-event-kinds.md), [ADR 0011](../../docs/adr/0011-evidence-binds-the-claim-context.md)).
- **Evidence is a locator, not the payload.** The client points at an event; the attestor re-reads it and derives every field that describes the event, so client input can only choose what to attest, never what the claim says ([ADR 0014](../../docs/adr/0014-chain-event-kinds.md), [ADR 0007](../../docs/adr/0007-no-evidence-commitment.md)).
- **Each variant is additive.** The variant tag is part of the policy hash, so a new variant does not change existing hashes. See [adding a variant](./docs/adding-a-variant.md).

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth): overall architecture and docs
- [CONTEXT.md](../../CONTEXT.md): the glossary
- [docs/DESIGN.md](../../docs/DESIGN.md): the architecture and the claim
- [docs/kind-author-guide.md](../../docs/kind-author-guide.md): how to add a kind
- [docs/adr/0014-chain-event-kinds.md](../../docs/adr/0014-chain-event-kinds.md): the chain-event kind contract
- [dApp integration guide](./docs/dapp-integration.md): client setup, the policy slot map, collecting a threshold, handing the claim to the contract, and the live check
- [Adding a variant](./docs/adding-a-variant.md): how to add an event shape to this package
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core): the claim and `policyHashOf`
