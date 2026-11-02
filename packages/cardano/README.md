# @thoth/cardano

The cardano@1 chain-event kind for Thoth, which attests one lovelace output at a watched Cardano address, for dApp developers who act on Cardano deposits and for the operators who run their attestors.

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
  slots: { blockTime: 0, slot: 1, blockNumber: 2, lovelace: 3, outputIndex: 4 },
};

const policyHash = cardanoPolicyHashOf(policy); // 32 bytes
```

The `slots` map says which claim slot each field fills. Slot indices must be distinct.

## Concepts

- [Policy](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the network, its magic, depth, address and slot map. `cardanoPolicyHashOf(policy)` is the claim's `policyHash`.
- Variant: one event shape the policy can describe, tagged by `kind`. `cardano@1` has one variant today, `output`.
- Law: `cardano@1`, the kind's tag. It covers one chain, Cardano, and its hashes include the tag.
- [Subject](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the event's identity: network, address, transaction hash, output index and block hash.
- [Window](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the event's block time.
- Depth: the number of blocks the event's block must sit below the chain tip before the attestor signs. It is part of the policy.
- [Holder](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): a per-claim commitment from `holderCommitmentOf(secret)`.

## Guarantees and limits

What the policy checks:

- `kind` names a known variant. An unknown kind fails and lists the valid kinds.
- `network` is one of `mainnet`, `preview`, `preprod`, `devnet`.
- `networkMagic` is a positive integer up to 2^32−1. For `mainnet`, `preview` and `preprod` it must be the fixed magic: 764824073, 2 and 1. For `devnet` it must not be one of those public magics.
- `address` is a bech32 payment address for that network: `addr1…` for mainnet, `addr_test1…` for the testnets and devnet. The prefix and charset are checked, and the address is lowercased.
- Each slot index is used once in the policy.
- The policy hash commits to every field, including `network` and `confirmationDepth`.

What the policy does not check, and what your app must do:

- **The claim certifies an observation, not ownership.** Any observer can request an attestation for the same event. If your predicate grants something per event, bind the claimant in your circuit.
- **The address must match the network.** The policy checks the prefix, not the network behind it.
- **A testnet address does not say which testnet it is.** Preview and preprod use the same prefix, so an address cannot tell them apart. The attestor compares the node's network magic with `network` before it signs (preview 2, preprod 1, mainnet 764824073).
- **The bech32 checksum is not verified.** A wrong checksum fails at the attestor's read, not in the policy.
- **A devnet policy works only on an undeployed network.** Its magic is set by that network, so no public network can serve it. Don't seal a devnet hash on a public contract, and point your attestors at the network the policy names. The policy can't enforce either.
- **Attestors are assumed to serve every public chain for now.** How an attestor advertises the networks it serves is deferred to the attestor work.
- **`confirmationDepth: 0` is accepted.** An attestation at depth 0 can later be rolled back, and the claim stays on the ledger. Set a depth that covers the risk you accept, and bound the block number or slot in your predicate.
- **The window is the block time, not the attestation time.** Set your `freshnessWindow` to cover the depth wait, the attestation round trips, proof generation and Midnight inclusion, or the claim expires before submission.
- **The salt is public.** Anyone can recompute it from the event, so an observer who suspects an event can confirm the link to a nullifier.
- **One event mints one claim per app and policy.** Replays are stopped by the nullifier. A reorged event is a new fact, so key once-per-event state on `txHash` and `outputIndex`, not on `subjectHash`.

## Design decisions

- **Depth is policy, not law.** Each app sets its own confirmation depth in the policy, so the law does not change when apps need different finality ([ADR 0013](../../docs/adr/0013-chain-event-kinds.md)).
- **One law per chain, one policy variant per event shape.** Adding an event shape adds a variant, not a law, so other chains' hashes never change ([ADR 0013](../../docs/adr/0013-chain-event-kinds.md)).
- **The salt is public, which diverges from ADR 0012.** Chain values are public, so a secret salt would only hide the event linkage ([ADR 0013](../../docs/adr/0013-chain-event-kinds.md), [ADR 0012](../../docs/adr/0012-nullifier-hashes-a-secret-attestor-derived-salt.md)).
- **The window is the event's block time, which diverges from ADR 0005.** Every attestor derives the same window from the block, so they sign the same message ([ADR 0013](../../docs/adr/0013-chain-event-kinds.md), [ADR 0005](../../docs/adr/0005-window-is-when-the-attestor-observed.md)).
- **No witness binds the claim context, which diverges from ADR 0011.** The attestor reads the chain itself, and the window follows from the event, so nothing the client chooses can move it ([ADR 0013](../../docs/adr/0013-chain-event-kinds.md), [ADR 0011](../../docs/adr/0011-evidence-binds-the-claim-context.md)).
- **Each variant is additive.** The variant tag is part of the policy hash, so a new variant does not change existing hashes. See [adding a variant](./docs/adding-a-variant.md).

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth): overall architecture and docs
- [CONTEXT.md](../../CONTEXT.md): the glossary
- [docs/DESIGN.md](../../docs/DESIGN.md): the architecture and the claim
- [docs/kind-author-guide.md](../../docs/kind-author-guide.md): how to add a kind
- [docs/adr/0013-chain-event-kinds.md](../../docs/adr/0013-chain-event-kinds.md): the chain-event kind contract
- [Adding a variant](./docs/adding-a-variant.md): how to add an event shape to this package
- [`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core): the claim and `policyHashOf`
