# Cardano output

One lovelace UTxO (unspent transaction output) at a watched Cardano address,
attested by the `cardano@1` chain-event kind.

## Source

The attestor reads the event from its own Cardano data node, a Dolos service.
`createDolosSource` from `@txpipe/thoth-cardano/dolos` connects to a UTxO-RPC
endpoint, and `readOutputObservation` reads the output, its block and the
node's tip from it ([package README](../../packages/cardano/README.md)).
The client reads the event once to check its own read against the locator and
the policy before it contacts an attestor.

The example watches a preview address. The policy's network and magic name the
chain; for mainnet use `network: 'mainnet'` and `networkMagic: 764824073`.

## Request

The client's evidence is a locator: an output reference.

- Locator: `{ txHash, outputIndex }`, naming one output. The example uses
  `65d12c1a8204919d850739e9edac795dd69afcf09fd6d77d85c1ffae76fdfe8f:0`.

Once contacted, an attestor reads the event from its own source and
derives the claim.
The client chooses the event through the locator, but every value of the
claim comes from the attestor's own read.

## Policy

```ts
import { cardanoPolicyHashOf, type CardanoPolicy } from '@txpipe/thoth-cardano';

export const policy: CardanoPolicy = {
  kind: 'output',
  network: 'preview',
  networkMagic: 2,
  confirmationDepth: 30,
  address:
    'addr_test1qpsuxemj2fmw6h3w42cdmc6cpu0fz68p9clyudx6p68xa3qxnsdv46lhvyng372rnslvuaw80gnqd3tru8yet2mgakxsf9yv63',
  slots: [
    { slot: 0, name: 'blockTime' },
    { slot: 1, name: 'blockNumber' },
    { slot: 2, name: 'lovelace' },
    { slot: 3, name: 'txHash' }, // byte slots start at #V = 3
  ],
};

export const policyHash = cardanoPolicyHashOf(policy);
```

The contract needs three numeric slots (`#V` 3) and one byte value (`#B` 2;
each 32-byte value is two 16-byte halves). It seals `policyHash`. Add
`outputIndex` to the slot map if your predicate reads it in-circuit.

## What it certifies

At the event's block time, the watched address received the output at
`txHash:outputIndex` worth `lovelace` lovelace, and the block holding it sat at
least `confirmationDepth` blocks below the attestor's tip when it read. The
claim carries the block time, block number, lovelace amount and transaction
hash; the policy pins the network, the address and the depth. The output can be
a script or key address; the app decides which it accepts.

## Limits

- The claim certifies an observation, not finality. A reorg can roll the block
  back; set `confirmationDepth` to the risk you accept and bound `blockNumber`
  or `slot` in your predicate
  ([ADR 0014](../adr/0014-chain-event-kinds.md)).
- The claim certifies the event, not ownership. The locator is public, so any
  observer can request the same event. Bind the claimant in your predicate if
  you grant something per event.
- The attestor trusts its own source. Attestors that share one endpoint count
  as one; point each at an independent source
  ([ADR 0003](../adr/0003-colluding-attestors-out-of-scope.md)).
- The salt is public: the [nullifier](../../CONTEXT.md#the-claim) reveals which
  event the claim attests. One event mints one claim per app and policy, so key
  once-per-event state on `txHash` and `outputIndex`, not on `subjectHash`; a
  reorg changes the subject.
- The [window](../../CONTEXT.md#the-claim) is the event's block time, not the
  attestation time. Size the contract's `freshnessWindow` to cover the depth
  wait, the attestation round trips and Midnight inclusion, or the claim
  expires before submission.
- Preview and preprod share the `addr_test1` prefix; the policy's
  `networkMagic` distinguishes them. A devnet policy works only on that devnet.
  `confirmationDepth: 0` is accepted and carries the most rollback risk.

The package README's
[Guarantees and limits](../../packages/cardano/README.md#guarantees-and-limits)
lists the full set.
