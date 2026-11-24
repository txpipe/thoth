# @thoth/cardano dApp integration

How to act on a Cardano event from a Midnight dApp: set up the client, write
the policy, collect a threshold of attestations, and hand the claim to the
contract. The [package README](../README.md) defines the
[terms](../README.md#concepts) and lists the
[checks and limits](../README.md#guarantees-and-limits); this guide is the
walkthrough.

## Client setup

`cardanoClient.init` takes:

- **`trusted`.** The attestors your app pins, built with `@thoth/client`'s
  `buildTrustedSet({ registrySize, attestors })`. `registrySize` is your
  contract's `#M`; each member pairs an attestor's descriptor with the
  `registryIndex` of its key in the deployed registry. The attestor does not
  choose its slot.
- **`transport`.** How the client reaches each attestor. You supply an
  `AttestorTransport`; the [@thoth/client README](../../client/README.md#usage)
  gives the recipe. JSON carries neither bigint nor bytes, so the recipe tags
  them with `toJson` and `fromJson`; your attestor's server must decode with
  the same pair, or every reply fails the claim or signature check.
- **`verifier`.** The signature verifier. For Jubjub Schnorr, use
  `jubjubVerifier` from `@thoth/client/jubjub`.
- **`policy`.** The one policy every attestor in the set enforces; see
  [The policy](#the-policy). Its hash is signed into every claim, and your
  contract must seal it.
- **`appId`.** The 32 bytes naming your app, signed into every claim.
- **`valueSlots`.** Your contract's `#V`, the numeric slot count, up to 64.
- **`byteSlots`.** Optional: the number of 32-byte byte values you measure,
  W, up to 64. The contract's `#B` is `2W`, since each value is two 16-byte
  halves. Defaults to `0`.
- **`read`.** Your own read of the event, in the observation shape the client
  and the attestors share. The client awaits it as-is and does not bound it,
  so a provider that hangs holds `collect` open past `expiresAt`. Give the
  provider its own timeout before you build the client.

A complete setup:

```ts
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { cardanoClient } from '@thoth/cardano/client';
import { createDolosSource, readRawEvent } from '@thoth/cardano/dolos';

const source = createDolosSource({ uri: 'http://localhost:50051' }); // your UTxO-RPC endpoint

const client = cardanoClient.init({
  trusted: buildTrustedSet({
    registrySize: 3, // the contract's #M
    attestors: [
      { attestor: descriptorA, registryIndex: 0 },
      { attestor: descriptorB, registryIndex: 1 },
    ],
  }),
  transport, // the @thoth/client README recipe
  verifier: jubjubVerifier,
  policy, // see The policy below
  appId, // 32 bytes
  valueSlots: 3, // the contract's #V
  byteSlots: 1, // one byte value; the contract's #B is 2
  read: (locator) => readRawEvent({ source, ...locator }),
});
```

`createDolosSource` builds a reader over a UTxO-RPC endpoint, and
`readRawEvent` reads one transaction, its block and the tip in one call and
returns the observation. A different provider works if it returns the same
`CardanoObservation`.

`readRawEvent` checks the response's transaction hash against the locator, so
an endpoint that answers with a different transaction is caught before
anything is read. The source is still trusted to describe its own chain
([ADR 0003](../../../docs/adr/0003-colluding-attestors-out-of-scope.md)): the
block it reports is bound into the subject, and each attestor derives the claim
again from its own read, so a client endpoint that invents a block yields a
claim the attestors refuse.

## The policy

`CardanoPolicy` describes what the attestors measure. Today it is the `output`
variant, which watches one lovelace output at one address:

```ts
import { cardanoPolicyHashOf, type CardanoPolicy } from '@thoth/cardano';

const policy: CardanoPolicy = {
  kind: 'output',
  network: 'preview',
  networkMagic: 2, // preview 2, preprod 1, mainnet 764824073
  confirmationDepth: 30,
  address: 'addr_test1…', // the address you watch
  slots: [
    { slot: 0, name: 'blockTime' },
    { slot: 1, name: 'blockNumber' },
    { slot: 2, name: 'lovelace' },
    { slot: 3, name: 'txHash' }, // byte slots start at #V = 3
  ],
};

const policyHash = cardanoPolicyHashOf(policy); // seal this in the contract
```

`slots` is an array of `{ slot, name }` entries:

- Numeric facts fill the first `#V` slots: `blockTime`, `slot`, `blockNumber`,
  `lovelace`, `outputIndex`, and `assetQuantity`, which also needs the policy's
  `asset` pin.
- The byte facts `txHash`, `blockHash` and `addressHash` fill the byte slots
  `#V .. #V+W-1`.
- Each slot index and each fact name appears once. The parser sorts the entries
  by slot, so the order you write them in does not change the hash.
- A slot you do not declare is signed absent: `present` is false and the value
  is zero.

`cardanoPolicyHashOf` parses the policy and hashes it under the `cardano@1` law
and the claim wire version, so the hash commits to every field, including
`networkMagic` and `confirmationDepth`. The contract seals that hash; a claim
under any other policy is rejected. The README's
[Guarantees and limits](../README.md#guarantees-and-limits) lists the field
checks, from the fixed public magics to the address prefix and the duplicate
slot rules.

`cardanoClient.init` rejects a policy whose slots do not fit `valueSlots` and
`byteSlots`, so a policy that parses can still fail at init.

## Collecting a threshold

```ts
import { holderCommitmentOf } from '@thoth/core/claim-context';

const attestment = await client.collect(
  { txHash, outputIndex },
  {
    holder: holderCommitmentOf(secret), // 32 random bytes, fresh per claim
    expiresAt: Date.now() + 60_000,
    threshold: 2, // the contract's #N
    attestorTimeoutMs: 5_000,
  },
);
```

The client reads the event once, derives `windowStart = windowEnd = block.time`,
and every attestor derives the same window from its own read and refuses a
proposal that differs.

The options:

- **`holder`.** A 32-byte commitment from a fresh secret,
  `holderCommitmentOf(secret)`. Keep the secret: the contract binds the vaulted
  claim to it, and opening the claim needs it.
- **`expiresAt`.** A local deadline in Unix milliseconds, not signed. It
  bounds the attestor attempts but not your read.
- **`threshold`.** The number of distinct registry slots that must sign; set
  it to your contract's `#N`.
- **`attestorTimeoutMs`.** The limit for one attestor, covering the transport
  and verification. An attempt is also cut at `expiresAt`.
- **`attestorIds`.** Optional candidate ids in contact order; defaults to the
  trusted set's order. The set must supply at least `threshold` distinct slots.

`collect` reads once, checks its read against the locator and the policy,
derives the claim, and asks the candidates until `threshold` replies verify
against that claim and their pinned keys. It returns `{ claim, collected,
failures }`. `collected` is sorted by registry slot, and each entry carries its
`attestation.signature` and the `registryIndex` it answered from. `failures`
lists the attestors that failed along the way. The client does not check depth;
that is the attestors' alone (see [Depth and finality](#depth-and-finality)).

A collection that cannot reach the threshold throws `CardanoThresholdError`
with a `reason`:

- **`invalid-options`.** The options are malformed or cannot supply `threshold`
  distinct slots: a holder that is not 32 bytes, a non-positive threshold or
  timeout, or unknown ids. It is a bug in the call; fix it instead of retrying.
- **`expired`.** The deadline passed before or during the call. Retry with a
  later deadline only if the event can still land inside the contract's
  `freshnessWindow`: the window is the block time, so every retry spends the
  claim's remaining life.
- **`threshold`.** The candidates ran out before enough signatures verified.
  Read `failures` to choose between a retry and surfacing the problem.

Each failure is `{ registryIndex, reason }` with one of two reasons:

- **`timeout`.** The attestor did not answer inside its limit or the call
  deadline. Retry, possibly with a larger `attestorTimeoutMs` or a later
  `expiresAt`.
- **`attestation`.** The transport failed, the reply did not verify, or the
  attestor signed another claim. A transient transport error may pass on a
  retry. A block that is not deep enough is also this reason, because the
  attestor rejects before it signs, so a first attempt right after the event
  may fail until the chain advances. Repeated `attestation` failures across
  the set mean the attestors are down, on another network, or reading a
  different event; surface that.

No remote error text crosses the boundary: a failed attestor is one of these
two reasons and its slot. Instrument your transport if you need the cause. A
read that throws, or a claim derivation that fails, throws out of `collect`
unchanged; those are your provider's errors, not threshold failures.

## Handing it to the contract

`attestment.claim` is the claim every collected attestor signed, and
`attestment.collected[i]` pairs a signature with the registry slot it answered
from.

```ts
import { toContractClaim } from '@thoth/core/claim';

// In your contract's getAttestationWitness:
return [toContractClaim(attestment.claim), signatures, commitRand];
```

`getAttestationWitness` returns the claim in the contract's shape, one
signature per registry slot, and 32 random bytes for the vault commitment.
Place each `attestment.collected[i].attestation.signature` at that entry's
`registryIndex` in the signature vector; slots you did not collect need a
placeholder signature that never verifies, as the acceptance test does.
`verifyAttestation` rebuilds the signed message with `buildMessage`, counts the
signatures that verify against the sealed registry, and checks the policy hash,
holder, window and nullifier before it vaults the claim. The
[contracts README](../../contracts/README.md#guarantees-and-limits) lists every
check.

- **Seal the policy hash.** Insert `cardanoPolicyHashOf(policy)` into the
  constructor's `policyHashes` set with `disclose`. A claim under another
  policy is rejected before the signature count.
- **Size the module to the slot map.** `#V` is your numeric slot count and
  `#B` is `2W`. `#K` is `14 + 2V + 2B`; the
  [attestation header](../../contracts/attestation.compact) has the layout. For
  the policy above, `#V` is 3, `#B` is 2 and `#K` is 24. The client's
  `valueSlots` must equal `#V`, and `byteSlots` must equal `#B / 2`. `init`
  checks that the slot map fits, not that it matches the deployed contract.
- **Bind the holder in the predicate.** `verifyAttestation` checks
  `claim.holder == holderCommitment(getHolderSecret())` and vaults the claim
  under that holder, so only the secret's owner can submit it. That is not
  ownership of the event: any observer can collect a claim for the same event.
  If your predicate grants the event to a user, bind the claimant in your own
  state, keyed on the vault pseudonym that the module's `holderOf(secret)`
  returns.
- **Size `freshnessWindow` to the claim's age.** `windowStart` and `windowEnd`
  are both the block time, and the contract accepts the claim while block time
  is strictly before `windowEnd + freshnessWindow`. By submission the block is
  already `confirmationDepth` blocks old, plus the attestation round trips,
  proving and Midnight inclusion; size the window to cover all of that or the
  claim expires. A zero-width window fits `maxWindow` 0 when the contract
  accepts only cardano claims.
- **Key once-per-event state on `txHash` and `outputIndex`.** The nullifier
  stops a second acceptance of the same observation, but a reorg moves the
  block and changes the subject, so the re-claimed event is a new claim. Key
  your own once-per-event state on the event's identity fields instead. Both
  are claim values: measure `txHash` and `outputIndex` as slots if the
  predicate reads them.
- **`addressHash` is the address in-circuit.** The policy hash pins the watched
  address and the attestors enforce it. An `addressHash` byte slot puts
  `cardanoAddressHashOf(address)` into the claim, so a predicate can compare it
  when the contract accepts several policies or keys state per address. The
  hash covers the lowercase bech32 string at its exact byte length, so
  recompute it with the same length.

The [contracts README](../../contracts/README.md) covers the module, the
parameters and `openClaim`. The
[acceptance test](../../contracts/test/acceptance-cardano.test.ts) is the
worked seam: two cardano attestors read one event, the client collects the
threshold, and the simulator accepts `toContractClaim`'s output.

## Depth and finality

Set the policy's `confirmationDepth` to the finality you accept. The attestor
checks it against its own tip before signing; the client does not check depth,
because its tip can differ. Depth `0` is accepted and carries the most rollback
risk, so measure `blockNumber` or `slot` and bound it in the predicate if you
need stronger finality. The README lists depth `0` under
[Guarantees and limits](../README.md#guarantees-and-limits);
[ADR 0014](../../../docs/adr/0014-chain-event-kinds.md) has the reasoning.

## Privacy

The salt is public, so a pending submission reveals the event it attests. One
event also mints one claim per app and policy, so an observer can race the first
acceptance: if your predicate grants the event to a user, bind the claimant;
otherwise first-come-first-served is the semantics you chose. The README's
[Guarantees and limits](../README.md#guarantees-and-limits) lists these limits.

## Live check

The live check reads one event from a real UTxO-RPC endpoint, runs one
attestor over that read, and collects a 1-of-1 claim through the client. It
skips unless `DOLOS_URL` names an endpoint, so `npm test` stays offline. Run it
from the repo root after building the packages:

```bash
npm run build
DOLOS_URL=http://localhost:50051 \
  npx vitest run packages/cardano/test/live.test.ts
```

A hosted endpoint takes its key in a header; `DOLOS_HEADERS` is a JSON object
sent on every call:

```bash
DOLOS_URL=https://cardano-preview.utxorpc-m1.demeter.run \
DOLOS_HEADERS='{"dmtr-api-key":"…"}' \
  npx vitest run packages/cardano/test/live.test.ts
```

The endpoint must retain the event's block: a Dolos in ledger-only or
sliding-history mode may not serve it. The default event is the preview
transaction in the recorded fixture; `CARDANO_TX_HASH` and
`CARDANO_OUTPUT_INDEX` name another one, and `CARDANO_CONFIRMATION_DEPTH` sets
the policy depth (default `0`).

The check covers the live read, policy derivation, signing and client
verification. It does not check agreement between independent sources or an
N-of-M set; the
[acceptance test](../../contracts/test/acceptance-cardano.test.ts) covers
those offline.

## Links

- [Package README](../README.md): the policy, the attestor, the guarantees and
  the limits
- [@thoth/client README](../../client/README.md): `buildTrustedSet`, the
  transport recipe and its `toJson`/`fromJson` pair
- [@thoth/contracts README](../../contracts/README.md): the attestation module,
  its parameters and its checks
- [attestation.compact](../../contracts/attestation.compact): the `Claim`
  struct, `buildMessage` and the wire layout
- [ADR 0014](../../../docs/adr/0014-chain-event-kinds.md): the chain-event kind
  contract
- [CONTEXT.md](../../../CONTEXT.md): the glossary
- [cardano acceptance test](../../contracts/test/acceptance-cardano.test.ts):
  the end-to-end seam
- [Adding a variant](./adding-a-variant.md): how to add an event shape to this
  package
