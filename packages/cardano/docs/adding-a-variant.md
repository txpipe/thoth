# Adding a variant

A variant is one event shape `cardano@1` can describe, such as the `output` variant that exists today. Each variant is a folder under `src/` that supplies what differs for that shape; the law-level pieces stay shared.

- `src/policy.ts`: the law tag, networks, `CardanoPolicyBase`, the fact and slot types (`CardanoFact`, `CardanoSlot`), the shared validators, and `policyHashOfCardano`.
- `src/bytes.ts`: the 32-byte field encoders and `cardanoAddressHashOf`.
- `src/index.ts`: the policy union and hash, the claim schema, `deriveCardanoClaim`, and the law-level locator and observation aliases.
- `src/attestor/`: the law and the attestor instance.

Read `src/output/` beside this guide: it implements every piece below.

## What a variant provides

A client reads the locator and derives the claim; each attestor re-reads the event, verifies the proposal and signs. The variant supplies:

| Piece | What it is | What it decides |
|-------|------------|-----------------|
| Policy (`index.ts`) | The app's commitment: the chain, the depth, the pins it watches and the slot list | Which events qualify, and where their facts land in the claim |
| Locator (`index.ts`) | The evidence the client sends | Which event to attest |
| Observation (`index.ts`) | The event and block an attestor read | Every value and the window the claim carries |
| Subject (`index.ts`) | The event's identity as 32-byte fields | Which event the claim is about |
| Salt (`index.ts`) | A tagged hash of that identity | Keeps one kind's salts apart; replay is the nullifier's job |
| Claim derivation (`index.ts`) | Observation and policy turned into a claim | The exact claim every attestor signs |
| Checks (`verify.ts`) | Locator, policy, depth and claim checks | What an attestor refuses |

## The policy

A variant's policy extends `CardanoPolicyBase` (`network`, `networkMagic` and `confirmationDepth`) with its own `kind`, the pins the app fixes about the event, and `slots`.

- `kind` names the variant and rides in the policy hash, so two variants never share a commitment.
- The pins are what the app fixes about the event, such as the output variant's `address` and its optional `asset`. Validate them with the shared helpers: `checkNetworkMagic` for the magic, and `checkAddressMatchesNetwork` for each address (pass `path` when the variant pins more than one).
- `slots` maps each fact the app measures to one claim slot. Name only the facts this variant's read fills, so a policy cannot ask for a value the read would never produce.

Every variant's slot list has this shape:

```ts
// One entry per fact: no duplicate slot index and no duplicate fact name.
slots: z
  .array(
    z.strictObject({
      slot: numericSlotSchema,
      name: z.enum([/* the facts this variant's read fills */]),
    }),
  )
  .min(1)
  .superRefine((slots, context) => {
    checkSlotIndicesDistinct(slots, context);
    checkSlotNamesDistinct(slots, context);
  }),
```

Build the schema as a strict object, refine the whole policy with the shared checks, and normalize before hashing: `addressSchema` lowercases an address, and a final `.transform` sorts `slots` by index, so the hash does not depend on the order you wrote the entries in. Give the policy a hash function that parses it and delegates to `policyHashOfCardano`.

The schema cannot check that a slot fits the contract's claim size, because the size comes with the client's proposal. `assertPolicySlotsInRange` checks it at derivation and verify, and `cardanoClient.init` checks it when the client starts.

Refuse a pin and fact combination the read cannot measure, as the output variant does for `assetQuantity` without the `asset` pin.

## The locator

The locator is the evidence the client sends: the minimal fields an attestor needs to find the event, such as a transaction hash and output index. Keep it strict and small.

The attestor re-reads the event from its own source and derives every field that describes the event from that read, so the locator can only choose which event to attest, never shape the claim ([ADR 0007](../../../docs/adr/0007-no-evidence-commitment.md), [ADR 0014](../../../docs/adr/0014-chain-event-kinds.md)). A strict schema also rejects an `observation` key the client adds.

## The observation

An observation is what one attestor's `read` returns: the network magic of the node it queried, the tip at read time, the block the event landed in, and the event's own values.

Validate it strictly, so a reader that returns a missing, extra or badly encoded field fails before anything is signed. Fix the encodings, because every attestor must derive the same claim from the same chain state: lowercase hex hashes, bigint amounts, and whole-second times.

## The subject

The subject is the event's identity: the fields that make it unique on the chain.

Encode each field as 32 bytes in the order the circuit struct declares. Build them with `bytes32OfUint32`, `bytes32OfHex` and `bytes32OfText`, and hash them with `subjectHashOf`. An app passes the fields as private input and recomputes `subjectHash` in-circuit, so the order and the encoding are both part of the contract ([ADR 0001](../../../docs/adr/0001-source-binding-by-in-circuit-subject-hash.md)). Use `cardanoAddressHashOf` to turn an address into the `addressHash` byte fact.

## The salt

The salt is a tagged hash of the event's identity, for example `thoth:cardano-salt:v1` followed by the identity fields. It is public for a chain-event kind, because the event's values are public chain data, so it hides nothing; the tag separates it from the subject and from other kinds' hashes ([ADR 0014](../../../docs/adr/0014-chain-event-kinds.md)). Replay is the nullifier's job.

Derive the salt from the read, never from the proposal. The attestor refuses a proposal whose salt differs.

## The claim derivation

`deriveCardanoClaim` is the law-level entry. The variant exports the function that fills one event, and the law-level one calls it.

Take only `appId`, the holder and the slot counts from the proposal. Every other field comes from the observation and the policy, so the client cannot write the claim: the version is `CLAIM_VERSION`, the window is the block time (`windowStart = windowEnd`), the policy hash comes from the policy, and the subject hash, salt and values come from the read.

Fill one `present` flag per slot and write each fact into the slot the policy names: numeric facts in the numeric region, byte facts in the byte region after it, and zero in every unmeasured slot. Call `assertPolicySlotsInRange` before you fill, so a policy that does not fit the claim fails with a clear error.

## The checks

Put the variant's checks in `verify.ts` as small functions, then compose them in one `verify<Variant>Observation` that the law calls. Use this order, which is the order a client can fix:

1. The observation is of the event the locator names.
2. The observation comes from the policy's chain and pins.
3. The event's block sits at least `confirmationDepth` blocks below the read tip.
4. The proposed claim is exactly the claim the observation derives: version `1`, the policy's hash, the block-time window, the subject hash, the salt, the values, the byte values and the `present` flags.

The client runs the first two checks on its own read before it contacts any attestor, so a wrong event fails fast with that reason. Depth stays the attestor's alone, because the client's tip can differ from an attestor's without a fork.

`src/client/index.ts` imports the output variant's two checks directly today, so a new variant extends that call beside the law's `verify`.

## Register the variant

A variant is registered in four places.

- `src/index.ts`: add the schema to `cardanoPolicySchema` and the type to `CardanoPolicy`, and re-export the variant's public types and schemas. Widen the law-level aliases (`CardanoLocator`, `CardanoObservation`, `CardanoObservedEvidence`, `cardanoEvidenceSchema`, `cardanoObservationSchema`), then extend `deriveCardanoClaim` to dispatch on `policy.kind`. The output variant is the only case today; when the second lands, turn the direct call into a `switch`.
- `src/attestor/law.ts`: extend `createCardanoDefinition`'s `verify` to dispatch on `policy.kind`, and widen the definition's evidence and observation types through the aliases.
- `src/attestor/index.ts`: the attestor parses the policy, the locator and the proposal, calls `read`, parses the observation, verifies, derives and signs. It reads the law-level aliases, so widening them carries the new variant here; the dispatch stays in the law and in `deriveCardanoClaim`.
- `src/client/index.ts`: the client parses the policy, the app id and the slot counts at init, then reads, checks, derives and collects. Extend its two read checks beside the law's `verify`.

An unknown `kind` still fails, and the error names the valid kinds.

## Tests and pins

Create `test/<variant>/` beside `test/output/` and mirror its files:

- `fixtures.ts`: one fixed policy, locator, observation, app id and holder.
- `policy.test.ts`: a parse test and one rejection per rule, the canonical hash pin, and a check that entry order does not change the hash.
- `verify.test.ts`: an honest accept, one rejection per check, and the derived message pin.
- `subject.test.ts`: the fields in struct order, and the hash equal to `subjectHashOf` over them.
- `attest.test.ts`: the attestor signs the claim from its own read and refuses a proposal another read would derive.

`address-parity.test.ts` covers the shared `cardanoAddressHashOf`, so it needs no copy per variant.

A new variant adds a new policy hash pin. The existing output pin does not change, because the output variant's bytes stay the same. A change to a shared field, such as `networkMagic`, does change every variant's bytes, and then every pin has to be updated deliberately.

## Why existing hashes do not change

The variant's `kind` is part of the hashed bytes, and the policy schema sorts the slot list before hashing. An existing policy hashes the same after the change, and two variants cannot collide, since their `kind` values differ.

## Checklist

- [ ] `src/<variant>/index.ts` and `src/<variant>/verify.ts` are added.
- [ ] The policy extends `CardanoPolicyBase`, names its `kind`, pins what the app fixes about the event and maps each measurable fact once.
- [ ] The slot schema uses `checkSlotIndicesDistinct` and `checkSlotNamesDistinct`, and the policy sorts `slots` before hashing.
- [ ] The locator is strict and names only what finds the event.
- [ ] The observation schema is strict and pins the encodings every attestor must derive.
- [ ] The subject, the salt and every claim value come from the read; only `appId`, the holder and the slot counts come from the proposal.
- [ ] The law's `verify` and the client's two read checks call the variant's checks.
- [ ] `cardanoPolicySchema`, `CardanoPolicy`, the law-level aliases and `deriveCardanoClaim` dispatch to the variant.
- [ ] The variant's tests and pins are under `test/<variant>/`.
- [ ] The existing output pin `43a36f36210e42c8d3357821afb855b739ec22c832ecf7a5df3b79b05221d907` still matches. Changing a shared field, such as `networkMagic`, changes every variant's hash, so update the pins deliberately.
