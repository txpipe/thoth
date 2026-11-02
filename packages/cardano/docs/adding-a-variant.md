# Adding a variant

A variant is one event shape `cardano@1` can describe, such as the `output` variant that exists today. This guide covers the steps in `src/index.ts` for a new variant. The attestor's verify step is not built yet, so it is not covered here.

A new variant adds its own definition and registers it alongside the existing ones. Nothing about the existing variant changes, so its tests and hash pin still hold.

## 1. Write the variant's schema

Follow the pattern of `outputSchema`: a strict object with the variant's fields and its own slot map, then `superRefine` calling the shared helpers.

```ts
const transferSchema = z
  .strictObject({
    network: z.enum(CARDANO_NETWORKS),
    confirmationDepth: z.number().int().nonnegative(),
    address: addressSchema,
    kind: z.literal('transfer'),
    slots: z.strictObject({
      blockTime: numericSlotSchema,
      slot: numericSlotSchema,
      blockNumber: numericSlotSchema,
      // the variant's own slots go here
    }),
  })
  .superRefine((policy, context) => {
    checkAddressMatchesNetwork(policy, context);
    checkSlotIndicesDistinct(policy.slots, context);
  });
```

Only `network`, `confirmationDepth`, `address` and the common slots are shared. Put anything else in the variant's own schema.

## 2. Add it to the union and the type

- Add the schema to the array in `cardanoPolicySchema`:

  ```ts
  z.discriminatedUnion('kind', [outputSchema, transferSchema]);
  ```

- Add the type and widen `CardanoPolicy`:

  ```ts
  export type CardanoPolicy = OutputPolicy | TransferPolicy;
  ```

An unknown `kind` still fails, and the error names the valid kinds.

## 3. Add its tests and pin

In `test/policy.test.ts`, add:

- A parse test for a valid policy of the new variant.
- Reject tests for its own slots and address rules.
- A hash pin for a fixed policy of the new variant. Its pin is new.

The output pin does not change, because the output variant's bytes stay the same. A change to a shared field, such as `networkMagic`, does change every variant's bytes, and then every pin has to be updated.

## Why existing hashes do not change

The variant's `kind` is part of the hashed bytes. An output policy hashes the same after the change, and a transfer policy cannot collide with an output policy, since their `kind` values differ.

## Checklist

- [ ] The variant schema uses the shared address and slot helpers.
- [ ] The schema is in the `discriminatedUnion` array.
- [ ] `CardanoPolicy` includes the new type.
- [ ] Parse, reject and pin tests are added.
- [ ] The existing output pin `260be4b7b15828a6ec3c053f8f4e9c9065658f69e083b0fb23d1e98bbce4f3b1` still matches. Changing a shared field, such as `networkMagic`, changes every variant's hash, so update the pins deliberately.
