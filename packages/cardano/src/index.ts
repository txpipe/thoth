// The cardano@1 chain-event kind: attests one event read from a Cardano
// transaction. This module carries the law tag, the policy schema and the
// policy hash; the attestor and client entry points build on it.

import type { CanonicalValue } from '@thoth/core/claim-context';
import { policyHashOf } from '@thoth/core/claim-context';
import { z } from 'zod';

/** The cardano@1 kind's law tag, also its kind identifier. */
export const CARDANO_LAW = 'cardano@1';

/** The Cardano networks the law covers. */
export const CARDANO_NETWORKS = ['mainnet', 'preview', 'preprod'] as const;

/** One Cardano network. */
export type CardanoNetwork = (typeof CARDANO_NETWORKS)[number];

/** A native asset, by policy id and name. */
export type CardanoAssetClass = {
  /** 28-byte policy id, hex without prefix (56 chars). */
  policyId: string;
  /** The asset name, hex without prefix, even length, at most 32 bytes. */
  assetName: string;
};

/** One byte slot: which claim byte slot a named field fills (ADR 0009). */
export type CardanoByteSlot = {
  /** The claim slot index in the claim's one index space. */
  slot: number;
  /** Exact byte length, 1–32 (ADR 0010). */
  length: number;
};

/** Fields every variant shares: the network, the depth and the address pin. */
export type CardanoBase = {
  /** The chain network the event must belong to. */
  network: CardanoNetwork;
  /** Blocks the event's block must sit below the tip at read time. */
  confirmationDepth: number;
  /** The script address the app watches, bech32, stored lowercase. */
  address: string;
};

/**
 * Slots every variant certifies. A slot map is total: each variant names
 * every slot it carries, so the claim's values are fully determined.
 */
export type CardanoCommonSlots = {
  /** The block's Unix time. */
  blockTime: number;
  /** The block's absolute slot. */
  slot: number;
  /** The block's height. */
  blockNumber: number;
};

/**
 * One lovelace output at the watched address. The `slots` map says which
 * claim slot each field fills (ADR 0009, ADR 0013).
 */
export type OutputPolicy = CardanoBase & {
  kind: 'output';
  slots: CardanoCommonSlots & {
    /** The output's lovelace amount. */
    lovelace: number;
  };
};

/**
 * One native asset output at the watched address. The asset is pinned in the
 * policy, so the claim is about that asset only.
 */
export type AssetOutputPolicy = CardanoBase & {
  kind: 'asset-output';
  /** The asset the output must carry. */
  asset: CardanoAssetClass;
  slots: CardanoCommonSlots & {
    /** The pinned asset's quantity in the output. */
    quantity: number;
    /** The pinned asset's policy id (28 bytes). */
    policyId: CardanoByteSlot;
    /** The pinned asset's name, with the pinned length. */
    assetName: CardanoByteSlot;
  };
};

/**
 * The policy a cardano@1 attestor enforces. The variant tag rides in the
 * policy hash, so adding a variant is additive (ADR 0013).
 */
export type CardanoPolicy = OutputPolicy | AssetOutputPolicy;

/** Byte length of a Cardano policy id. */
const POLICY_ID_BYTES = 28;

const policyIdSchema = z
  .string()
  .length(2 * POLICY_ID_BYTES)
  .regex(/^[0-9a-f]+$/i, 'expected hex');

const assetNameSchema = z
  .string()
  .regex(/^(?:[0-9a-f]{2}){0,32}$/i, 'expected even hex of at most 32 bytes');

/**
 * Bech32 payment addresses per network, lowercase. The checksum is not
 * verified: a wrong checksum fails at the attestor's read, not here.
 */
const ADDRESS_PATTERN: Record<CardanoNetwork, RegExp> = {
  mainnet: /^addr1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,}$/,
  preview: /^addr_test1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,}$/,
  preprod: /^addr_test1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,}$/,
};

const assetClassSchema = z.strictObject({
  policyId: policyIdSchema,
  assetName: assetNameSchema,
});

const numericSlotSchema = z.number().int().nonnegative();

const byteSlotSchema = z.strictObject({
  slot: z.number().int().nonnegative(),
  length: z.number().int().min(1).max(32),
});

const policyIdSlotSchema = byteSlotSchema.refine(
  (entry) => entry.length === POLICY_ID_BYTES,
  'policyId is 28 bytes',
);

const commonSlots = {
  blockTime: numericSlotSchema,
  slot: numericSlotSchema,
  blockNumber: numericSlotSchema,
};

// Bech32 is case-insensitive, so the policy stores one canonical case.
const addressSchema = z
  .string()
  .min(1)
  .transform((address) => address.toLowerCase());

const baseShape = {
  network: z.enum(CARDANO_NETWORKS),
  confirmationDepth: z.number().int().nonnegative(),
  address: addressSchema,
};

const outputSchema = z.strictObject({
  ...baseShape,
  kind: z.literal('output'),
  slots: z.strictObject({
    ...commonSlots,
    lovelace: numericSlotSchema,
  }),
});

const assetOutputSchema = z.strictObject({
  ...baseShape,
  kind: z.literal('asset-output'),
  asset: assetClassSchema,
  slots: z.strictObject({
    ...commonSlots,
    quantity: numericSlotSchema,
    policyId: policyIdSlotSchema,
    assetName: byteSlotSchema,
  }),
});

/** The claim slot index an entry fills. */
const slotIndexOf = (entry: number | CardanoByteSlot): number =>
  typeof entry === 'number' ? entry : entry.slot;

/**
 * Runtime validator for {@link CardanoPolicy}. The types fix each variant's
 * slot names; this checks what they cannot: the address format for the
 * network, slot indices that are distinct across all names, and an asset-name
 * slot whose length matches the pinned name.
 */
export const cardanoPolicySchema: z.ZodType<CardanoPolicy> = z
  .discriminatedUnion('kind', [outputSchema, assetOutputSchema])
  .superRefine((policy, context) => {
    if (!ADDRESS_PATTERN[policy.network].test(policy.address)) {
      context.addIssue({
        code: 'custom',
        message: `address is not a ${policy.network} payment address`,
        path: ['address'],
      });
    }

    const entries = Object.values(policy.slots) as (number | CardanoByteSlot)[];
    const indices = entries.map(slotIndexOf);
    if (new Set(indices).size !== indices.length) {
      context.addIssue({
        code: 'custom',
        message: 'each slot index may be declared once',
        path: ['slots'],
      });
    }

    // The pinned name's length is known here, so a slot that disagrees would
    // certify a value the pin can never match.
    if (policy.kind === 'asset-output') {
      const pinnedBytes = policy.asset.assetName.length / 2;
      if (policy.slots.assetName.length !== pinnedBytes) {
        context.addIssue({
          code: 'custom',
          message: `assetName slot is ${policy.slots.assetName.length} bytes, the pinned name is ${pinnedBytes}`,
          path: ['slots', 'assetName', 'length'],
        });
      }
    }
  });

/**
 * Parse a policy into the form every hash and check reads. Every field is
 * canonical as written, so the parsed policy is the normalized one.
 *
 * @throws if the policy fails {@link cardanoPolicySchema}.
 */
export const normalizeCardanoPolicy = (policy: CardanoPolicy): CardanoPolicy =>
  cardanoPolicySchema.parse(policy);

/**
 * Hash a policy under the `cardano@1` law and the claim wire version.
 *
 * Policies that parse the same hash the same.
 *
 * @throws if the policy fails {@link cardanoPolicySchema}.
 */
export const cardanoPolicyHashOf = (policy: CardanoPolicy): Uint8Array =>
  policyHashOf(CARDANO_LAW, normalizeCardanoPolicy(policy) as CanonicalValue);
