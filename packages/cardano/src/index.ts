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

/**
 * The part of a transaction one policy is about. The kind's per-selector check
 * parameters and certifiable slot names are closed over this union; the
 * selector rides in the policy hash, so adding one is additive (ADR 0013).
 */
export type CardanoSelector =
  | {
      /** One output at a script address. */
      kind: 'script';
      /** The script address the app watches, bech32. */
      address: string;
      /** Present when the app watches one asset of the output. */
      asset?: CardanoAssetClass;
    }
  | {
      /** One minted asset in the transaction. */
      kind: 'mint';
      /** The asset the policy is about, also the event's identity. */
      asset: CardanoAssetClass;
    }
  | {
      /** One delegation certificate in the transaction. */
      kind: 'delegation';
    };

/** One byte slot: which claim byte slot a named field fills (ADR 0009). */
export type CardanoByteSlot = {
  /** The claim slot index in the claim's one index space. */
  slot: number;
  /** Exact byte length, 1–32 (ADR 0010). */
  length: number;
};

/** The policy a cardano@1 attestor enforces. */
export type CardanoPolicy = {
  /** The chain network the event must belong to. */
  network: CardanoNetwork;
  /** Blocks the event's block must sit below the tip at read time. */
  confirmationDepth: number;
  /** Which sub-part of the transaction the event is, and what pins it. */
  selector: CardanoSelector;
  /**
   * The slot map: which claim slot each named field fills, in the claim's one
   * index space — numeric slots `0..V-1`, byte slots from `V` (ADR 0009). A
   * field whose value is a number maps to its `values` index, written as a
   * bare number; a field whose value is a 32-byte string maps to a
   * {@link CardanoByteSlot} (`{slot, length}`). `blockTime` and `slot` are
   * certifiable for every selector; the rest per selector: `lovelace` for
   * `script`, `policyId`, `assetName` and `quantity` for `script` with an
   * `asset` pin, `quantity` for `mint`, `poolId` for `delegation`. `policyId`
   * and `poolId` are 28 bytes, `assetName` carries its length.
   */
  slots: {
    /** The block's Unix time. */
    blockTime?: number;
    /** The block's absolute slot. */
    slot?: number;
    /** The output's lovelace amount. */
    lovelace?: number;
    /** The minted or pinned asset's quantity. */
    quantity?: number;
    /** The pinned asset's policy id. */
    policyId?: CardanoByteSlot;
    /** The pinned asset's name. */
    assetName?: CardanoByteSlot;
    /** The pool id of a delegation certificate. */
    poolId?: CardanoByteSlot;
  };
};

/** Byte length of a Cardano policy id. */
const POLICY_ID_BYTES = 28;

const policyIdSchema = z
  .string()
  .length(2 * POLICY_ID_BYTES)
  .regex(/^[0-9a-f]+$/i, 'expected hex');

const assetNameSchema = z
  .string()
  .regex(/^(?:[0-9a-f]{2}){0,32}$/i, 'expected even hex of at most 32 bytes');

const assetClassSchema = z.object({
  policyId: policyIdSchema,
  assetName: assetNameSchema,
});

const selectorSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('script'),
    address: z.string().min(1),
    asset: assetClassSchema.optional(),
  }),
  z.object({
    kind: z.literal('mint'),
    asset: assetClassSchema,
  }),
  z.object({ kind: z.literal('delegation') }),
]);

const numericSlotSchema = z.number().int().nonnegative();

const byteSlotSchema = z.strictObject({
  slot: z.number().int().nonnegative(),
  length: z.number().int().min(1).max(32),
});

const slotsSchema = z.object({
  blockTime: numericSlotSchema.optional(),
  slot: numericSlotSchema.optional(),
  lovelace: numericSlotSchema.optional(),
  quantity: numericSlotSchema.optional(),
  policyId: byteSlotSchema
    .refine((entry) => entry.length === POLICY_ID_BYTES, 'policyId is 28 bytes')
    .optional(),
  assetName: byteSlotSchema.optional(),
  poolId: byteSlotSchema
    .refine((entry) => entry.length === POLICY_ID_BYTES, 'poolId is 28 bytes')
    .optional(),
});

/** One declared slot name. */
type SlotName = keyof CardanoPolicy['slots'];

/** The claim slot index a declared entry fills. */
const slotIndexOf = (entry: number | CardanoByteSlot): number =>
  typeof entry === 'number' ? entry : entry.slot;

/**
 * Runtime validator for {@link CardanoPolicy}: slot indices are unique, at
 * least one slot is declared, and each declared name is certifiable for the
 * policy's selector.
 */
export const cardanoPolicySchema: z.ZodType<CardanoPolicy> = z
  .object({
    network: z.enum(CARDANO_NETWORKS),
    confirmationDepth: z.number().int().nonnegative(),
    selector: selectorSchema,
    slots: slotsSchema,
  })
  .superRefine((policy, context) => {
    const { selector, slots } = policy;
    const declared = (Object.keys(slots) as SlotName[]).filter((name) => slots[name] !== undefined);
    if (declared.length === 0) {
      context.addIssue({
        code: 'custom',
        message: 'a policy needs at least one slot',
        path: ['slots'],
      });
    }
    const indices = declared.map((name) => slotIndexOf(slots[name] as number | CardanoByteSlot));
    if (new Set(indices).size !== indices.length) {
      context.addIssue({
        code: 'custom',
        message: 'each slot index may be declared once',
        path: ['slots'],
      });
    }

    const allowed: SlotName[] = ['blockTime', 'slot'];
    if (selector.kind === 'script') {
      allowed.push('lovelace');
      if (selector.asset) allowed.push('policyId', 'assetName', 'quantity');
    } else if (selector.kind === 'mint') {
      allowed.push('quantity');
    } else {
      allowed.push('poolId');
    }
    for (const name of declared) {
      if (!allowed.includes(name)) {
        context.addIssue({
          code: 'custom',
          message: `"${name}" is not certifiable for the ${selector.kind} selector`,
          path: ['slots', name],
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
