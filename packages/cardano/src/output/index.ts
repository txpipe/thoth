// The output variant of cardano@1: one lovelace output at a watched address.
// Policy, evidence, observation, subject, salt and claim derivation live here;
// the checks are in ./verify.ts.

import type { Claim } from '@thoth/core/claim';
import { CLAIM_VERSION } from '@thoth/core/claim';
import type { CanonicalValue } from '@thoth/core/claim-context';
import { subjectHashOf } from '@thoth/core/claim-context';
import { z } from 'zod';
import {
  bytes32OfHex,
  bytes32OfText,
  bytes32OfUint32,
  cardanoAddressHashOf,
  HEX_64,
} from '../bytes.js';
import {
  addressSchema,
  assertPolicySlotsInRange,
  CARDANO_FACTS,
  CARDANO_NETWORKS,
  type CardanoByteFact,
  type CardanoNumericFact,
  type CardanoPolicyBase,
  type CardanoSlot,
  checkAddressMatchesNetwork,
  checkNetworkMagic,
  checkSlotIndicesDistinct,
  checkSlotNamesDistinct,
  isCardanoByteFact,
  MAX_NETWORK_MAGIC,
  numericSlotSchema,
  policyHashOfCardano,
} from '../policy.js';

/** The overflow bound of a claim value: lovelace is a uint64. */
const MAX_LOVELACE = 2n ** 64n - 1n;

/** The minting policy id as lowercase hex: 28 bytes. */
const HEX_56 = /^[0-9a-f]{56}$/;

/** The asset name as lowercase hex: 0 to 32 bytes. */
const HEX_NAME = /^[0-9a-f]{0,64}$/;

/** The class of one native asset: the minting policy id and the asset name. */
export type AssetClass = {
  /** The minting policy id, 56 lowercase hex characters. */
  policyId: string;
  /** The asset name, up to 64 lowercase hex characters (0 to 32 bytes). */
  assetName: string;
};

/** One native asset of an output: its class and the quantity the output carries. */
export type NativeAsset = AssetClass & {
  /** The quantity, a uint64. */
  quantity: bigint;
};

/** Runtime validator for one {@link AssetClass}. */
const assetClassSchema = z.strictObject({
  policyId: z.string().regex(HEX_56, 'expected 56 lowercase hex characters'),
  assetName: z.string().regex(HEX_NAME, 'expected up to 64 lowercase hex characters'),
});

/**
 * One output at the watched address. The `slots` list says which claim slot
 * each measured fact fills (ADR 0009, ADR 0014); the policy hash commits to
 * it, so every attestor fills the same slots.
 */
export type OutputPolicy = CardanoPolicyBase & {
  kind: 'output';
  /** The address the app watches, bech32, stored lowercase. */
  address: string;
  /**
   * The native asset the policy requires. When set, the attestor requires the
   * output to carry it, and `assetQuantity` may be measured.
   */
  asset?: AssetClass;
  slots: readonly CardanoSlot[];
};

/** Runtime validator for one {@link CardanoSlot}. */
const outputSlotSchema = z.strictObject({
  slot: numericSlotSchema,
  name: z.enum(CARDANO_FACTS),
});

/** Runtime validator for {@link OutputPolicy}. */
export const cardanoOutputPolicySchema = z
  .strictObject({
    network: z.enum(CARDANO_NETWORKS),
    networkMagic: z.number().int().min(1).max(MAX_NETWORK_MAGIC),
    confirmationDepth: z.number().int().nonnegative(),
    address: addressSchema,
    kind: z.literal('output'),
    asset: assetClassSchema.optional(),
    slots: z
      .array(outputSlotSchema)
      .min(1)
      .max(CARDANO_FACTS.length)
      .superRefine((slots, context) => {
        checkSlotIndicesDistinct(slots, context);
        checkSlotNamesDistinct(slots, context);
      }),
  })
  .superRefine((policy, context) => {
    checkNetworkMagic(policy, context);
    checkAddressMatchesNetwork(policy, context);
    if (
      policy.asset === undefined &&
      policy.slots.some((entry) => entry.name === 'assetQuantity')
    ) {
      context.addIssue({
        code: 'custom',
        message: "'assetQuantity' requires the 'asset' pin",
        path: ['slots'],
      });
    }
  })
  .transform((policy) => ({
    ...policy,
    // Sorted by index, so the policy hash is the same whatever order the
    // author wrote the entries in.
    slots: [...policy.slots].sort((a, b) => a.slot - b.slot),
  }));

/**
 * Hash an output policy under the `cardano@1` law and the claim wire version.
 * Policies that parse the same hash the same.
 *
 * @throws if the policy fails {@link cardanoOutputPolicySchema}.
 */
export const cardanoOutputPolicyHashOf = (policy: OutputPolicy): Uint8Array =>
  policyHashOfCardano(cardanoOutputPolicySchema.parse(policy) as CanonicalValue);

/** Points at one output of one Cardano transaction. */
export interface OutputLocator {
  /** The transaction hash, 64 lowercase hex characters. */
  txHash: string;
  /** The output's index within the transaction, a uint32. */
  outputIndex: number;
}

/**
 * Runtime validator for {@link OutputLocator}. Strict, so a client cannot add
 * an `observation` key and try to shape the claim.
 */
export const cardanoOutputEvidenceSchema: z.ZodType<OutputLocator> = z.strictObject({
  txHash: z.string().regex(HEX_64, 'expected 64 lowercase hex characters'),
  outputIndex: z
    .number()
    .int()
    .min(0)
    .max(2 ** 32 - 1),
});

/** One output and the block it landed in, as the attestor read them. */
export interface OutputObservation {
  /** The network magic of the node the attestor read. */
  networkMagic: number;
  /** The node's tip height at read time. */
  tipBlockNumber: number;
  block: {
    /** The block hash, 64 lowercase hex characters. */
    hash: string;
    /** The block's absolute slot. */
    slot: number;
    /** The block's height. */
    blockNumber: number;
    /** The block's Unix time in seconds. */
    time: number;
  };
  output: {
    /** The transaction hash, 64 lowercase hex characters. */
    txHash: string;
    /** The output's index within the transaction, a uint32. */
    outputIndex: number;
    /** The output's address, lowercase bech32. */
    address: string;
    /** The output's lovelace amount, below 2^64. */
    lovelace: bigint;
    /** The output's native assets, in policy-id/name order as read. */
    assets: readonly NativeAsset[];
  };
}

/**
 * Runtime validator for {@link OutputObservation}. Strict, so a reader that
 * returns an unexpected field fails instead of silently dropping it.
 */
export const cardanoOutputObservationSchema: z.ZodType<OutputObservation> = z.strictObject({
  networkMagic: z.number().int().min(0).max(MAX_NETWORK_MAGIC),
  tipBlockNumber: z.number().int().nonnegative(),
  block: z.strictObject({
    hash: z.string().regex(HEX_64, 'expected 64 lowercase hex characters'),
    // No transaction lives in the genesis block, so a zero slot or height is a
    // field the reader left unset; as a height it would pass any depth check.
    slot: z.number().int().positive(),
    blockNumber: z.number().int().positive(),
    time: z.number().int().nonnegative(),
  }),
  output: z.strictObject({
    txHash: z.string().regex(HEX_64, 'expected 64 lowercase hex characters'),
    outputIndex: z
      .number()
      .int()
      .min(0)
      .max(2 ** 32 - 1),
    address: z
      .string()
      .min(1)
      .refine((address) => address === address.toLowerCase(), {
        message: 'address must be lowercase bech32',
      }),
    lovelace: z.bigint().min(0n).max(MAX_LOVELACE),
    assets: z.array(
      z.strictObject({
        policyId: z.string().regex(HEX_56, 'expected 56 lowercase hex characters'),
        assetName: z.string().regex(HEX_NAME, 'expected up to 64 lowercase hex characters'),
        quantity: z.bigint().min(0n).max(MAX_LOVELACE),
      }),
    ),
  }),
});

/**
 * The locator plus the observation the attestor read, what `verify` judges.
 * `observation` is optional so a direct `verify` call cannot skip the
 * missing-observation check.
 */
export type OutputObservedEvidence = OutputLocator & {
  observation?: OutputObservation;
};

/** The raw fields of one output the subject commits to. */
export interface OutputSubjectInput {
  /** The network magic of the chain the output belongs to. */
  networkMagic: number;
  /** The transaction hash, 64 lowercase hex characters. */
  txHash: string;
  /** The output's index within the transaction, a uint32. */
  outputIndex: number;
  /** The block hash, 64 lowercase hex characters. */
  blockHash: string;
}

/**
 * The subject of one observed output as 32-byte fields, in the order the
 * circuit struct declares them. An app passes these fields as private input
 * and recomputes the hash in-circuit (ADR 0001).
 */
export interface OutputSubject {
  /** The network magic as a 32-byte big-endian uint32, right-aligned. */
  networkMagic: Uint8Array;
  /** The 32 bytes of the transaction hash. */
  txHash: Uint8Array;
  /** The output index as a 32-byte big-endian uint32, right-aligned. */
  outputIndex: Uint8Array;
  /** The 32 bytes of the block hash. */
  blockHash: Uint8Array;
}

/**
 * Build the subject fields of one observed output, in the order the circuit's
 * subject struct declares them.
 *
 * @throws if the network magic or output index is not a uint32, or a hash is
 *   not 64 lowercase hex characters.
 */
export const cardanoOutputSubjectOf = (input: OutputSubjectInput): OutputSubject => ({
  networkMagic: bytes32OfUint32(input.networkMagic),
  txHash: bytes32OfHex(input.txHash),
  outputIndex: bytes32OfUint32(input.outputIndex),
  blockHash: bytes32OfHex(input.blockHash),
});

/**
 * Hash the event's identity: the network magic, the transaction hash, the
 * output index and the block hash.
 *
 * The result equals the circuit's `persistentHash` of the subject struct with
 * these fields in declaration order, so an app can recompute it in-circuit.
 *
 * @throws if the network magic or output index is not a uint32, or a hash is
 *   not 64 lowercase hex characters.
 */
export const cardanoOutputSubjectHashOf = (input: OutputSubjectInput): Uint8Array => {
  const subject = cardanoOutputSubjectOf(input);
  return subjectHashOf([
    subject.networkMagic,
    subject.txHash,
    subject.outputIndex,
    subject.blockHash,
  ]);
};

/** Keeps the salt apart from the subject and any other kind's hashes. */
const SALT_TAG = 'thoth:cardano-salt:v1';

/**
 * Derive the salt of one observed output: a tagged hash of the network magic,
 * the transaction hash and the output index. Replay is stopped by the
 * nullifier; the salt itself is public (ADR 0014).
 *
 * @throws if the network magic or output index is not a uint32, or the
 *   transaction hash is not 64 lowercase hex characters.
 */
export const cardanoOutputSaltOf = (
  networkMagic: number,
  txHash: string,
  outputIndex: number,
): Uint8Array =>
  subjectHashOf([
    bytes32OfText(SALT_TAG),
    bytes32OfUint32(networkMagic),
    bytes32OfHex(txHash),
    bytes32OfUint32(outputIndex),
  ]);

/**
 * The quantity of the pinned asset in the observed output's assets.
 *
 * @throws if the assets do not carry the pinned asset.
 */
export const assetQuantityOf = (asset: AssetClass, assets: readonly NativeAsset[]): bigint => {
  const found = assets.find(
    (candidate) => candidate.policyId === asset.policyId && candidate.assetName === asset.assetName,
  );
  if (found === undefined) {
    throw new Error('policy asset is not in the output');
  }
  return found.quantity;
};

/**
 * Derive the claim of one observed output. `appId`, `holder` and the slot
 * counts come from the proposal; every other field comes from the observation
 * and the policy, never from the proposal.
 *
 * @throws if a policy slot is out of range or in the wrong region for its
 *   fact's type.
 */
export const deriveOutputClaim = (options: {
  policy: OutputPolicy;
  observation: OutputObservation;
  /** 32 bytes, from the proposal. */
  appId: Uint8Array;
  /** 32 bytes, from the proposal. */
  holder: Uint8Array;
  /** The contract's numeric value count, from the proposal's `values.length`. */
  valueSlots: number;
  /** The contract's byte value count, from the proposal's `byteValues.length`. */
  byteSlots: number;
}): Claim<number, number> => {
  const { policy, observation, appId, holder, valueSlots, byteSlots } = options;
  const { block, output } = observation;
  assertPolicySlotsInRange(policy.slots, valueSlots, byteSlots);
  const present = Array.from({ length: valueSlots + byteSlots }, () => false);
  const values = Array.from({ length: valueSlots }, () => 0n);
  const byteValues: Uint8Array[] = Array.from({ length: byteSlots }, () => new Uint8Array(32));
  const numericFactValues: Record<CardanoNumericFact, number | bigint> = {
    blockTime: block.time,
    slot: block.slot,
    blockNumber: block.blockNumber,
    lovelace: output.lovelace,
    outputIndex: output.outputIndex,
    // Never read without the pin: the slot loop throws before this fallback
    // can reach a claim, and the policy schema rejects the combination.
    assetQuantity: policy.asset === undefined ? 0n : assetQuantityOf(policy.asset, output.assets),
  };
  const byteFactValues: Record<CardanoByteFact, Uint8Array> = {
    txHash: bytes32OfHex(output.txHash),
    blockHash: bytes32OfHex(block.hash),
    addressHash: cardanoAddressHashOf(output.address),
  };
  for (const { slot, name } of policy.slots) {
    if (name === 'assetQuantity' && policy.asset === undefined) {
      // The policy schema refuses this combination; this guard is for a caller
      // that passes a hand-built policy and must not get a claim signing 0.
      throw new Error("'assetQuantity' requires the 'asset' pin");
    }
    if (isCardanoByteFact(name)) {
      byteValues[slot - valueSlots] = byteFactValues[name];
    } else {
      values[slot] = BigInt(numericFactValues[name]);
    }
    present[slot] = true;
  }

  return {
    version: CLAIM_VERSION,
    appId,
    policyHash: cardanoOutputPolicyHashOf(policy),
    windowStart: BigInt(block.time),
    windowEnd: BigInt(block.time),
    subjectHash: cardanoOutputSubjectHashOf({
      networkMagic: observation.networkMagic,
      txHash: output.txHash,
      outputIndex: output.outputIndex,
      blockHash: block.hash,
    }),
    holder,
    salt: cardanoOutputSaltOf(observation.networkMagic, output.txHash, output.outputIndex),
    present,
    values,
    byteValues,
  };
};
