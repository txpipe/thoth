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
  CARDANO_NETWORKS,
  type CardanoCommonSlots,
  type CardanoPolicyBase,
  checkAddressMatchesNetwork,
  checkNetworkMagic,
  checkSlotIndicesDistinct,
  MAX_NETWORK_MAGIC,
  numericSlotSchema,
  policyHashOfCardano,
} from '../policy.js';

/** The overflow bound of a claim value: lovelace is a uint64. */
const MAX_LOVELACE = 2n ** 64n - 1n;

/** The slots the output variant certifies. */
export type OutputSlots = CardanoCommonSlots & {
  /** The output's lovelace amount. */
  lovelace: number;
  /** The output's index within its transaction. */
  outputIndex: number;
};

/**
 * One lovelace output at the watched address. The `slots` map says which
 * claim slot each field fills (ADR 0009, ADR 0013).
 */
export type OutputPolicy = CardanoPolicyBase & {
  kind: 'output';
  /** The address the app watches, bech32, stored lowercase. */
  address: string;
  slots: OutputSlots;
};

/** Runtime validator for {@link OutputPolicy}. */
export const cardanoOutputPolicySchema = z
  .strictObject({
    network: z.enum(CARDANO_NETWORKS),
    networkMagic: z.number().int().min(1).max(MAX_NETWORK_MAGIC),
    confirmationDepth: z.number().int().nonnegative(),
    address: addressSchema,
    kind: z.literal('output'),
    slots: z.strictObject({
      blockTime: numericSlotSchema,
      slot: numericSlotSchema,
      blockNumber: numericSlotSchema,
      lovelace: numericSlotSchema,
      outputIndex: numericSlotSchema,
    }),
  })
  .superRefine((policy, context) => {
    checkNetworkMagic(policy, context);
    checkAddressMatchesNetwork(policy, context);
    checkSlotIndicesDistinct(policy.slots, context);
  });

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
    slot: z.number().int().nonnegative(),
    blockNumber: z.number().int().nonnegative(),
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

/**
 * Hash the event's identity: the network magic, the address, the transaction
 * hash, the output index and the block hash.
 *
 * The result equals the circuit's `persistentHash` of the subject struct with
 * these fields in declaration order, so an app can recompute it in-circuit.
 *
 * @throws if the network magic or output index is not a uint32, or a hash is
 *   not 64 lowercase hex characters.
 */
export const cardanoOutputSubjectHashOf = (
  networkMagic: number,
  address: string,
  txHash: string,
  outputIndex: number,
  blockHash: string,
): Uint8Array =>
  subjectHashOf([
    bytes32OfUint32(networkMagic),
    cardanoAddressHashOf(address),
    bytes32OfHex(txHash),
    bytes32OfUint32(outputIndex),
    bytes32OfHex(blockHash),
  ]);

/** Keeps the salt apart from the subject and any other kind's hashes. */
const SALT_TAG = 'thoth:cardano-salt:v1';

/**
 * Derive the salt of one observed output: a tagged hash of the network magic,
 * the transaction hash and the output index. Replay is stopped by the
 * nullifier; the salt itself is public (ADR 0013).
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
 * Derive the claim of one observed output. `appId`, `holder` and the value
 * count come from the proposal; every other field comes from the observation
 * and the policy, never from the proposal.
 *
 * @throws if a policy slot index is outside `valueSlots`.
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
}): Claim<number, 0> => {
  const { policy, observation, appId, holder, valueSlots } = options;
  const present = Array.from({ length: valueSlots }, () => false);
  const values = Array.from({ length: valueSlots }, () => 0n);
  const fill = (slot: number, value: number | bigint): void => {
    if (slot < 0 || slot >= valueSlots) {
      throw new Error(`policy slot ${slot} is outside the claim's ${valueSlots} value slots`);
    }
    present[slot] = true;
    values[slot] = BigInt(value);
  };
  fill(policy.slots.blockTime, observation.block.time);
  fill(policy.slots.slot, observation.block.slot);
  fill(policy.slots.blockNumber, observation.block.blockNumber);
  fill(policy.slots.lovelace, observation.output.lovelace);
  fill(policy.slots.outputIndex, observation.output.outputIndex);

  const { block, output } = observation;
  return {
    version: CLAIM_VERSION,
    appId,
    policyHash: cardanoOutputPolicyHashOf(policy),
    windowStart: BigInt(block.time),
    windowEnd: BigInt(block.time),
    subjectHash: cardanoOutputSubjectHashOf(
      observation.networkMagic,
      output.address,
      output.txHash,
      output.outputIndex,
      block.hash,
    ),
    holder,
    salt: cardanoOutputSaltOf(observation.networkMagic, output.txHash, output.outputIndex),
    present,
    values,
    byteValues: [],
  };
};
