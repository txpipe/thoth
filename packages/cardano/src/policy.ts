// Shared cardano@1 policy primitives: the law tag, networks, base fields and
// validators. Each event variant supplies its own schema on top of these.

import type { CanonicalValue } from '@txpipe/thoth-core/claim-context';
import { policyHashOf } from '@txpipe/thoth-core/claim-context';
import { z } from 'zod';
import { MAX_UINT32 } from './bytes.js';

/** The cardano@1 kind's law tag, also its kind identifier. */
export const CARDANO_LAW = 'cardano@1';

/** The Cardano networks the law covers. `devnet` is an undeployed local network. */
export const CARDANO_NETWORKS = ['mainnet', 'preview', 'preprod', 'devnet'] as const;

/** One Cardano network. */
export type CardanoNetwork = (typeof CARDANO_NETWORKS)[number];

/** Network magics of the public networks, which a policy must use for them. */
const PUBLIC_MAGICS = {
  mainnet: 764824073,
  preview: 2,
  preprod: 1,
} as const;

/** Largest network magic: Cardano's magic is a 32-bit unsigned integer. */
export const MAX_NETWORK_MAGIC = MAX_UINT32;

/** Fields every variant shares: the network, its magic and the depth. */
export type CardanoPolicyBase = {
  /** The chain network the event must belong to. */
  network: CardanoNetwork;
  /**
   * The network magic the node must report. Public networks have fixed
   * values; a devnet sets its own (1 to 2^32-1, not a public magic).
   */
  networkMagic: number;
  /** Blocks the event's block must sit below the tip at read time. */
  confirmationDepth: number;
};

/**
 * The facts any cardano@1 policy can measure, each a field of the event read.
 * A variant's schema narrows this to the subset its read can fill.
 */
export const CARDANO_FACTS = [
  'blockTime',
  'slot',
  'blockNumber',
  'lovelace',
  'outputIndex',
  'assetQuantity',
  'txHash',
  'blockHash',
  'addressHash',
] as const;

/** One measurable fact of a cardano@1 event. */
export type CardanoFact = (typeof CARDANO_FACTS)[number];

/** The byte facts: 32-byte values that fill a byte slot, not a numeric one. */
export const CARDANO_BYTE_FACTS = ['txHash', 'blockHash', 'addressHash'] as const;

/** A fact that fills a 32-byte byte slot. */
export type CardanoByteFact = (typeof CARDANO_BYTE_FACTS)[number];

/** A fact that fills a `Uint<64>` numeric slot. */
export type CardanoNumericFact = Exclude<CardanoFact, CardanoByteFact>;

/** Whether a fact fills a byte slot rather than a numeric one. */
export const isCardanoByteFact = (name: CardanoFact): name is CardanoByteFact =>
  (CARDANO_BYTE_FACTS as readonly string[]).includes(name);

/** One claim-slot binding: which fact fills which claim slot. */
export type CardanoSlot = {
  /** Index into the claim's value slots: numeric `0..V-1`, byte `V..V+W-1`. */
  slot: number;
  /** The fact to measure into `slot`. */
  name: CardanoFact;
};

// CIP-19 payment addresses, bech32, lowercase. The 53 characters after the
// prefix are the smallest payment address (29 bytes, 47 characters, plus the
// 6-character checksum); pointer addresses are longer and CIP-19 sets no
// maximum. The checksum is not verified here: a wrong checksum fails at the
// attestor's read.
const BECH32_CHARS = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const MAINNET_ADDRESS = new RegExp(`^addr1[${BECH32_CHARS}]{53,}$`);
// Preview, preprod and devnet share the testnet prefix, so an address cannot
// tell them apart. The network magic is what identifies the network.
const TESTNET_ADDRESS = new RegExp(`^addr_test1[${BECH32_CHARS}]{53,}$`);

const ADDRESS_PATTERN: Record<CardanoNetwork, RegExp> = {
  mainnet: MAINNET_ADDRESS,
  preview: TESTNET_ADDRESS,
  preprod: TESTNET_ADDRESS,
  devnet: TESTNET_ADDRESS,
};

/** A policy slot index. */
export const slotIndexSchema = z.number().int().nonnegative();

/** A bech32 payment address, stored in its canonical lowercase form. */
export const addressSchema = z
  .string()
  .min(1)
  .transform((address) => address.toLowerCase());

/**
 * Fails when the address prefix or charset does not match the network.
 *
 * `path` is the field the issue points at; it defaults to `['address']` so a
 * variant whose address field has another name can report the right one.
 */
export const checkAddressMatchesNetwork = (
  policy: { network: CardanoNetwork; address: string },
  context: z.RefinementCtx,
  path: (string | number)[] = ['address'],
): void => {
  if (!ADDRESS_PATTERN[policy.network].test(policy.address)) {
    context.addIssue({
      code: 'custom',
      message: `address is not a ${policy.network} payment address`,
      path,
    });
  }
};

/**
 * Fails when the magic does not identify the network. A public network must
 * use its fixed magic; a devnet must not claim one, or it could be confused
 * with a public network.
 */
export const checkNetworkMagic = (
  policy: { network: CardanoNetwork; networkMagic: number },
  context: z.RefinementCtx,
): void => {
  if (policy.network === 'devnet') {
    const publicMagics = Object.values(PUBLIC_MAGICS) as number[];
    if (publicMagics.includes(policy.networkMagic)) {
      context.addIssue({
        code: 'custom',
        message: `devnet cannot use the public magic ${policy.networkMagic}`,
        path: ['networkMagic'],
      });
    }
    return;
  }
  if (policy.networkMagic !== PUBLIC_MAGICS[policy.network]) {
    context.addIssue({
      code: 'custom',
      message: `${policy.network} magic is ${PUBLIC_MAGICS[policy.network]}`,
      path: ['networkMagic'],
    });
  }
};

/** Fails when two slot entries share a claim slot index. */
export const checkSlotIndicesDistinct = (
  slots: readonly { slot: number }[],
  context: z.RefinementCtx,
): void => {
  const indices = slots.map((entry) => entry.slot);
  if (new Set(indices).size !== indices.length) {
    context.addIssue({
      code: 'custom',
      message: 'each slot index may be declared once',
      path: ['slots'],
    });
  }
};

/** Fails when one fact is mapped to more than one claim slot. */
export const checkSlotNamesDistinct = (
  slots: readonly { name: string }[],
  context: z.RefinementCtx,
): void => {
  const names = slots.map((entry) => entry.name);
  if (new Set(names).size !== names.length) {
    context.addIssue({
      code: 'custom',
      message: 'each fact may be mapped once',
      path: ['slots'],
    });
  }
};

/**
 * Require every policy slot to be non-negative and fit the claim's size and its
 * fact's region: numeric facts in `0..V-1`, byte facts in `V..V+W-1`.
 *
 * @throws if a slot is negative, out of range or in the wrong region for its fact.
 */
export const assertPolicySlotsInRange = (
  slots: readonly CardanoSlot[],
  valueSlots: number,
  byteSlots: number,
): void => {
  const total = valueSlots + byteSlots;
  const outOfRange = slots.find((entry) => entry.slot < 0 || entry.slot >= total);
  if (outOfRange !== undefined) {
    throw new Error(`policy slot ${outOfRange.slot} is outside the claim's ${total} slots`);
  }
  const wrongRegion = slots.find((entry) =>
    isCardanoByteFact(entry.name) ? entry.slot < valueSlots : entry.slot >= valueSlots,
  );
  if (wrongRegion !== undefined) {
    throw new Error(
      isCardanoByteFact(wrongRegion.name)
        ? `policy fact ${wrongRegion.name} at slot ${wrongRegion.slot} targets a numeric slot`
        : `policy fact ${wrongRegion.name} at slot ${wrongRegion.slot} targets a byte slot`,
    );
  }
};

/**
 * Hash a normalized cardano@1 policy under the law tag and the claim wire
 * version, so the same policy under another law or version hashes differently.
 */
export const hashParsedCardanoPolicy = (policy: CanonicalValue): Uint8Array =>
  policyHashOf(CARDANO_LAW, policy);
