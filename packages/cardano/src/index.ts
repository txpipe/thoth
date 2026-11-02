// The cardano@1 chain-event kind: attests one lovelace output read from a
// Cardano transaction. This module carries the law tag, the policy schema and
// the policy hash; the attestor and client entry points build on it.

import type { CanonicalValue } from '@thoth/core/claim-context';
import { policyHashOf } from '@thoth/core/claim-context';
import { z } from 'zod';

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
const MAX_NETWORK_MAGIC = 2 ** 32 - 1;

/** Fields every variant shares: the network, its magic, the depth and the address pin. */
export type CardanoBase = {
  /** The chain network the event must belong to. */
  network: CardanoNetwork;
  /**
   * The network magic the node must report. Public networks have fixed
   * values; a devnet sets its own (1 to 2^32-1, not a public magic).
   */
  networkMagic: number;
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
    /** The output's index within its transaction. */
    outputIndex: number;
  };
};

/**
 * The policy a cardano@1 attestor enforces. The variant tag rides in the
 * policy hash, so adding a variant is additive (ADR 0013).
 */
export type CardanoPolicy = OutputPolicy;

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

const numericSlotSchema = z.number().int().nonnegative();

// Bech32 is case-insensitive, so the policy stores one canonical case.
const addressSchema = z
  .string()
  .min(1)
  .transform((address) => address.toLowerCase());

/** Fails when the address prefix or charset does not match the network. */
const checkAddressMatchesNetwork = (
  policy: { network: CardanoNetwork; address: string },
  context: z.RefinementCtx,
): void => {
  if (!ADDRESS_PATTERN[policy.network].test(policy.address)) {
    context.addIssue({
      code: 'custom',
      message: `address is not a ${policy.network} payment address`,
      path: ['address'],
    });
  }
};

/**
 * Fails when the magic does not identify the network. A public network must
 * use its fixed magic; a devnet must not claim one, or it could be confused
 * with a public network.
 */
const checkNetworkMagic = (
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

/** Fails when two named slots share a claim slot index. */
const checkSlotIndicesDistinct = (
  slots: Record<string, number>,
  context: z.RefinementCtx,
): void => {
  const indices = Object.values(slots);
  if (new Set(indices).size !== indices.length) {
    context.addIssue({
      code: 'custom',
      message: 'each slot index may be declared once',
      path: ['slots'],
    });
  }
};

// Each variant owns its schema and refinements. A new variant adds its own
// schema here and an entry in the union below; this one is not edited.
const outputSchema = z
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
 * Runtime validator for {@link CardanoPolicy}. Dispatches on `kind`, so an
 * unknown kind fails with the valid kinds named.
 */
export const cardanoPolicySchema: z.ZodType<CardanoPolicy> = z.discriminatedUnion('kind', [
  outputSchema,
]);

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
