// Shared cardano@1 policy primitives: the law tag, networks, base fields and
// validators. Each event variant supplies its own schema on top of these.

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
export const MAX_NETWORK_MAGIC = 2 ** 32 - 1;

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
export const numericSlotSchema = z.number().int().nonnegative();

/** A bech32 payment address, stored in its canonical lowercase form. */
export const addressSchema = z
  .string()
  .min(1)
  .transform((address) => address.toLowerCase());

/** Fails when the address prefix or charset does not match the network. */
export const checkAddressMatchesNetwork = (
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

/** Fails when two named slots share a claim slot index. */
export const checkSlotIndicesDistinct = (
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

/**
 * Hash a normalized cardano@1 policy under the law tag and the claim wire
 * version, so the same policy under another law or version hashes differently.
 */
export const policyHashOfCardano = (policy: CanonicalValue): Uint8Array =>
  policyHashOf(CARDANO_LAW, policy);
