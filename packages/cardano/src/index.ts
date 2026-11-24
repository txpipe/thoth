// The cardano@1 chain-event kind: the policy union, policy hash and claim
// schema shared by every variant. The output variant lives under ./output/.

import type { AttestationInput } from '@thoth/core';
import type { Claim, ClaimInput, FlatMessage } from '@thoth/core/claim';
import { claimSchema } from '@thoth/core/claim';
import { z } from 'zod';
import { cardanoAddressHashOf } from './bytes.js';
import { CARDANO_LIMITS } from './limits.js';
import {
  type AssetClass,
  cardanoOutputEvidenceSchema,
  cardanoOutputObservationSchema,
  cardanoOutputPolicyHashOf,
  cardanoOutputPolicySchema,
  cardanoOutputSaltOf,
  cardanoOutputSubjectHashOf,
  cardanoOutputSubjectOf,
  deriveOutputClaim,
  type NativeAsset,
  type OutputLocator,
  type OutputObservation,
  type OutputObservedEvidence,
  type OutputPolicy,
  type OutputSubject,
  type OutputSubjectInput,
} from './output/index.js';
import {
  CARDANO_BYTE_FACTS,
  CARDANO_FACTS,
  CARDANO_LAW,
  CARDANO_NETWORKS,
  type CardanoByteFact,
  type CardanoFact,
  type CardanoNetwork,
  type CardanoPolicyBase,
  type CardanoSlot,
} from './policy.js';

export type {
  AssetClass,
  CardanoByteFact,
  CardanoFact,
  CardanoNetwork,
  CardanoPolicyBase,
  CardanoSlot,
  NativeAsset,
  OutputLocator,
  OutputObservation,
  OutputObservedEvidence,
  OutputPolicy,
  OutputSubject,
  OutputSubjectInput,
};
export {
  CARDANO_BYTE_FACTS,
  CARDANO_FACTS,
  CARDANO_LAW,
  CARDANO_LIMITS,
  CARDANO_NETWORKS,
  cardanoAddressHashOf,
  cardanoOutputEvidenceSchema,
  cardanoOutputObservationSchema,
  cardanoOutputSaltOf,
  cardanoOutputSubjectHashOf,
  cardanoOutputSubjectOf,
};

/**
 * The law-level locator. Today the only variant is `output`; a second variant
 * widens this to a union.
 */
export type CardanoLocator = OutputLocator;

/** The law-level observation. Today it is the output observation. */
export type CardanoObservation = OutputObservation;

/**
 * The locator plus the observation the law's `verify` judges. Today it is the
 * output variant's shape; a second variant widens it to a union.
 */
export type CardanoObservedEvidence = OutputObservedEvidence;

/** Runtime validator for the current law-level locator (today, output). */
export const cardanoEvidenceSchema = cardanoOutputEvidenceSchema;

/** Runtime validator for the current law-level observation (today, output). */
export const cardanoObservationSchema = cardanoOutputObservationSchema;

/**
 * The policy a cardano@1 attestor enforces. The variant tag rides in the
 * policy hash, so adding a variant is additive (ADR 0014).
 */
export type CardanoPolicy = OutputPolicy;

/**
 * Runtime validator for {@link CardanoPolicy}. Dispatches on `kind`, so an
 * unknown kind fails with the valid kinds named.
 */
export const cardanoPolicySchema: z.ZodType<CardanoPolicy> = z.discriminatedUnion('kind', [
  cardanoOutputPolicySchema,
]);

/**
 * Parse a policy into the form every hash and check reads. Every field is
 * canonical as written, so the parsed policy is the normalized one.
 *
 * @throws `ZodError` if the policy fails {@link cardanoPolicySchema}.
 */
export const normalizeCardanoPolicy = (policy: CardanoPolicy): CardanoPolicy =>
  cardanoPolicySchema.parse(policy);

/**
 * Hash a policy under the `cardano@1` law and the claim wire version.
 * Policies that parse the same hash the same. Today it is the output
 * variant's hash; a second variant turns it into a dispatch on `kind`.
 *
 * @throws `ZodError` if the policy fails its variant's schema.
 */
export const cardanoPolicyHashOf: (policy: CardanoPolicy) => Uint8Array = cardanoOutputPolicyHashOf;

/**
 * Runtime validator for a cardano@1 claim: the standard claim, sized by the
 * client's proposal and capped by {@link CARDANO_LIMITS}. `verify` checks the
 * proposal covers every policy slot.
 *
 * The caps run before the slot arrays' elements are parsed, so a remote
 * proposal cannot size the work its own schema does.
 */
export const cardanoClaimSchema = z.preprocess<
  unknown,
  ReturnType<typeof claimSchema<number, number>>,
  ClaimInput<number, number>
>((input, context) => {
  if (typeof input !== 'object' || input === null) {
    return input;
  }
  const bounded: Record<string, unknown> = { ...input };
  const caps = [
    ['values', CARDANO_LIMITS.valueSlots],
    ['byteValues', CARDANO_LIMITS.byteSlots],
    ['present', CARDANO_LIMITS.valueSlots + CARDANO_LIMITS.byteSlots],
  ] as const;
  for (const [key, maximum] of caps) {
    const entries = bounded[key];
    if (!Array.isArray(entries)) {
      continue;
    }
    // One past the cap is enough to fail, so a huge array is not copied.
    const copy = entries.slice(0, maximum + 1);
    bounded[key] = copy;
    if (copy.length > maximum) {
      context.addIssue({
        code: 'too_big',
        origin: 'array',
        maximum,
        inclusive: true,
        input: copy,
        path: [key],
      });
    }
  }
  return bounded;
}, claimSchema<number, number>());

/** The cardano@1 definition, the value `createCardanoDefinition` returns. */
export interface CardanoDefinition {
  /** The kind identifier, `cardano@1`. */
  readonly kind: typeof CARDANO_LAW;
  readonly policy: typeof cardanoPolicySchema;
  readonly evidence: typeof cardanoEvidenceSchema;
  readonly claim: typeof cardanoClaimSchema;
  /** Check a parsed proposal against the observation the attestor read. Throws to reject. */
  verify(
    input: AttestationInput<CardanoPolicy, CardanoObservedEvidence, Claim<number, number>>,
  ): void;
  /** Encode the parsed claim into the flat signed message. */
  message(claim: Claim<number, number>): FlatMessage;
}

/**
 * Derive the claim of one observed event. Today it is the output variant's
 * derivation; a second variant turns it into a dispatch on `policy.kind`.
 *
 * @throws if a policy slot is out of range or in the wrong region for its
 *   fact's type.
 */
export const deriveCardanoClaim: typeof deriveOutputClaim = deriveOutputClaim;
