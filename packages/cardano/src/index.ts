// The cardano@1 chain-event kind: the policy union, policy hash and claim
// schema shared by every variant. The output variant lives under ./output/.

import type { AttestationInput } from '@thoth/core';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { claimSchema } from '@thoth/core/claim';
import type { CanonicalValue } from '@thoth/core/claim-context';
import { z } from 'zod';
import { cardanoAddressHashOf } from './bytes.js';
import {
  cardanoOutputEvidenceSchema,
  cardanoOutputObservationSchema,
  cardanoOutputPolicySchema,
  cardanoOutputSaltOf,
  cardanoOutputSubjectHashOf,
  cardanoOutputSubjectOf,
  deriveOutputClaim,
  type OutputLocator,
  type OutputObservation,
  type OutputObservedEvidence,
  type OutputPolicy,
  type OutputSubject,
  type OutputSubjectInput,
} from './output/index.js';
import {
  CARDANO_FACTS,
  CARDANO_LAW,
  CARDANO_NETWORKS,
  type CardanoFact,
  type CardanoNetwork,
  type CardanoPolicyBase,
  type CardanoSlot,
  policyHashOfCardano,
} from './policy.js';

export type {
  CardanoFact,
  CardanoNetwork,
  CardanoPolicyBase,
  CardanoSlot,
  OutputLocator,
  OutputObservation,
  OutputObservedEvidence,
  OutputPolicy,
  OutputSubject,
  OutputSubjectInput,
};
export {
  CARDANO_FACTS,
  CARDANO_LAW,
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
 * policy hash, so adding a variant is additive (ADR 0013).
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
  policyHashOfCardano(normalizeCardanoPolicy(policy) as CanonicalValue);

/**
 * Runtime validator for a cardano@1 claim: the standard numeric claim, sized
 * by the client's proposal. `verify` checks the proposal covers every policy
 * slot.
 */
export const cardanoClaimSchema = claimSchema<number, 0>();

/** The cardano@1 definition, the value `createCardanoDefinition` returns. */
export interface CardanoDefinition {
  /** The kind identifier, `cardano@1`. */
  readonly kind: typeof CARDANO_LAW;
  readonly policy: typeof cardanoPolicySchema;
  readonly evidence: typeof cardanoEvidenceSchema;
  readonly claim: typeof cardanoClaimSchema;
  /** Check a parsed proposal against the observation the attestor read. Throws to reject. */
  verify(input: AttestationInput<CardanoPolicy, CardanoObservedEvidence, Claim<number, 0>>): void;
  /** Encode the parsed claim into the flat signed message. */
  message(claim: Claim<number, 0>): FlatMessage;
}

/**
 * Derive the claim of one observed output. `appId`, `holder` and the value
 * count come from the proposal; every other field comes from the observation
 * and the policy, never from the proposal.
 *
 * @throws if a policy slot index is outside `valueSlots`.
 */
export const deriveCardanoClaim = (options: {
  policy: CardanoPolicy;
  observation: CardanoObservation;
  /** 32 bytes, from the proposal. */
  appId: Uint8Array;
  /** 32 bytes, from the proposal. */
  holder: Uint8Array;
  /** The contract's numeric value count, from the proposal's `values.length`. */
  valueSlots: number;
}): Claim<number, 0> =>
  deriveOutputClaim({
    policy: options.policy,
    observation: options.observation,
    appId: options.appId,
    holder: options.holder,
    valueSlots: options.valueSlots,
  });
