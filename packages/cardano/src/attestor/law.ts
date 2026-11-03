// The cardano@1 law: the schemas and checks every cardano@1 attestor runs, with
// no key material. Paired with a key by `cardanoAttestor` in `./index.js`.

import { defineAttestor } from '@thoth/attestor';
import type { AttestationInput } from '@thoth/core';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import {
  CARDANO_LAW,
  type CardanoObservedEvidence,
  type CardanoPolicy,
  cardanoClaimSchema,
  cardanoEvidenceSchema,
  cardanoPolicySchema,
} from '../index.js';
import { verifyOutputObservation } from '../output/verify.js';

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
 * Create the cardano@1 law: the policy union, the output variant's evidence
 * schema and checks, the numeric claim schema, and `claimToMessage`.
 *
 * The output variant is the only one today. A second variant adds its case to
 * `verify` here and to the attestor's evidence, read and derivation dispatch.
 */
export const createCardanoDefinition = (): CardanoDefinition =>
  defineAttestor({
    kind: CARDANO_LAW,
    policy: cardanoPolicySchema,
    evidence: cardanoEvidenceSchema,
    claim: cardanoClaimSchema,
    verify: verifyOutputObservation,
    message: (claim: Claim<number, 0>): FlatMessage => claimToMessage(claim),
  });
