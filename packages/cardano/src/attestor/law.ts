// The cardano@1 law: the schemas and checks every cardano@1 attestor runs, with
// no key material. Paired with a key by `cardanoAttestor` in `./index.js`.

import { defineAttestor } from '@txpipe/thoth-attestor';
import type { Claim, FlatMessage } from '@txpipe/thoth-core/claim';
import { claimToMessage } from '@txpipe/thoth-core/claim';
import {
  CARDANO_LAW,
  type CardanoDefinition,
  cardanoClaimSchema,
  cardanoEvidenceSchema,
  cardanoPolicySchema,
} from '../index.js';
import { verifyOutputObservation } from '../output/verify.js';

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
    message: (claim: Claim<number, number>): FlatMessage => claimToMessage(claim),
  });
