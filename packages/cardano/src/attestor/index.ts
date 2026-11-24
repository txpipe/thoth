// The cardano@1 attestor instance: the law paired with an operator's key and
// its own Cardano reader.

import type { Attestor, KeyPair } from '@txpipe/thoth-attestor';
import { buildAttestor } from '@txpipe/thoth-attestor';
import type { FlatMessage } from '@txpipe/thoth-core/claim';
import {
  type CardanoDefinition,
  type CardanoLocator,
  type CardanoObservation,
  cardanoObservationSchema,
  deriveCardanoClaim,
} from '../index.js';
import { createCardanoDefinition } from './law.js';

export type { CardanoDefinition };
export { createCardanoDefinition };

/**
 * Build a deployable cardano@1 attestor.
 *
 * `read` is the operator's own Cardano endpoint query. It receives the
 * client's locator and must return the output and the block that contains it;
 * the attestor derives every field that describes the event from that read.
 * Only the app id, holder and slot counts come from the proposal.
 *
 * The returned `attest` throws to reject a policy, evidence or claim that does
 * not match the observation, or a read that does not match its schema.
 *
 * @example
 * ```ts
 * import { cardanoAttestor } from '@txpipe/thoth-cardano/attestor';
 *
 * const attestor = cardanoAttestor({
 *   id: 'cardano-preview-1',
 *   keyPair, // the attestor's signing key
 *   read: async ({ txHash, outputIndex }) => {
 *     // Query your own Cardano endpoint for the output and its block.
 *     return readOutput(txHash, outputIndex); // a CardanoObservation
 *   },
 * });
 * ```
 */
export function cardanoAttestor<PK, S>(parts: {
  id: string;
  keyPair: KeyPair<PK, S, FlatMessage>;
  /** Read the event from the operator's own Cardano endpoint. */
  read: (locator: CardanoLocator) => CardanoObservation | Promise<CardanoObservation>;
}): Attestor<CardanoDefinition, PK, S> {
  const { id, keyPair, read } = parts;
  const definition = createCardanoDefinition();
  const publicKey = keyPair.publicKey;
  return buildAttestor({
    id,
    definition,
    keyPair,
    attest: async (definition, signer, input) => {
      const policy = definition.policy.parse(input.policy);
      const locator = definition.evidence.parse(input.evidence);
      const proposed = definition.claim.parse(input.claim);
      const observation = cardanoObservationSchema.parse(await read(locator));
      // The evidence schema parses only the client's locator; the observation
      // comes from this attestor's own read, so verify receives both.
      definition.verify({ policy, evidence: { ...locator, observation }, claim: proposed });
      const claim = deriveCardanoClaim({
        policy,
        observation,
        appId: proposed.appId,
        holder: proposed.holder,
        valueSlots: proposed.values.length,
        byteSlots: proposed.byteValues.length,
      });
      const message = definition.message(claim);
      const signature = await signer.sign(message);
      return { claim, message, publicKey, signature };
    },
  });
}
