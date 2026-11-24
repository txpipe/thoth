// The tlsn@1 attestor: check a presentation against the pinned notary and the policy,
// then sign the claim derived from what the notary attested.

import { isDeepStrictEqual } from 'node:util';
import type { Attestor, KeyPair } from '@txpipe/thoth-attestor';
import { buildAttestor, defineAttestor } from '@txpipe/thoth-attestor';
import type { AttestationInput } from '@txpipe/thoth-core';
import type { Claim, FlatMessage } from '@txpipe/thoth-core/claim';
import { claimToMessage } from '@txpipe/thoth-core/claim';
import {
  assertPolicySlotsInRange,
  deriveTlsnClaim,
  observePresentation,
  subjectRequestOf,
  TLSN_LAW,
  type TlsnDefinition,
  type TlsnEvidence,
  type TlsnNotaryKey,
  type TlsnObservation,
  type TlsnPolicy,
  type TlsnPresentationVerifier,
  tlsnClaimContextDigestOf,
  tlsnClaimSchema,
  tlsnEvidenceSchema,
  tlsnPolicySchema,
  verifiedPresentationSchema,
} from '../index.js';

/** What an operator pins: its own notary's key, and how presentations are verified. */
export interface TlsnTrustAnchors {
  /** The public key of the operator's own notary, as `thoth-tlsn notary-key` prints it. */
  readonly notaryKey: TlsnNotaryKey;
  /** The presentation verifier, such as `nativePresentationVerifier` from `./verifier`. */
  readonly verifier: TlsnPresentationVerifier;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

/**
 * Run every tlsn@1 check on parsed input, in order, and return the observation
 * the claim derives from.
 *
 * 1. Every policy slot fits the proposal's slot counts.
 * 2. The presentation verifies: notary signature, certificate chain, transcript proof.
 * 3. The notary is the pinned one.
 * 4. The presentation satisfies the policy (see `observePresentation`).
 * 5. The notary saw the server inside the proposed window.
 * 6. The notary signed this claim's claim context digest, and the salt is that digest.
 * 7. The proposal says exactly what the derived claim says.
 *
 * @throws on the first failed check.
 */
export const checkTlsnInput = async (
  input: AttestationInput<TlsnPolicy, TlsnEvidence, Claim<number, number>>,
  anchors: TlsnTrustAnchors,
): Promise<TlsnObservation> => {
  const { policy, evidence, claim } = input;
  assertPolicySlotsInRange(policy, claim.values.length, claim.byteValues.length);

  const verified = verifiedPresentationSchema.parse(
    await anchors.verifier.verify(evidence.presentation),
  );
  // The verifier only shows that the presentation's own key signed it. Without this
  // check a client could run its own notary and have any response certified.
  if (
    verified.notaryKey.alg !== anchors.notaryKey.alg ||
    verified.notaryKey.key.toLowerCase() !== anchors.notaryKey.key.toLowerCase()
  ) {
    throw new Error("the presentation is signed by another notary than this attestor's");
  }

  const observation = observePresentation(verified, policy);
  if (observation.time < claim.windowStart || observation.time > claim.windowEnd) {
    throw new Error(
      `notary observation ${observation.time} is outside the claim window [${claim.windowStart}, ${claim.windowEnd}]`,
    );
  }

  const expectedContext = tlsnClaimContextDigestOf({
    policy,
    request: subjectRequestOf(observation),
    holder: claim.holder,
    windowStart: claim.windowStart,
    windowEnd: claim.windowEnd,
  });
  if (!sameBytes(observation.claimContext, expectedContext)) {
    throw new Error(
      "the notary-signed claim context digest is not this claim's (holder, window, policy or subject differ)",
    );
  }
  if (!sameBytes(claim.salt, observation.claimContext)) {
    throw new Error('claim salt is not the claim context digest the notary signed');
  }

  const derived = deriveTlsnClaim({
    observation,
    policy,
    appId: claim.appId,
    holder: claim.holder,
    valueSlots: claim.values.length,
    byteSlots: claim.byteValues.length,
    windowStart: claim.windowStart,
    windowEnd: claim.windowEnd,
  });
  if (!isDeepStrictEqual(derived, { ...claim })) {
    throw new Error('the proposed claim does not say what the presentation shows');
  }
  return observation;
};

/**
 * Create the tlsn@1 definition for one operator: the three schemas, a `verify`
 * that runs {@link checkTlsnInput}, and `message` as `claimToMessage`.
 */
export function createTlsnDefinition(anchors: TlsnTrustAnchors): TlsnDefinition {
  return defineAttestor({
    kind: TLSN_LAW,
    policy: tlsnPolicySchema,
    evidence: tlsnEvidenceSchema,
    claim: tlsnClaimSchema,
    verify: async (input: AttestationInput<TlsnPolicy, TlsnEvidence, Claim<number, number>>) => {
      await checkTlsnInput(input, anchors);
    },
    message: (claim: Claim<number, number>): FlatMessage => claimToMessage(claim),
  });
}

/**
 * Build a deployable tlsn@1 attestor.
 *
 * It accepts presentations only from the notary whose key it pins, runs
 * {@link checkTlsnInput}, then derives its own claim from the presentation,
 * sized to the proposal's slot counts, and signs that.
 *
 * @example
 * ```ts
 * import { tlsnAttestor } from '@txpipe/thoth-tlsn/attestor';
 * import { nativePresentationVerifier } from '@txpipe/thoth-tlsn/verifier';
 *
 * const attestor = tlsnAttestor({
 *   id: 'tlsn-github-1',
 *   keyPair, // the attestor's signing key, not the notary's
 *   notaryKey: { alg: 'k256', key: '03…' }, // from `thoth-tlsn notary-key`
 *   verifier: nativePresentationVerifier({ binary: '/usr/local/bin/thoth-tlsn' }),
 * });
 * ```
 */
export function tlsnAttestor<PK, S>(
  parts: TlsnTrustAnchors & {
    id: string;
    keyPair: KeyPair<PK, S, FlatMessage>;
  },
): Attestor<TlsnDefinition, PK, S> {
  const { id, keyPair, notaryKey, verifier } = parts;
  const anchors = { notaryKey, verifier };
  const publicKey = keyPair.publicKey;
  return buildAttestor({
    id,
    definition: createTlsnDefinition(anchors),
    keyPair,
    attest: async (definition, signer, input) => {
      const policy = definition.policy.parse(input.policy);
      const evidence = definition.evidence.parse(input.evidence);
      const proposed = definition.claim.parse(input.claim);
      // The same checks `definition.verify` runs, kept to reuse the observation
      // instead of verifying the presentation twice.
      const observation = await checkTlsnInput({ policy, evidence, claim: proposed }, anchors);
      const claim = deriveTlsnClaim({
        observation,
        policy,
        appId: proposed.appId,
        holder: proposed.holder,
        valueSlots: proposed.values.length,
        byteSlots: proposed.byteValues.length,
        windowStart: proposed.windowStart,
        windowEnd: proposed.windowEnd,
      });
      const message = claimToMessage(claim);
      const signature = await signer.sign(message);
      return { claim, message, publicKey, signature };
    },
  });
}
