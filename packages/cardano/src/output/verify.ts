// The output variant's checks: the proposal must say exactly what the observation
// shows. The attestor runs them all; the client runs the first two on its own read.

import type { AttestationInput } from '@thoth/core';
import type { Claim } from '@thoth/core/claim';
import { CLAIM_VERSION } from '@thoth/core/claim';
import { assertPolicySlotsInRange } from '../policy.js';
import {
  assetQuantityOf,
  cardanoOutputPolicyHashOf,
  deriveOutputClaim,
  type OutputLocator,
  type OutputObservation,
  type OutputObservedEvidence,
  type OutputPolicy,
} from './index.js';

/**
 * Require the observation to be of the transaction and output the locator
 * names.
 *
 * @throws on the first failed check.
 */
export const checkLocatorMatchesObservation = (
  locator: OutputLocator,
  observation: OutputObservation,
): void => {
  if (observation.output.txHash !== locator.txHash) {
    throw new Error('observation txHash does not match the locator');
  }
  if (observation.output.outputIndex !== locator.outputIndex) {
    throw new Error('observation outputIndex does not match the locator');
  }
};

/**
 * Require the observation to come from the policy's chain and address, and to
 * carry the pinned asset when one is set. Everything but the depth, which is
 * the attestor's alone: the client's tip can differ from an attestor's without
 * a fork.
 *
 * @throws on the first failed check.
 */
export const checkObservationMatchesPolicy = (
  policy: OutputPolicy,
  observation: OutputObservation,
): void => {
  if (observation.output.address !== policy.address) {
    throw new Error(`observation address ${observation.output.address} is not the policy address`);
  }
  if (observation.networkMagic !== policy.networkMagic) {
    throw new Error(
      `observation network magic ${observation.networkMagic} is not the policy's ${policy.networkMagic}`,
    );
  }
  if (policy.asset !== undefined) {
    assetQuantityOf(policy.asset, observation.output.assets);
  }
};

/**
 * Require the event's block to sit at least the policy's depth below the read
 * tip. Depth 0 accepts the tip block; a block above the tip gives a negative
 * depth, which also fails.
 *
 * @throws if the block is not deep enough.
 */
export const checkBlockDepth = (policy: OutputPolicy, observation: OutputObservation): void => {
  const depth = observation.tipBlockNumber - observation.block.blockNumber;
  if (depth < policy.confirmationDepth) {
    throw new Error(
      `block ${observation.block.blockNumber} is ${depth} blocks below tip ${observation.tipBlockNumber}, need ${policy.confirmationDepth}`,
    );
  }
};

/**
 * Require the proposal to be exactly the claim the observation derives: the
 * window is the block time, the policy hash and version match the policy, and
 * the derived claim equals the proposal field for field.
 *
 * @throws on the first failed check.
 */
export const checkClaimMatchesObservation = (
  input: AttestationInput<OutputPolicy, OutputObservedEvidence, Claim<number, number>>,
): void => {
  const { policy, claim, evidence } = input;
  const observation = evidence.observation;
  if (observation === undefined) {
    throw new Error('observation missing');
  }

  // Structural policy sanity first, so a policy that cannot fit the claim
  // fails before the claim-dependent checks.
  assertPolicySlotsInRange(policy.slots, claim.values.length, claim.byteValues.length);

  const blockTime = BigInt(observation.block.time);
  if (claim.windowStart !== blockTime || claim.windowEnd !== blockTime) {
    throw new Error(`claim window is not the block time ${observation.block.time}`);
  }
  if (claim.version !== CLAIM_VERSION) {
    throw new Error(`claim version is not ${CLAIM_VERSION}`);
  }
  const expectedPolicyHash = cardanoOutputPolicyHashOf(policy);
  if (!Buffer.from(claim.policyHash).equals(expectedPolicyHash)) {
    throw new Error('claim policyHash does not match the policy');
  }

  const derived = deriveOutputClaim({
    policy,
    observation,
    appId: claim.appId,
    holder: claim.holder,
    valueSlots: claim.values.length,
    byteSlots: claim.byteValues.length,
  });
  if (!Buffer.from(claim.subjectHash).equals(derived.subjectHash)) {
    throw new Error('claim subjectHash does not match the observation');
  }
  if (!Buffer.from(claim.salt).equals(derived.salt)) {
    throw new Error('claim salt does not match the observation');
  }
  if (
    claim.values.length !== derived.values.length ||
    claim.values.some((value, index) => value !== derived.values[index])
  ) {
    throw new Error('claim values do not match the observation');
  }
  if (
    claim.byteValues.length !== derived.byteValues.length ||
    claim.byteValues.some((value, index) => {
      const derivedValue = derived.byteValues[index];
      return derivedValue === undefined || !Buffer.from(value).equals(derivedValue);
    })
  ) {
    throw new Error('claim byte values do not match the observation');
  }
  if (
    claim.present.length !== derived.present.length ||
    claim.present.some((present, index) => present !== derived.present[index])
  ) {
    throw new Error('claim present flags do not match the observation');
  }
};

/**
 * Require the proposal to say exactly what the observation shows. The order is
 * the order a client can fix: the observation's identity first, then the
 * policy, then the depth, then the derived claim.
 *
 * @throws on the first failed check.
 */
export const verifyOutputObservation = (
  input: AttestationInput<OutputPolicy, OutputObservedEvidence, Claim<number, number>>,
): void => {
  const { observation } = input.evidence;
  if (observation === undefined) {
    throw new Error('observation missing');
  }
  checkLocatorMatchesObservation(input.evidence, observation);
  checkObservationMatchesPolicy(input.policy, observation);
  checkBlockDepth(input.policy, observation);
  checkClaimMatchesObservation(input);
};
