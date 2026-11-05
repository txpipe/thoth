// The output variant's checks: the proposal must say exactly what the
// observation shows.

import type { AttestationInput } from '@thoth/core';
import type { Claim } from '@thoth/core/claim';
import { deriveOutputClaim, type OutputObservedEvidence, type OutputPolicy } from './index.js';

/**
 * Require the proposal to say exactly what the observation shows. The order is
 * the order a client can fix: the observation's identity first, then the
 * policy, then the derived claim.
 *
 * The observation is optional in the evidence type, so a direct `verify` call
 * without one is rejected rather than treated as nothing to check.
 *
 * @throws on the first failed check.
 */
export const verifyOutputObservation = (
  input: AttestationInput<OutputPolicy, OutputObservedEvidence, Claim<number, 0>>,
): void => {
  const { observation } = input.evidence;
  if (observation === undefined) {
    throw new Error('observation missing');
  }

  const { policy, claim, evidence } = input;
  const { block, output } = observation;
  if (output.txHash !== evidence.txHash) {
    throw new Error('observation txHash does not match the locator');
  }
  if (output.outputIndex !== evidence.outputIndex) {
    throw new Error('observation outputIndex does not match the locator');
  }
  if (output.address !== policy.address) {
    throw new Error(`observation address ${output.address} is not the policy address`);
  }
  if (observation.networkMagic !== policy.networkMagic) {
    throw new Error(
      `observation network magic ${observation.networkMagic} is not the policy's ${policy.networkMagic}`,
    );
  }

  // Depth 0 accepts the tip block. A block above the tip gives a negative
  // depth, which also fails.
  const depth = observation.tipBlockNumber - block.blockNumber;
  if (depth < policy.confirmationDepth) {
    throw new Error(
      `block ${block.blockNumber} is ${depth} blocks below tip ${observation.tipBlockNumber}, need ${policy.confirmationDepth}`,
    );
  }

  const blockTime = BigInt(block.time);
  if (claim.windowStart !== blockTime || claim.windowEnd !== blockTime) {
    throw new Error(`claim window is not the block time ${block.time}`);
  }

  for (const { slot } of policy.slots) {
    if (slot >= claim.values.length) {
      throw new Error(
        `policy slot ${slot} is outside the claim's ${claim.values.length} value slots`,
      );
    }
  }

  const derived = deriveOutputClaim({
    policy,
    observation,
    appId: claim.appId,
    holder: claim.holder,
    valueSlots: claim.values.length,
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
    claim.present.length !== derived.present.length ||
    claim.present.some((present, index) => present !== derived.present[index])
  ) {
    throw new Error('claim present flags do not match the observation');
  }
};
