// Unit tests for the cardano@1 attestor (`@thoth/cardano/attestor`): the read
// is the source of the claim, the proposal is checked, and the locator schema
// is strict.

import type { KeyPair } from '@thoth/attestor';
import { deriveCardanoClaim, type OutputLocator, type OutputObservation } from '@thoth/cardano';
import { cardanoAttestor } from '@thoth/cardano/attestor';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import { describe, expect, it } from 'vitest';
import { APP_ID, HOLDER, LOCATOR, OBSERVATION, POLICY } from './fixtures.js';

const keyPair: KeyPair<string, string, FlatMessage> = {
  publicKey: 'test-public-key',
  signer: { sign: (message) => `signed:${message.join(',')}` },
};

const claimFor = (observation: OutputObservation = OBSERVATION): Claim<number, number> =>
  deriveCardanoClaim({
    policy: POLICY,
    observation,
    appId: APP_ID,
    holder: HOLDER,
    valueSlots: 5,
    byteSlots: 1,
  });

const attestorFor = (observation: OutputObservation = OBSERVATION) => {
  const reads: OutputLocator[] = [];
  const attestor = cardanoAttestor({
    id: 'cardano-test-1',
    keyPair,
    read: (locator) => {
      reads.push(locator);
      return observation;
    },
  });
  return { attestor, reads };
};

describe('cardanoAttestor', () => {
  it('attests the claim derived from its own read, not the proposal', async () => {
    const observed = {
      ...OBSERVATION,
      output: { ...OBSERVATION.output, lovelace: 7_000_000n },
    };
    const { attestor, reads } = attestorFor(observed);
    const expected = claimFor(observed);
    const proposed: Claim<number, number> = {
      ...claimFor(observed),
      version: 9n,
      policyHash: new Uint8Array(32),
    };

    const attestation = await attestor.attest({
      policy: POLICY,
      evidence: LOCATOR,
      claim: proposed,
    });

    expect(reads).toEqual([LOCATOR]);
    expect(attestation.claim).toEqual(expected);
    expect(attestation.message).toEqual(claimToMessage(expected));
    expect(attestation.publicKey).toBe('test-public-key');
    expect(attestation.signature).toBe(`signed:${claimToMessage(expected).join(',')}`);
  });

  it('keeps appId and holder from the proposal', async () => {
    const appId = new Uint8Array(32).fill(0x11);
    const holder = new Uint8Array(32).fill(0x22);
    const { attestor } = attestorFor();

    const attestation = await attestor.attest({
      policy: POLICY,
      evidence: LOCATOR,
      claim: { ...claimFor(), appId, holder },
    });

    expect(attestation.claim.appId).toEqual(appId);
    expect(attestation.claim.holder).toEqual(holder);
    expect(attestation.claim.subjectHash).toEqual(claimFor().subjectHash);
  });

  it('refuses a proposal whose window is not the block time', async () => {
    const { attestor } = attestorFor();
    await expect(
      attestor.attest({
        policy: POLICY,
        evidence: LOCATOR,
        claim: { ...claimFor(), windowStart: 1n },
      }),
    ).rejects.toThrow('claim window');
  });

  it('refuses a proposal with another subject hash', async () => {
    const { attestor } = attestorFor();
    await expect(
      attestor.attest({
        policy: POLICY,
        evidence: LOCATOR,
        claim: { ...claimFor(), subjectHash: new Uint8Array(32) },
      }),
    ).rejects.toThrow('subjectHash');
  });

  it('refuses a proposal with another salt', async () => {
    const { attestor } = attestorFor();
    await expect(
      attestor.attest({
        policy: POLICY,
        evidence: LOCATOR,
        claim: { ...claimFor(), salt: new Uint8Array(32) },
      }),
    ).rejects.toThrow('salt');
  });

  it('refuses a proposal with another value', async () => {
    const { attestor } = attestorFor();
    const base = claimFor();
    const values = base.values.map((value, index) => (index === 3 ? value + 1n : value));
    await expect(
      attestor.attest({ policy: POLICY, evidence: LOCATOR, claim: { ...base, values } }),
    ).rejects.toThrow('values do not match');
  });

  it('refuses a client-supplied observation in the evidence', async () => {
    const { attestor, reads } = attestorFor();
    const evidence = { ...LOCATOR, observation: OBSERVATION } as unknown as OutputLocator;

    await expect(
      attestor.attest({ policy: POLICY, evidence, claim: claimFor() }),
    ).rejects.toThrow();

    expect(reads).toHaveLength(0);
  });
});
