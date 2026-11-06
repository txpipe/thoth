// Unit tests for the cardano@1 law's verify (`@thoth/cardano/attestor`): the
// honest observation, one rejection per check, and the derived-message pin.

import { deriveCardanoClaim, type OutputObservation, type OutputPolicy } from '@thoth/cardano';
import { createCardanoDefinition } from '@thoth/cardano/attestor';
import type { Claim } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import { describe, expect, it } from 'vitest';
import { APP_ID, BLOCK_HASH, HOLDER, LOCATOR, OBSERVATION, POLICY } from './fixtures.js';

const definition = createCardanoDefinition();

const claimFor = (observation: OutputObservation = OBSERVATION): Claim<number, number> =>
  deriveCardanoClaim({
    policy: POLICY,
    observation,
    appId: APP_ID,
    holder: HOLDER,
    valueSlots: 5,
    byteSlots: 1,
  });

const verify = (options: {
  policy?: OutputPolicy;
  evidence?: { txHash: string; outputIndex: number; observation?: OutputObservation };
  claim?: Claim<number, number>;
}): void =>
  definition.verify({
    policy: options.policy ?? POLICY,
    evidence: options.evidence ?? { ...LOCATOR, observation: OBSERVATION },
    claim: options.claim ?? claimFor(),
  });

describe('cardano verify', () => {
  it('accepts an observation that matches the locator, policy and proposal', () => {
    expect(() => verify({})).not.toThrow();
  });

  it('rejects a missing observation', () => {
    expect(() => verify({ evidence: { ...LOCATOR } })).toThrow('observation missing');
  });

  it('rejects an observation whose txHash differs from the locator', () => {
    expect(() =>
      verify({ evidence: { ...LOCATOR, txHash: BLOCK_HASH, observation: OBSERVATION } }),
    ).toThrow('txHash does not match the locator');
  });

  it('rejects an observation whose outputIndex differs from the locator', () => {
    expect(() =>
      verify({ evidence: { ...LOCATOR, outputIndex: 2, observation: OBSERVATION } }),
    ).toThrow('outputIndex does not match the locator');
  });

  it('rejects an output at another address', () => {
    const observation = {
      ...OBSERVATION,
      output: { ...OBSERVATION.output, address: `addr_test1${'p'.repeat(53)}` },
    };
    expect(() =>
      verify({ evidence: { ...LOCATOR, observation }, claim: claimFor(observation) }),
    ).toThrow('is not the policy address');
  });

  it('rejects another network magic', () => {
    const observation = { ...OBSERVATION, networkMagic: 1 };
    expect(() =>
      verify({ evidence: { ...LOCATOR, observation }, claim: claimFor(observation) }),
    ).toThrow('network magic');
  });

  it('rejects a block that is not deep enough', () => {
    const observation = { ...OBSERVATION, tipBlockNumber: 1002 };
    expect(() =>
      verify({ evidence: { ...LOCATOR, observation }, claim: claimFor(observation) }),
    ).toThrow('need 3');
  });

  it('rejects a block above the tip', () => {
    const observation = { ...OBSERVATION, tipBlockNumber: 999 };
    expect(() =>
      verify({ evidence: { ...LOCATOR, observation }, claim: claimFor(observation) }),
    ).toThrow('need 3');
  });

  it('rejects a window that is not the block time', () => {
    const base = claimFor();
    expect(() => verify({ claim: { ...base, windowStart: 1n } })).toThrow('claim window');
    expect(() => verify({ claim: { ...base, windowEnd: 1n } })).toThrow('claim window');
  });

  it('rejects a numeric fact mapped past the claim numeric slots', () => {
    const badPolicy: OutputPolicy = { ...POLICY, slots: [{ slot: 5, name: 'outputIndex' }] };
    expect(() => verify({ policy: badPolicy })).toThrow(
      'policy fact outputIndex at slot 5 targets a byte slot',
    );
  });

  it('rejects a byte fact mapped into the numeric region', () => {
    const badPolicy: OutputPolicy = { ...POLICY, slots: [{ slot: 0, name: 'txHash' }] };
    expect(() => verify({ policy: badPolicy })).toThrow(
      'policy fact txHash at slot 0 targets a numeric slot',
    );
  });

  it('rejects a fact mapped beyond the claim slots', () => {
    const badPolicy: OutputPolicy = { ...POLICY, slots: [{ slot: 6, name: 'txHash' }] };
    expect(() => verify({ policy: badPolicy })).toThrow("outside the claim's 6 value slots");
  });

  it('rejects another subject hash', () => {
    const base = claimFor();
    expect(() => verify({ claim: { ...base, subjectHash: new Uint8Array(32) } })).toThrow(
      'subjectHash',
    );
  });

  it('rejects another salt', () => {
    const base = claimFor();
    expect(() => verify({ claim: { ...base, salt: new Uint8Array(32) } })).toThrow('salt');
  });

  it('rejects another value', () => {
    const base = claimFor();
    const values = base.values.map((value, index) => (index === 3 ? value + 1n : value));
    expect(() => verify({ claim: { ...base, values } })).toThrow('values do not match');
  });

  it('rejects another byte value', () => {
    const base = claimFor();
    const byteValues = base.byteValues.map((value) => {
      const flipped = new Uint8Array(value);
      flipped[0] ^= 0xff;
      return flipped;
    });
    expect(() => verify({ claim: { ...base, byteValues } })).toThrow('byte values do not match');
  });

  it('rejects another present flag', () => {
    const base = claimFor();
    const present = base.present.map((flag, index) => (index === 3 ? false : flag));
    expect(() => verify({ claim: { ...base, present } })).toThrow('present flags do not match');
  });

  it('pins the message derived from the fixed observation', () => {
    expect(claimToMessage(claimFor()).join(',')).toBe(
      '1,226854911280625642308916404954512140970,226854911280625642308916404954512140970,239491174588143157753471590601048204648,253783133056544356928925031460646215332,1700000000,1700000000,152863117808294749381153575209862223096,255484261701604909417534612838043798448,249540402408688206539808045449963355067,249540402408688206539808045449963355067,50282554025485700236719036188234476089,187213460572670018709882692108604400772,2,1,1,1,1,1,1,1,1700000000,123456,1000,5000000,1,273560334191342686313693311856911699405,273560334191342686313693311856911699405',
    );
  });
});
