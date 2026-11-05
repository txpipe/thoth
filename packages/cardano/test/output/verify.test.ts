// Unit tests for the cardano@1 law's verify (`@thoth/cardano/attestor`): the
// honest observation, one rejection per check, and the derived-message pin.

import { deriveCardanoClaim, type OutputObservation } from '@thoth/cardano';
import { createCardanoDefinition } from '@thoth/cardano/attestor';
import type { Claim } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import { describe, expect, it } from 'vitest';
import { APP_ID, BLOCK_HASH, HOLDER, LOCATOR, OBSERVATION, POLICY } from './fixtures.js';

const definition = createCardanoDefinition();

const claimFor = (observation: OutputObservation = OBSERVATION): Claim<number, 0> =>
  deriveCardanoClaim({ policy: POLICY, observation, appId: APP_ID, holder: HOLDER, valueSlots: 5 });

const verify = (options: {
  evidence?: { txHash: string; outputIndex: number; observation?: OutputObservation };
  claim?: Claim<number, 0>;
}): void =>
  definition.verify({
    policy: POLICY,
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

  it('rejects a claim that does not cover every policy slot', () => {
    const base = claimFor();
    const short: Claim<number, 0> = {
      ...base,
      present: base.present.slice(0, 4),
      values: base.values.slice(0, 4),
    };
    expect(() => verify({ claim: short })).toThrow("outside the claim's 4 value slots");
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

  it('rejects another present flag', () => {
    const base = claimFor();
    const present = base.present.map((flag, index) => (index === 3 ? false : flag));
    expect(() => verify({ claim: { ...base, present } })).toThrow('present flags do not match');
  });

  it('pins the message derived from the fixed observation', () => {
    expect(claimToMessage(claimFor()).join(',')).toBe(
      '1,226854911280625642308916404954512140970,226854911280625642308916404954512140970,192220423080039531133528621049496996646,236539722718139341599763164022600328549,1700000000,1700000000,152863117808294749381153575209862223096,255484261701604909417534612838043798448,249540402408688206539808045449963355067,249540402408688206539808045449963355067,50282554025485700236719036188234476089,187213460572670018709882692108604400772,0,1,1,1,1,1,1700000000,123456,1000,5000000,1',
    );
  });
});
