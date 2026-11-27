// Unit tests for the cardano@1 law's verify (`@txpipe/thoth-cardano/attestor`): the
// honest observation, one rejection per check, and the derived-message pin.

import {
  CARDANO_LIMITS,
  cardanoAddressHashOf,
  cardanoClaimSchema,
  deriveCardanoClaim,
  type OutputObservation,
  type OutputPolicy,
} from '@txpipe/thoth-cardano';
import { createCardanoDefinition } from '@txpipe/thoth-cardano/attestor';
import type { Claim } from '@txpipe/thoth-core/claim';
import { claimToMessage } from '@txpipe/thoth-core/claim';
import { describe, expect, it } from 'vitest';
import {
  APP_ID,
  ASSET_OBSERVATION,
  ASSET_POLICY,
  BLOCK_HASH,
  BYTE_FACT_POLICY,
  HOLDER,
  LOCATOR,
  OBSERVATION,
  POLICY,
  TEST_ADDRESS,
} from './fixtures.js';

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

const assetClaimFor = (): Claim<number, number> =>
  deriveCardanoClaim({
    policy: ASSET_POLICY,
    observation: ASSET_OBSERVATION,
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

  it('accepts an observation that carries the pinned asset', () => {
    expect(() =>
      verify({
        policy: ASSET_POLICY,
        evidence: { ...LOCATOR, observation: ASSET_OBSERVATION },
        claim: assetClaimFor(),
      }),
    ).not.toThrow();
  });

  it('rejects an observation that lacks the pinned asset', () => {
    expect(() =>
      verify({
        policy: ASSET_POLICY,
        evidence: { ...LOCATOR, observation: OBSERVATION },
        claim: claimFor(),
      }),
    ).toThrow('policy asset is not in the output');
  });

  it('fills the addressHash and blockHash byte slots', () => {
    const claim = deriveCardanoClaim({
      policy: BYTE_FACT_POLICY,
      observation: OBSERVATION,
      appId: APP_ID,
      holder: HOLDER,
      valueSlots: 5,
      byteSlots: 2,
    });
    expect(claim.byteValues).toEqual([
      cardanoAddressHashOf(TEST_ADDRESS),
      Uint8Array.from(Buffer.from(BLOCK_HASH, 'hex')),
    ]);
    expect(claim.present).toEqual(Array.from({ length: 7 }, () => true));
    expect(() =>
      verify({
        policy: BYTE_FACT_POLICY,
        evidence: { ...LOCATOR, observation: OBSERVATION },
        claim,
      }),
    ).not.toThrow();
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

  it('accepts a block at the tip when the confirmation depth is zero', () => {
    const policy: OutputPolicy = { ...POLICY, confirmationDepth: 0 };
    const observation: OutputObservation = {
      ...OBSERVATION,
      tipBlockNumber: OBSERVATION.block.blockNumber,
    };
    const claim = deriveCardanoClaim({
      policy,
      observation,
      appId: APP_ID,
      holder: HOLDER,
      valueSlots: 5,
      byteSlots: 1,
    });
    expect(() => verify({ policy, evidence: { ...LOCATOR, observation }, claim })).not.toThrow();
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
    expect(() => verify({ policy: badPolicy })).toThrow("outside the claim's 6 slots");
  });

  it('rejects a negative policy slot index', () => {
    const badPolicy: OutputPolicy = { ...POLICY, slots: [{ slot: -1, name: 'lovelace' }] };
    const derive = () =>
      deriveCardanoClaim({
        policy: badPolicy,
        observation: OBSERVATION,
        appId: APP_ID,
        holder: HOLDER,
        valueSlots: 5,
        byteSlots: 1,
      });
    expect(derive).toThrow("outside the claim's 6 slots");
    expect(() => verify({ policy: badPolicy })).toThrow("outside the claim's 6 slots");
  });

  it('caps the claim slot counts the schema accepts', () => {
    const base = claimFor();
    const atLimit = {
      ...base,
      present: Array.from(
        { length: CARDANO_LIMITS.valueSlots + CARDANO_LIMITS.byteSlots },
        () => true,
      ),
      values: Array.from({ length: CARDANO_LIMITS.valueSlots }, () => 0n),
      byteValues: Array.from({ length: CARDANO_LIMITS.byteSlots }, () => new Uint8Array(32)),
    };
    expect(() => cardanoClaimSchema.parse(atLimit)).not.toThrow();
    expect(() =>
      cardanoClaimSchema.parse({
        ...atLimit,
        values: [...atLimit.values, 0n],
        present: [...atLimit.present, true],
      }),
    ).toThrow(/Too big/);
    expect(() =>
      cardanoClaimSchema.parse({
        ...atLimit,
        byteValues: [...atLimit.byteValues, new Uint8Array(32)],
        present: [...atLimit.present, true],
      }),
    ).toThrow(/Too big/);
  });

  it('rejects a claim whose policyHash does not match the policy', () => {
    const base = claimFor();
    expect(() => verify({ claim: { ...base, policyHash: new Uint8Array(32) } })).toThrow(
      'policyHash',
    );
  });

  it('rejects a claim whose version is not 1', () => {
    const base = claimFor();
    expect(() => verify({ claim: { ...base, version: 2n } })).toThrow('version');
  });

  it('refuses to derive an asset quantity without the asset pin', () => {
    const handBuilt: OutputPolicy = { ...POLICY, slots: [{ slot: 3, name: 'assetQuantity' }] };
    expect(() =>
      deriveCardanoClaim({
        policy: handBuilt,
        observation: OBSERVATION,
        appId: APP_ID,
        holder: HOLDER,
        valueSlots: 5,
        byteSlots: 1,
      }),
    ).toThrow("requires the 'asset' pin");
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
      '1,5,2,182,303837957360663282997492429078022244162373961299138760051286757137556939642,187,331696088961062018140437717472803902704679643573449532404696204189334485947',
    );
  });

  it('pins the asset claim message derived from the fixed observation', () => {
    expect(claimToMessage(assetClaimFor()).join(',')).toBe(
      '1,5,2,102,386363916334097245282356200136609270278926858894029555787879277522298771074,187,331696088961062018140437717472803902704679643573449532404696204189334485947',
    );
  });
});
