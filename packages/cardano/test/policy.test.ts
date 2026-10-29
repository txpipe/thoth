// Unit tests for the cardano@1 kind's policy schema and hash
// (`@thoth/cardano`): normalization, the pinned hash bytes, and the rejection
// matrix of the schema's per-selector rules.

import {
  type CardanoPolicy,
  cardanoPolicyHashOf,
  cardanoPolicySchema,
  normalizeCardanoPolicy,
} from '@thoth/cardano';
import { describe, expect, it } from 'vitest';

/** A 28-byte policy id: hex `ab`, repeated. */
const POLICY_ID = 'ab'.repeat(28);

/** A full `script` policy with an asset pin, using every certifiable slot. */
const CANONICAL_POLICY: CardanoPolicy = {
  network: 'preview',
  confirmationDepth: 3,
  selector: {
    kind: 'script',
    address: 'addr_test1qqexample',
    asset: { policyId: POLICY_ID, assetName: 'cd' },
  },
  slots: {
    blockTime: 0,
    slot: 1,
    lovelace: 2,
    quantity: 3,
    policyId: { slot: 4, length: 28 },
    assetName: { slot: 5, length: 1 },
  },
};

const parse = (policy: CardanoPolicy): CardanoPolicy => cardanoPolicySchema.parse(policy);

describe('cardanoPolicySchema', () => {
  it('parses the canonical policy', () => {
    expect(parse(CANONICAL_POLICY)).toEqual(CANONICAL_POLICY);
  });

  it('accepts blockTime and slot for every selector', () => {
    const base = { ...CANONICAL_POLICY, slots: { blockTime: 0, slot: 1 } };
    expect(
      parse({ ...base, selector: { kind: 'script', address: 'addr_test1' } }).selector.kind,
    ).toBe('script');
    expect(
      parse({
        ...base,
        selector: { kind: 'mint', asset: { policyId: POLICY_ID, assetName: 'cd' } },
      }).selector.kind,
    ).toBe('mint');
    expect(parse({ ...base, selector: { kind: 'delegation' } }).selector.kind).toBe('delegation');
  });

  it('rejects a policy with no slots', () => {
    expect(() => parse({ ...CANONICAL_POLICY, slots: {} })).toThrow('at least one slot');
  });

  it('rejects duplicate slot indices across names', () => {
    expect(() => parse({ ...CANONICAL_POLICY, slots: { blockTime: 0, lovelace: 0 } })).toThrow(
      'declared once',
    );
    expect(() =>
      parse({ ...CANONICAL_POLICY, slots: { blockTime: 4, policyId: { slot: 4, length: 28 } } }),
    ).toThrow('declared once');
  });

  it('rejects a negative or fractional slot index, and a bad depth', () => {
    expect(() => parse({ ...CANONICAL_POLICY, slots: { blockTime: -1 } })).toThrow();
    expect(() => parse({ ...CANONICAL_POLICY, slots: { blockTime: 0.5 } })).toThrow();
    expect(() =>
      parse({ ...CANONICAL_POLICY, slots: { policyId: { slot: 4, length: 28.5 } } }),
    ).toThrow();
    expect(() => parse({ ...CANONICAL_POLICY, confirmationDepth: 1.5 })).toThrow();
    expect(() => parse({ ...CANONICAL_POLICY, confirmationDepth: -1 })).toThrow();
  });

  it('rejects a byte slot with a missing or out-of-range length', () => {
    expect(() =>
      parse({ ...CANONICAL_POLICY, slots: { assetName: { slot: 5 } as never } }),
    ).toThrow();
    expect(() =>
      parse({ ...CANONICAL_POLICY, slots: { assetName: { slot: 5, length: 0 } } }),
    ).toThrow();
    expect(() =>
      parse({ ...CANONICAL_POLICY, slots: { assetName: { slot: 5, length: 33 } } }),
    ).toThrow();
  });

  it('rejects a policyId or poolId slot whose length is not 28', () => {
    expect(() =>
      parse({ ...CANONICAL_POLICY, slots: { policyId: { slot: 4, length: 27 } } }),
    ).toThrow('policyId is 28 bytes');
    expect(() =>
      parse({
        ...CANONICAL_POLICY,
        selector: { kind: 'delegation' },
        slots: { poolId: { slot: 4, length: 29 } },
      }),
    ).toThrow('poolId is 28 bytes');
  });

  it('rejects a slot name its selector cannot certify', () => {
    expect(() =>
      parse({
        ...CANONICAL_POLICY,
        selector: { kind: 'script', address: 'addr_test1' },
        slots: { quantity: 0 },
      }),
    ).toThrow('is not certifiable for the script selector');
    expect(() =>
      parse({
        ...CANONICAL_POLICY,
        selector: { kind: 'mint', asset: { policyId: POLICY_ID, assetName: 'cd' } },
        slots: { lovelace: 0 },
      }),
    ).toThrow('is not certifiable for the mint selector');
    expect(() =>
      parse({
        ...CANONICAL_POLICY,
        selector: { kind: 'delegation' },
        slots: { lovelace: 0 },
      }),
    ).toThrow('is not certifiable for the delegation selector');
  });

  it('rejects an unknown network and an unknown selector kind', () => {
    expect(() => parse({ ...CANONICAL_POLICY, network: 'banana' as never })).toThrow();
    expect(() => parse({ ...CANONICAL_POLICY, selector: { kind: 'burn' } as never })).toThrow();
  });

  it('rejects a malformed asset, and a script selector without an address', () => {
    expect(() =>
      parse({
        ...CANONICAL_POLICY,
        selector: { kind: 'mint', asset: { policyId: 'zz'.repeat(28), assetName: 'cd' } },
      }),
    ).toThrow('expected hex');
    expect(() =>
      parse({
        ...CANONICAL_POLICY,
        selector: { kind: 'mint', asset: { policyId: POLICY_ID, assetName: 'abc' } },
      }),
    ).toThrow('even hex');
    expect(() =>
      parse({
        ...CANONICAL_POLICY,
        selector: { kind: 'mint', asset: { policyId: POLICY_ID, assetName: 'ab'.repeat(33) } },
      }),
    ).toThrow('at most 32 bytes');
    expect(() =>
      parse({ ...CANONICAL_POLICY, selector: { kind: 'script', address: '' } }),
    ).toThrow();
  });
});

describe('cardanoPolicyHashOf', () => {
  it('hashes equivalent policies the same, whatever the key order', () => {
    const reordered = {
      confirmationDepth: CANONICAL_POLICY.confirmationDepth,
      slots: CANONICAL_POLICY.slots,
      selector: CANONICAL_POLICY.selector,
      network: CANONICAL_POLICY.network,
    };
    expect(cardanoPolicyHashOf(reordered)).toEqual(cardanoPolicyHashOf(CANONICAL_POLICY));
  });

  it('normalizes before hashing', () => {
    expect(cardanoPolicyHashOf(CANONICAL_POLICY)).toEqual(
      cardanoPolicyHashOf(normalizeCardanoPolicy(CANONICAL_POLICY)),
    );
  });

  it('changes the hash when one field changes', () => {
    const baseline = cardanoPolicyHashOf(CANONICAL_POLICY);
    const mutations: CardanoPolicy[] = [
      { ...CANONICAL_POLICY, network: 'mainnet' },
      { ...CANONICAL_POLICY, confirmationDepth: 4 },
      {
        ...CANONICAL_POLICY,
        selector: { kind: 'delegation' },
        slots: { poolId: { slot: 4, length: 28 } },
      },
      { ...CANONICAL_POLICY, slots: { ...CANONICAL_POLICY.slots, lovelace: 6 } },
      {
        ...CANONICAL_POLICY,
        selector: {
          kind: 'script',
          address: 'addr_test1qqexample',
          asset: { policyId: POLICY_ID, assetName: 'ef' },
        },
      },
    ];
    for (const mutated of mutations) {
      expect(cardanoPolicyHashOf(mutated)).not.toEqual(baseline);
    }
  });

  it('pins the canonical policy hash to its bytes', () => {
    expect(Buffer.from(cardanoPolicyHashOf(CANONICAL_POLICY)).toString('hex')).toBe(
      'b300cb1f7b0a797faf94ad4a31f6a893cdb8744d5b92d67a6119001cbe6421ee',
    );
  });
});
