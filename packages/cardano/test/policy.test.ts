// Unit tests for the cardano@1 kind's policy schema and hash
// (`@thoth/cardano`): normalization, the pinned hash bytes, and the rejection
// matrix of the variants' slot sets and the cross-field rules.

import {
  type AssetOutputPolicy,
  type CardanoPolicy,
  cardanoPolicyHashOf,
  cardanoPolicySchema,
  normalizeCardanoPolicy,
  type OutputPolicy,
} from '@thoth/cardano';
import { describe, expect, it } from 'vitest';

/** A 28-byte policy id: hex `ab`, repeated. */
const POLICY_ID = 'ab'.repeat(28);

/** A well-formed preview payment address (bech32, lowercase). */
const TEST_ADDRESS = 'addr_test1qqexample';

const OUTPUT: OutputPolicy = {
  kind: 'output',
  network: 'preview',
  confirmationDepth: 3,
  address: TEST_ADDRESS,
  slots: { blockTime: 0, slot: 1, blockNumber: 2, lovelace: 3 },
};

const ASSET_OUTPUT: AssetOutputPolicy = {
  kind: 'asset-output',
  network: 'preview',
  confirmationDepth: 3,
  address: TEST_ADDRESS,
  asset: { policyId: POLICY_ID, assetName: 'cd' },
  slots: {
    blockTime: 0,
    slot: 1,
    blockNumber: 2,
    quantity: 3,
    policyId: { slot: 4, length: 28 },
    assetName: { slot: 5, length: 1 },
  },
};

const parse = (policy: unknown): CardanoPolicy => cardanoPolicySchema.parse(policy);

describe('cardanoPolicySchema', () => {
  it('parses each variant', () => {
    expect(parse(OUTPUT)).toEqual(OUTPUT);
    expect(parse(ASSET_OUTPUT)).toEqual(ASSET_OUTPUT);
  });

  it('accepts a zero confirmation depth, leaving the depth to the app', () => {
    expect(parse({ ...OUTPUT, confirmationDepth: 0 }).confirmationDepth).toBe(0);
  });

  it('requires the common slots in every variant', () => {
    const { blockNumber: _, ...withoutBlockNumber } = OUTPUT.slots;
    expect(() => parse({ ...OUTPUT, slots: withoutBlockNumber })).toThrow();
    const { blockTime: __, ...withoutBlockTime } = ASSET_OUTPUT.slots;
    expect(() => parse({ ...ASSET_OUTPUT, slots: withoutBlockTime })).toThrow();
  });

  it('rejects a slot the variant does not carry', () => {
    // lovelace belongs to output; asset-output carries quantity instead.
    expect(() =>
      parse({ ...ASSET_OUTPUT, slots: { ...ASSET_OUTPUT.slots, lovelace: 6 } }),
    ).toThrow();
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, quantity: 6 } })).toThrow();
    expect(() =>
      parse({ ...OUTPUT, slots: { ...OUTPUT.slots, policyId: { slot: 6, length: 28 } } }),
    ).toThrow();
  });

  it('rejects a variant without its pinned asset', () => {
    const { asset: _, ...withoutAsset } = ASSET_OUTPUT;
    expect(() => parse(withoutAsset)).toThrow();
  });

  it('rejects duplicate slot indices across names', () => {
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, lovelace: 0 } })).toThrow(
      'declared once',
    );
    expect(() =>
      parse({
        ...ASSET_OUTPUT,
        slots: { ...ASSET_OUTPUT.slots, quantity: 4 },
      }),
    ).toThrow('declared once');
  });

  it('rejects a negative or fractional slot index, and a bad depth', () => {
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, blockTime: -1 } })).toThrow();
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, blockTime: 0.5 } })).toThrow();
    expect(() => parse({ ...OUTPUT, confirmationDepth: 1.5 })).toThrow();
    expect(() => parse({ ...OUTPUT, confirmationDepth: -1 })).toThrow();
  });

  it('rejects a byte slot with a missing or out-of-range length', () => {
    expect(() =>
      parse({ ...ASSET_OUTPUT, slots: { ...ASSET_OUTPUT.slots, assetName: { slot: 5 } } }),
    ).toThrow();
    expect(() =>
      parse({
        ...ASSET_OUTPUT,
        slots: { ...ASSET_OUTPUT.slots, assetName: { slot: 5, length: 0 } },
      }),
    ).toThrow();
    expect(() =>
      parse({
        ...ASSET_OUTPUT,
        slots: { ...ASSET_OUTPUT.slots, assetName: { slot: 5, length: 33 } },
      }),
    ).toThrow();
  });

  it('rejects a policyId slot whose length is not 28', () => {
    expect(() =>
      parse({
        ...ASSET_OUTPUT,
        slots: { ...ASSET_OUTPUT.slots, policyId: { slot: 4, length: 27 } },
      }),
    ).toThrow('policyId is 28 bytes');
  });

  it('rejects an assetName slot whose length differs from the pinned name', () => {
    expect(() =>
      parse({
        ...ASSET_OUTPUT,
        slots: { ...ASSET_OUTPUT.slots, assetName: { slot: 5, length: 2 } },
      }),
    ).toThrow('assetName slot is 2 bytes, the pinned name is 1');
    expect(() => parse(ASSET_OUTPUT)).not.toThrow();
  });

  it('rejects an unknown key anywhere, so a typo cannot silently drop a slot', () => {
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, lovelcae: 4 } })).toThrow();
    expect(() => parse({ ...OUTPUT, extra: 1 })).toThrow();
    expect(() => parse({ ...OUTPUT, asset: { policyId: POLICY_ID, assetName: '' } })).toThrow();
    expect(() =>
      parse({
        ...ASSET_OUTPUT,
        asset: { policyId: POLICY_ID, assetName: 'cd', name: 'x' },
      }),
    ).toThrow();
  });

  it('checks the address prefix and charset against the network', () => {
    expect(() => parse({ ...OUTPUT, network: 'mainnet' })).toThrow(
      'is not a mainnet payment address',
    );
    expect(() => parse({ ...OUTPUT, address: 'addr1qqexample' })).toThrow(
      'is not a preview payment address',
    );
    expect(() => parse({ ...OUTPUT, address: 'addr_test1' })).toThrow(
      'is not a preview payment address',
    );
    // 'b' is outside the bech32 charset.
    expect(() => parse({ ...OUTPUT, address: 'addr_test1bbbbbbbb' })).toThrow(
      'is not a preview payment address',
    );
    expect(() => parse({ ...OUTPUT, network: 'mainnet', address: 'addr1qqexample' })).not.toThrow();
  });

  it('lowercases the address on parse, so case variants hash the same', () => {
    const upper = parse({ ...OUTPUT, address: 'ADDR_TEST1QQEXAMPLE' });
    expect(upper.address).toBe(TEST_ADDRESS);
    expect(cardanoPolicyHashOf(upper)).toEqual(cardanoPolicyHashOf(OUTPUT));
  });

  it('rejects an unknown network, an unknown kind and a malformed asset', () => {
    expect(() => parse({ ...OUTPUT, network: 'banana' })).toThrow();
    expect(() => parse({ ...OUTPUT, kind: 'mint' })).toThrow();
    expect(() => parse({ ...OUTPUT, kind: 'delegation' })).toThrow();
    expect(() =>
      parse({ ...ASSET_OUTPUT, asset: { policyId: 'zz'.repeat(28), assetName: 'cd' } }),
    ).toThrow('expected hex');
    expect(() =>
      parse({ ...ASSET_OUTPUT, asset: { policyId: POLICY_ID, assetName: 'abc' } }),
    ).toThrow('even hex');
    expect(() =>
      parse({ ...ASSET_OUTPUT, asset: { policyId: POLICY_ID, assetName: 'ab'.repeat(33) } }),
    ).toThrow('at most 32 bytes');
  });
});

describe('cardanoPolicyHashOf', () => {
  it('hashes equivalent policies the same, whatever the key order', () => {
    const reordered = {
      slots: OUTPUT.slots,
      address: OUTPUT.address,
      confirmationDepth: OUTPUT.confirmationDepth,
      network: OUTPUT.network,
      kind: OUTPUT.kind,
    };
    expect(cardanoPolicyHashOf(reordered as OutputPolicy)).toEqual(cardanoPolicyHashOf(OUTPUT));
  });

  it('normalizes before hashing', () => {
    expect(cardanoPolicyHashOf(OUTPUT)).toEqual(
      cardanoPolicyHashOf(normalizeCardanoPolicy(OUTPUT)),
    );
  });

  it('hashes an output and an asset-output differently', () => {
    expect(cardanoPolicyHashOf(OUTPUT)).not.toEqual(cardanoPolicyHashOf(ASSET_OUTPUT));
  });

  it('changes the hash when one field changes', () => {
    const baseline = cardanoPolicyHashOf(OUTPUT);
    const mutations: CardanoPolicy[] = [
      { ...OUTPUT, network: 'mainnet', address: 'addr1qqexample' },
      { ...OUTPUT, confirmationDepth: 4 },
      { ...OUTPUT, address: 'addr_test1qqexample2' },
      { ...OUTPUT, slots: { ...OUTPUT.slots, lovelace: 6 } },
      { ...OUTPUT, slots: { ...OUTPUT.slots, blockNumber: 6 } },
    ];
    for (const mutated of mutations) {
      expect(cardanoPolicyHashOf(mutated)).not.toEqual(baseline);
    }
    const otherAsset: AssetOutputPolicy = {
      ...ASSET_OUTPUT,
      asset: { policyId: POLICY_ID, assetName: 'ef' },
      slots: { ...ASSET_OUTPUT.slots, assetName: { slot: 5, length: 1 } },
    };
    expect(cardanoPolicyHashOf(otherAsset)).not.toEqual(cardanoPolicyHashOf(ASSET_OUTPUT));
  });

  it('pins the canonical output policy hash to its bytes', () => {
    expect(Buffer.from(cardanoPolicyHashOf(OUTPUT)).toString('hex')).toBe(
      '819d4541bf35079c7e420d4dd5a46c1dbf96d952cc955835b0bea0f06a9ac10e',
    );
  });

  it('pins the canonical asset-output policy hash to its bytes', () => {
    expect(Buffer.from(cardanoPolicyHashOf(ASSET_OUTPUT)).toString('hex')).toBe(
      '13c167d4acf7c1f719d4666d1b4389d1a4d7bcfc38aeffea29e4ca21e0b0b866',
    );
  });
});
