// Unit tests for the cardano@1 kind's policy schema and hash
// (`@txpipe/thoth-cardano`): normalization, the pinned hash bytes, the address rules
// per network, and the rejection matrix of the output slot set.

import {
  CARDANO_FACTS,
  type CardanoPolicy,
  cardanoPolicyHashOf,
  cardanoPolicySchema,
  normalizeCardanoPolicy,
  type OutputPolicy,
} from '@txpipe/thoth-cardano';
import { describe, expect, it } from 'vitest';

/**
 * A preview payment address at the smallest CIP-19 length (53 characters
 * after the prefix). The checksum is not verified, so the body is a fixture.
 */
const TEST_ADDRESS = `addr_test1${'q'.repeat(53)}`;
const MAINNET_ADDRESS = `addr1${'q'.repeat(53)}`;
const ASSET_PIN = { policyId: 'ab'.repeat(28), assetName: 'cd'.repeat(4) };

const OUTPUT: OutputPolicy = {
  kind: 'output',
  network: 'preview',
  networkMagic: 2,
  confirmationDepth: 3,
  address: TEST_ADDRESS,
  slots: [
    { slot: 0, name: 'blockTime' },
    { slot: 1, name: 'slot' },
    { slot: 2, name: 'blockNumber' },
    { slot: 3, name: 'lovelace' },
    { slot: 4, name: 'outputIndex' },
  ],
};

const parse = (policy: unknown): CardanoPolicy => cardanoPolicySchema.parse(policy);

describe('cardanoPolicySchema', () => {
  it('parses the output variant, sorting its slots by index', () => {
    const shuffled = { ...OUTPUT, slots: [...OUTPUT.slots].reverse() };
    expect(parse(shuffled)).toEqual(OUTPUT);
  });

  it('accepts a zero confirmation depth, leaving the depth to the app', () => {
    expect(parse({ ...OUTPUT, confirmationDepth: 0 }).confirmationDepth).toBe(0);
  });

  it('accepts a policy that maps a subset of the facts', () => {
    const minimal = parse({ ...OUTPUT, slots: [{ slot: 0, name: 'lovelace' }] });
    expect(minimal.slots).toEqual([{ slot: 0, name: 'lovelace' }]);
  });

  it('accepts a byte fact', () => {
    const withByte = parse({ ...OUTPUT, slots: [{ slot: 5, name: 'txHash' }] });
    expect(withByte.slots).toEqual([{ slot: 5, name: 'txHash' }]);
  });

  it('accepts a policy that pins an asset and measures its quantity', () => {
    const withAsset = parse({
      ...OUTPUT,
      asset: ASSET_PIN,
      slots: [{ slot: 3, name: 'assetQuantity' }],
    });
    expect(withAsset.asset).toEqual(ASSET_PIN);
  });

  it("rejects 'assetQuantity' without the 'asset' pin", () => {
    expect(() => parse({ ...OUTPUT, slots: [{ slot: 3, name: 'assetQuantity' }] })).toThrow(
      "requires the 'asset' pin",
    );
  });

  it('rejects a malformed asset pin', () => {
    expect(() => parse({ ...OUTPUT, asset: { ...ASSET_PIN, policyId: 'ab' } })).toThrow(
      '56 lowercase hex',
    );
    expect(() => parse({ ...OUTPUT, asset: { ...ASSET_PIN, assetName: 'zz' } })).toThrow(
      '64 lowercase hex',
    );
  });

  it('rejects an empty slot list', () => {
    expect(() => parse({ ...OUTPUT, slots: [] })).toThrow();
  });

  it('accepts one entry per fact, the largest slot map a policy can carry', () => {
    const allFacts = CARDANO_FACTS.map((name, slot) => ({ slot, name }));
    expect(parse({ ...OUTPUT, asset: ASSET_PIN, slots: allFacts }).slots).toHaveLength(
      CARDANO_FACTS.length,
    );
  });

  it('rejects more slot entries than the variant has facts', () => {
    const tooMany = Array.from({ length: CARDANO_FACTS.length + 1 }, (_, slot) => ({
      slot,
      name: 'lovelace' as const,
    }));
    expect(() => parse({ ...OUTPUT, slots: tooMany })).toThrow(/Too big/);
  });

  it('rejects a fact the variant does not carry', () => {
    expect(() => parse({ ...OUTPUT, slots: [{ slot: 0, name: 'quantity' }] })).toThrow();
    expect(() => parse({ ...OUTPUT, slots: [{ slot: 0, name: 'policyId' }] })).toThrow();
  });

  it('rejects duplicate slot indices across facts', () => {
    const duplicated = [...OUTPUT.slots.slice(0, 4), { slot: 0, name: 'outputIndex' }];
    expect(() => parse({ ...OUTPUT, slots: duplicated })).toThrow('declared once');
  });

  it('rejects one fact mapped to more than one slot', () => {
    const duplicated = [...OUTPUT.slots, { slot: 5, name: 'lovelace' }];
    expect(() => parse({ ...OUTPUT, slots: duplicated })).toThrow('mapped once');
  });

  it('rejects a negative or fractional slot index, and a bad depth', () => {
    expect(() => parse({ ...OUTPUT, slots: [{ slot: -1, name: 'lovelace' }] })).toThrow();
    expect(() => parse({ ...OUTPUT, slots: [{ slot: 0.5, name: 'lovelace' }] })).toThrow();
    expect(() => parse({ ...OUTPUT, confirmationDepth: 1.5 })).toThrow();
    expect(() => parse({ ...OUTPUT, confirmationDepth: -1 })).toThrow();
  });

  it('rejects an unknown key anywhere, so a typo cannot silently drop a fact', () => {
    expect(() => parse({ ...OUTPUT, slots: [{ slot: 4, name: 'lovelcae' }] })).toThrow();
    expect(() => parse({ ...OUTPUT, extra: 1 })).toThrow();
  });

  it('checks the address prefix against the network', () => {
    expect(() =>
      parse({ ...OUTPUT, network: 'mainnet', networkMagic: 764824073, address: TEST_ADDRESS }),
    ).toThrow('is not a mainnet payment address');
    expect(() => parse({ ...OUTPUT, address: MAINNET_ADDRESS })).toThrow(
      'is not a preview payment address',
    );
    expect(() =>
      parse({ ...OUTPUT, network: 'mainnet', networkMagic: 764824073, address: MAINNET_ADDRESS }),
    ).not.toThrow();
  });

  it('accepts a testnet address under either testnet name, since the address cannot say which', () => {
    expect(parse({ ...OUTPUT, network: 'preprod', networkMagic: 1 }).network).toBe('preprod');
    expect(parse({ ...OUTPUT, network: 'preview' }).network).toBe('preview');
  });

  it('rejects an address that is neither a mainnet nor a testnet payment address', () => {
    expect(() => parse({ ...OUTPUT, address: `stake_test1${'q'.repeat(53)}` })).toThrow(
      'is not a preview payment address',
    );
    expect(() => parse({ ...OUTPUT, address: `addr_xyz1${'q'.repeat(53)}` })).toThrow(
      'is not a preview payment address',
    );
    expect(() => parse({ ...OUTPUT, address: `addr_test1${'q'.repeat(52)}` })).toThrow(
      'is not a preview payment address',
    );
    expect(() => parse({ ...OUTPUT, address: `addr1${'q'.repeat(52)}` })).toThrow();
  });

  it('rejects a bech32 body with a character outside the charset', () => {
    // 'b' is outside the bech32 charset.
    expect(() => parse({ ...OUTPUT, address: `addr_test1b${'q'.repeat(52)}` })).toThrow(
      'is not a preview payment address',
    );
  });

  it('lowercases the address on parse, so case variants hash the same', () => {
    const upper = parse({ ...OUTPUT, address: TEST_ADDRESS.toUpperCase() });
    expect(upper.address).toBe(TEST_ADDRESS);
    expect(cardanoPolicyHashOf(upper)).toEqual(cardanoPolicyHashOf(OUTPUT));
  });

  it('rejects an unknown network', () => {
    expect(() => parse({ ...OUTPUT, network: 'banana' })).toThrow();
  });

  it('requires the fixed magic for each public network', () => {
    expect(parse({ ...OUTPUT, network: 'preprod', networkMagic: 1 }).networkMagic).toBe(1);
    expect(() => parse({ ...OUTPUT, network: 'preprod', networkMagic: 2 })).toThrow(
      'preprod magic is 1',
    );
    expect(() => parse({ ...OUTPUT, networkMagic: 1 })).toThrow('preview magic is 2');
    const mainnet = { ...OUTPUT, network: 'mainnet', address: MAINNET_ADDRESS };
    expect(() => parse({ ...mainnet, networkMagic: 764824073 })).not.toThrow();
    expect(() => parse({ ...mainnet, networkMagic: 2 })).toThrow('mainnet magic is 764824073');
  });

  it('accepts a devnet with its own magic, using the testnet address prefix', () => {
    const devnet = { ...OUTPUT, network: 'devnet', networkMagic: 42 };
    expect(parse(devnet).network).toBe('devnet');
    expect(() => parse({ ...devnet, address: MAINNET_ADDRESS })).toThrow(
      'is not a devnet payment address',
    );
  });

  it('rejects a devnet that claims a public magic', () => {
    for (const magic of [1, 2, 764824073]) {
      expect(() => parse({ ...OUTPUT, network: 'devnet', networkMagic: magic })).toThrow(
        'cannot use the public magic',
      );
    }
  });

  it('rejects a magic outside 1 to 2^32-1, zero, and a fractional magic', () => {
    expect(() => parse({ ...OUTPUT, networkMagic: 0 })).toThrow();
    expect(() => parse({ ...OUTPUT, networkMagic: -1 })).toThrow();
    expect(() => parse({ ...OUTPUT, networkMagic: 1.5 })).toThrow();
    const devnet = { ...OUTPUT, network: 'devnet' };
    expect(parse({ ...devnet, networkMagic: 2 ** 32 - 1 }).networkMagic).toBe(2 ** 32 - 1);
    expect(() => parse({ ...devnet, networkMagic: 2 ** 32 })).toThrow();
  });

  it('names the valid kind when the kind is unknown', () => {
    expect(() => parse({ ...OUTPUT, kind: 'mint' })).toThrow("Expected 'output'");
    expect(() => parse({ ...OUTPUT, kind: 'asset-output' })).toThrow("Expected 'output'");
  });
});

describe('cardanoPolicyHashOf', () => {
  it('hashes equivalent policies the same, whatever the entry order', () => {
    const reordered = { ...OUTPUT, slots: [...OUTPUT.slots].reverse() };
    expect(cardanoPolicyHashOf(reordered as OutputPolicy)).toEqual(cardanoPolicyHashOf(OUTPUT));
  });

  it('normalizes before hashing', () => {
    expect(cardanoPolicyHashOf(OUTPUT)).toEqual(
      cardanoPolicyHashOf(normalizeCardanoPolicy(OUTPUT)),
    );
  });

  it('changes the hash when one field changes', () => {
    const baseline = cardanoPolicyHashOf(OUTPUT);
    const remapped = (name: OutputPolicy['slots'][number]['name'], slot: number) =>
      OUTPUT.slots.map((entry) => (entry.name === name ? { ...entry, slot } : entry));
    const mutations: CardanoPolicy[] = [
      { ...OUTPUT, network: 'preprod', networkMagic: 1 },
      { ...OUTPUT, network: 'mainnet', networkMagic: 764824073, address: MAINNET_ADDRESS },
      { ...OUTPUT, network: 'devnet', networkMagic: 42 },
      { ...OUTPUT, confirmationDepth: 4 },
      { ...OUTPUT, address: `addr_test1${'p'.repeat(53)}` },
      { ...OUTPUT, asset: ASSET_PIN },
      { ...OUTPUT, slots: remapped('lovelace', 6) },
      { ...OUTPUT, slots: remapped('blockNumber', 6) },
    ];
    for (const mutated of mutations) {
      expect(cardanoPolicyHashOf(mutated)).not.toEqual(baseline);
    }
  });

  it('hashes two devnets that differ only in magic differently', () => {
    const a = cardanoPolicyHashOf({ ...OUTPUT, network: 'devnet', networkMagic: 42 });
    const b = cardanoPolicyHashOf({ ...OUTPUT, network: 'devnet', networkMagic: 43 });
    expect(a).not.toEqual(b);
  });

  it('pins the canonical output policy hash to its bytes', () => {
    expect(Buffer.from(cardanoPolicyHashOf(OUTPUT)).toString('hex')).toBe(
      '43a36f36210e42c8d3357821afb855b739ec22c832ecf7a5df3b79b05221d907',
    );
  });
});
