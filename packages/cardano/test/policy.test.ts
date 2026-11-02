// Unit tests for the cardano@1 kind's policy schema and hash
// (`@thoth/cardano`): normalization, the pinned hash bytes, the address rules
// per network, and the rejection matrix of the output slot set.

import {
  type CardanoPolicy,
  cardanoPolicyHashOf,
  cardanoPolicySchema,
  normalizeCardanoPolicy,
  type OutputPolicy,
} from '@thoth/cardano';
import { describe, expect, it } from 'vitest';

/**
 * A preview payment address at the smallest CIP-19 length (53 characters
 * after the prefix). The checksum is not verified, so the body is a fixture.
 */
const TEST_ADDRESS = `addr_test1${'q'.repeat(53)}`;
const MAINNET_ADDRESS = `addr1${'q'.repeat(53)}`;

const OUTPUT: OutputPolicy = {
  kind: 'output',
  network: 'preview',
  confirmationDepth: 3,
  address: TEST_ADDRESS,
  slots: { blockTime: 0, slot: 1, blockNumber: 2, lovelace: 3 },
};

const parse = (policy: unknown): CardanoPolicy => cardanoPolicySchema.parse(policy);

describe('cardanoPolicySchema', () => {
  it('parses the output variant', () => {
    expect(parse(OUTPUT)).toEqual(OUTPUT);
  });

  it('accepts a zero confirmation depth, leaving the depth to the app', () => {
    expect(parse({ ...OUTPUT, confirmationDepth: 0 }).confirmationDepth).toBe(0);
  });

  it('requires every slot the output carries', () => {
    const { blockNumber: _, ...withoutBlockNumber } = OUTPUT.slots;
    expect(() => parse({ ...OUTPUT, slots: withoutBlockNumber })).toThrow();
    const { blockTime: __, ...withoutBlockTime } = OUTPUT.slots;
    expect(() => parse({ ...OUTPUT, slots: withoutBlockTime })).toThrow();
    const { lovelace: ___, ...withoutLovelace } = OUTPUT.slots;
    expect(() => parse({ ...OUTPUT, slots: withoutLovelace })).toThrow();
  });

  it('rejects a slot the variant does not carry', () => {
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, quantity: 6 } })).toThrow();
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, policyId: 6 } })).toThrow();
  });

  it('rejects duplicate slot indices across names', () => {
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, lovelace: 0 } })).toThrow(
      'declared once',
    );
  });

  it('rejects a negative or fractional slot index, and a bad depth', () => {
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, blockTime: -1 } })).toThrow();
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, blockTime: 0.5 } })).toThrow();
    expect(() => parse({ ...OUTPUT, confirmationDepth: 1.5 })).toThrow();
    expect(() => parse({ ...OUTPUT, confirmationDepth: -1 })).toThrow();
  });

  it('rejects an unknown key anywhere, so a typo cannot silently drop a slot', () => {
    expect(() => parse({ ...OUTPUT, slots: { ...OUTPUT.slots, lovelcae: 4 } })).toThrow();
    expect(() => parse({ ...OUTPUT, extra: 1 })).toThrow();
  });

  it('checks the address prefix against the network', () => {
    expect(() => parse({ ...OUTPUT, network: 'mainnet', address: TEST_ADDRESS })).toThrow(
      'is not a mainnet payment address',
    );
    expect(() => parse({ ...OUTPUT, address: MAINNET_ADDRESS })).toThrow(
      'is not a preview payment address',
    );
    expect(() => parse({ ...OUTPUT, network: 'mainnet', address: MAINNET_ADDRESS })).not.toThrow();
  });

  it('accepts a testnet address under either testnet name, since the address cannot say which', () => {
    expect(parse({ ...OUTPUT, network: 'preprod' }).network).toBe('preprod');
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

  it('names the valid kind when the kind is unknown', () => {
    expect(() => parse({ ...OUTPUT, kind: 'mint' })).toThrow("Expected 'output'");
    expect(() => parse({ ...OUTPUT, kind: 'asset-output' })).toThrow("Expected 'output'");
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

  it('changes the hash when one field changes', () => {
    const baseline = cardanoPolicyHashOf(OUTPUT);
    const mutations: CardanoPolicy[] = [
      { ...OUTPUT, network: 'preprod' },
      { ...OUTPUT, network: 'mainnet', address: MAINNET_ADDRESS },
      { ...OUTPUT, confirmationDepth: 4 },
      { ...OUTPUT, address: `addr_test1${'p'.repeat(53)}` },
      { ...OUTPUT, slots: { ...OUTPUT.slots, lovelace: 6 } },
      { ...OUTPUT, slots: { ...OUTPUT.slots, blockNumber: 6 } },
    ];
    for (const mutated of mutations) {
      expect(cardanoPolicyHashOf(mutated)).not.toEqual(baseline);
    }
  });

  it('pins the canonical output policy hash to its bytes', () => {
    expect(Buffer.from(cardanoPolicyHashOf(OUTPUT)).toString('hex')).toBe(
      '38b7a121e0284266cd9ffe580bb01ccded4ee5cd46e3151a8cb886f5893b60a8',
    );
  });
});
