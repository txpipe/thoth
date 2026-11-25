// Parity between @txpipe/thoth-cardano's cardanoAddressHashOf and the compiled
// circuit's persistentHash over the exact-length address literal.
//
// An app pins a watched address in-circuit by baking it as an exact-length
// literal and comparing the hash against the claim's addressHash fact. That
// binding is only sound if the off-chain helper and the circuit agree; here
// the compiled pure circuits are the oracle.
import { CompactTypeBytes, persistentHash } from '@midnight-ntwrk/compact-runtime';
import { cardanoAddressHashOf } from '@txpipe/thoth-cardano';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../../../contracts/artifacts/mock_address_hash/contract/index.js';

const PREFIX = 'addr_test1';
const ADDRESS = `${PREFIX}${'q'.repeat(93)}`;
const encoder = new TextEncoder();

/** Bech32 data characters, between `length.min` and `length.max` of them. */
const bech32 = (length: { min: number; max: number }): fc.Arbitrary<string> =>
  fc.string({
    unit: fc.constantFrom(...'qpzry9x8gf2tvdw0s3jn54khce6mua7l'),
    minLength: length.min,
    maxLength: length.max,
  });

/** A lowercase testnet address whose byte length is in `length`: the prefix, then bech32 data. */
const address = (length: { min: number; max: number }): fc.Arbitrary<string> =>
  bech32({ min: length.min - PREFIX.length, max: length.max - PREFIX.length }).map(
    (data) => `${PREFIX}${data}`,
  );

describe('cardanoAddressHashOf circuit parity', () => {
  it('matches the baked exact-length literal', () => {
    expect(cardanoAddressHashOf(ADDRESS)).toEqual(pureCircuits.bakedHash());
  });

  it('matches the witness path over every 103-byte address', () => {
    fc.assert(
      fc.property(address({ min: 103, max: 103 }), (addr) => {
        expect(cardanoAddressHashOf(addr)).toEqual(pureCircuits.hashOf(encoder.encode(addr)));
      }),
    );
  });

  // The mock bakes one length, so the checks across lengths run off-chain.
  it('differs from the hash of a longer address with the same prefix', () => {
    fc.assert(
      fc.property(address({ min: 58, max: 110 }), bech32({ min: 1, max: 32 }), (addr, more) => {
        expect(cardanoAddressHashOf(`${addr}${more}`)).not.toEqual(cardanoAddressHashOf(addr));
      }),
    );
  });

  it('differs from the hash of the same address zero-padded to a longer length', () => {
    fc.assert(
      fc.property(
        address({ min: 58, max: 110 }),
        fc.integer({ min: 1, max: 64 }),
        (addr, extra) => {
          const bytes = encoder.encode(addr);
          const padded = new Uint8Array(bytes.length + extra);
          padded.set(bytes);
          const longer = persistentHash(new CompactTypeBytes(padded.length), padded);
          expect(cardanoAddressHashOf(addr)).not.toEqual(longer);
        },
      ),
    );
  });
});
