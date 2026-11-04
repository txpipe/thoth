// Unit tests for the output subject fields and hash (`@thoth/cardano`): the
// five fields an app binds in-circuit, in struct order, and the hash they
// produce.

import { createHash } from 'node:crypto';
import { cardanoOutputSubjectHashOf, cardanoOutputSubjectOf } from '@thoth/cardano';
import { subjectHashOf } from '@thoth/core/claim-context';
import { describe, expect, it } from 'vitest';
import { BLOCK_HASH, TEST_ADDRESS, TX_HASH } from './fixtures.js';

const INPUT = {
  networkMagic: 2,
  address: TEST_ADDRESS,
  txHash: TX_HASH,
  outputIndex: 1,
  blockHash: BLOCK_HASH,
};

const uint32 = (value: number): Uint8Array => {
  const field = new Uint8Array(32);
  new DataView(field.buffer).setUint32(28, value, false);
  return field;
};

const bytesOfHex = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex, 'hex'));

const addressHashOf = (address: string): Uint8Array =>
  new Uint8Array(createHash('sha256').update(address.toLowerCase(), 'utf-8').digest());

describe('cardanoOutputSubjectOf', () => {
  it('builds the five fields in struct order', () => {
    expect(cardanoOutputSubjectOf(INPUT)).toEqual({
      networkMagic: uint32(2),
      addressHash: addressHashOf(TEST_ADDRESS),
      txHash: bytesOfHex(TX_HASH),
      outputIndex: uint32(1),
      blockHash: bytesOfHex(BLOCK_HASH),
    });
  });

  it('lowercases the address before hashing it', () => {
    const upper = cardanoOutputSubjectOf({ ...INPUT, address: TEST_ADDRESS.toUpperCase() });
    expect(upper.addressHash).toEqual(addressHashOf(TEST_ADDRESS));
  });

  it('rejects a non-uint32 magic or index', () => {
    expect(() => cardanoOutputSubjectOf({ ...INPUT, networkMagic: -1 })).toThrow('uint32');
    expect(() => cardanoOutputSubjectOf({ ...INPUT, networkMagic: 2 ** 32 })).toThrow('uint32');
    expect(() => cardanoOutputSubjectOf({ ...INPUT, outputIndex: 1.5 })).toThrow('uint32');
    expect(() => cardanoOutputSubjectOf({ ...INPUT, outputIndex: 2 ** 32 })).toThrow('uint32');
  });

  it('rejects a hash that is not 64 lowercase hex characters', () => {
    expect(() => cardanoOutputSubjectOf({ ...INPUT, txHash: TX_HASH.toUpperCase() })).toThrow(
      '64 lowercase hex',
    );
    expect(() => cardanoOutputSubjectOf({ ...INPUT, blockHash: BLOCK_HASH.slice(2) })).toThrow(
      '64 lowercase hex',
    );
  });
});

describe('cardanoOutputSubjectHashOf', () => {
  it('hashes the fields in the order the struct declares', () => {
    const subject = cardanoOutputSubjectOf(INPUT);
    expect(cardanoOutputSubjectHashOf(INPUT)).toEqual(
      subjectHashOf([
        subject.networkMagic,
        subject.addressHash,
        subject.txHash,
        subject.outputIndex,
        subject.blockHash,
      ]),
    );
  });

  it('hashes the same fields the same whatever the address case', () => {
    expect(cardanoOutputSubjectHashOf({ ...INPUT, address: TEST_ADDRESS.toUpperCase() })).toEqual(
      cardanoOutputSubjectHashOf(INPUT),
    );
  });
});
