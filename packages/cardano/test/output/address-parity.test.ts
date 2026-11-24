// Parity between @txpipe/thoth-cardano's cardanoAddressHashOf and the compiled
// circuit's persistentHash over the exact-length address literal.
//
// An app pins a watched address in-circuit by baking it as an exact-length
// literal and comparing the hash against the claim's addressHash fact. That
// binding is only sound if the off-chain helper and the circuit agree; here
// the compiled pure circuits are the oracle.
import {
  CompactTypeBytes,
  CompactTypeVector,
  persistentHash,
} from '@midnight-ntwrk/compact-runtime';
import { cardanoAddressHashOf } from '@txpipe/thoth-cardano';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../../../contracts/artifacts/mock_address_hash/contract/index.js';

const ADDRESS = `addr_test1${'q'.repeat(93)}`;
const encoder = new TextEncoder();

describe('cardanoAddressHashOf circuit parity', () => {
  it('matches the baked exact-length literal', () => {
    expect(cardanoAddressHashOf(ADDRESS)).toEqual(pureCircuits.bakedHash());
  });

  it('matches the witness path over the address bytes', () => {
    expect(cardanoAddressHashOf(ADDRESS)).toEqual(pureCircuits.hashOf(encoder.encode(ADDRESS)));
  });

  it('differs from a hash of the same bytes at another length', () => {
    const bytes = encoder.encode(ADDRESS);
    const padded = new Uint8Array(128);
    padded.set(bytes);
    const chunked = [0, 1, 2, 3].map((index) => padded.slice(index * 32, (index + 1) * 32));
    const otherLength = persistentHash(new CompactTypeVector(4, new CompactTypeBytes(32)), chunked);
    expect(cardanoAddressHashOf(ADDRESS)).not.toEqual(otherLength);
  });
});
