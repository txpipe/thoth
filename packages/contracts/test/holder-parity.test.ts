// Parity between the off-chain holder commitment
// (`@thoth/core/claim-context`'s `holderCommitmentOf`) and the compiled
// `holderCommitment` pure circuit.
//
// ADR 0004 binds each claim to a per-claim holder commitment. The client
// derives it off-chain for the claim context and the contract re-derives it
// in-circuit from the caller's secret, so the two must agree byte for byte.
// The compiled pure circuit is the oracle.
import { randomBytes } from 'node:crypto';
import { holderCommitmentOf } from '@thoth/core/claim-context';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';

const filled = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

/** Read 32 bytes as an unsigned integer, big-endian or little-endian. */
const asInteger = (bytes: Uint8Array, littleEndian: boolean): bigint => {
  const ordered = littleEndian ? Uint8Array.from(bytes).reverse() : bytes;
  return BigInt(`0x${Buffer.from(ordered).toString('hex')}`);
};

describe('holderCommitmentOf circuit parity', () => {
  it('matches the holderCommitment circuit for fixed and random secrets', () => {
    for (const secret of [filled(0x00), filled(0xff), filled(0x42), randomBytes(32)]) {
      expect(holderCommitmentOf(secret)).toEqual(pureCircuits.holderCommitment(secret));
    }
  });
});

describe('holderCommitment circuit', () => {
  it('gives distinct secrets distinct commitments', () => {
    expect(pureCircuits.holderCommitment(filled(1))).not.toEqual(
      pureCircuits.holderCommitment(filled(2)),
    );
  });

  it('differs from the vault pseudonym of the same secret', () => {
    // deriveHolder (exported as holderOf) is the vault pseudonym, a Field.
    // Read the commitment as an integer in either byte order: the two roles
    // must not collapse to one value.
    for (const secret of [filled(7), randomBytes(32)]) {
      const pseudonym = pureCircuits.holderOf(secret);
      const commitment = pureCircuits.holderCommitment(secret);

      expect(asInteger(commitment, false)).not.toBe(pseudonym);
      expect(asInteger(commitment, true)).not.toBe(pseudonym);
    }
  });
});
