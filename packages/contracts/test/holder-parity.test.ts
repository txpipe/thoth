// Parity between the off-chain holder commitment
// (`@thoth/core/claim-context`'s `holderCommitmentOf`) and the compiled
// `holderCommitment` pure circuit.
//
// ADR 0004 binds each claim to a per-claim holder commitment. The client
// derives it off-chain for the claim context and the contract re-derives it
// in-circuit from the caller's secret, so the two must agree byte for byte.
// The compiled pure circuit is the oracle.
import { createHash, randomBytes } from 'node:crypto';
import { degradeToTransient, ecMulGenerator, jubjubPointX } from '@midnight-ntwrk/compact-runtime';
import { holderCommitmentOf } from '@thoth/core/claim-context';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';

const filled = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

const flipLast = (bytes: Uint8Array): Uint8Array => {
  const copy = Uint8Array.from(bytes);
  copy[31] = (copy[31] ?? 0) ^ 0xff;
  return copy;
};

/** Read bytes as an unsigned integer, big-endian or little-endian. */
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

  it('is SHA-256 of the 22-byte tag and the secret, one block in-circuit', () => {
    const secret = randomBytes(32);
    const tag = new TextEncoder().encode('thoth:holder-commit:v1');
    expect(tag).toHaveLength(22);
    const digest = createHash('sha256').update(tag).update(secret).digest();
    expect(pureCircuits.holderCommitment(secret)).toEqual(new Uint8Array(digest));
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

// The vault pseudonym is `x(s * G)` with `s` the secret's first 31 bytes read
// little-endian: curve arithmetic only, so it survives a network upgrade that
// changes `hashToCurve` or `transientHash`.
describe('vault pseudonym (holderOf)', () => {
  it('is the x coordinate of the generator times the first 31 secret bytes', () => {
    for (const secret of [filled(0x00).fill(1, 0, 1), filled(0xff), randomBytes(32)]) {
      const scalar = asInteger(secret.slice(0, 31), true);
      expect(pureCircuits.holderOf(secret)).toBe(jubjubPointX(ecMulGenerator(scalar)));
    }
  });

  it("is what openClaim's holder scalar witness, degradeToTransient(secret), opens", () => {
    for (const secret of [filled(0x00).fill(1, 0, 1), filled(0xff), randomBytes(32)]) {
      const scalar = degradeToTransient(secret);
      expect(scalar).toBe(asInteger(secret.slice(0, 31), true));
      expect(jubjubPointX(ecMulGenerator(scalar))).toBe(pureCircuits.holderOf(secret));
    }
  });

  it('ignores byte 31 of the secret', () => {
    const secret = randomBytes(32);
    expect(pureCircuits.holderOf(flipLast(secret))).toBe(pureCircuits.holderOf(secret));
  });
});
