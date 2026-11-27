// Parity between the off-chain holder commitment
// (`@txpipe/thoth-core/claim-context`'s `holderCommitmentOf`) and the compiled
// `holderCommitment` pure circuit, over seeded random secrets. A failure names
// its seed: rerun with `THOTH_SEED=<seed>` to replay it.
//
// ADR 0004 binds each claim to a per-claim holder commitment. The client
// derives it off-chain for the claim context and the contract re-derives it
// in-circuit from the caller's secret, so the two must agree byte for byte.
import { createHash, randomBytes } from 'node:crypto';
import { holderCommitmentOf } from '@txpipe/thoth-core/claim-context';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import { RUNS, SEED, SeededRandom } from './helpers/random-claims.js';

const filled = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

/** Read 32 bytes as an unsigned integer, big-endian or little-endian. */
const asInteger = (bytes: Uint8Array, littleEndian: boolean): bigint => {
  const ordered = littleEndian ? Uint8Array.from(bytes).reverse() : bytes;
  return BigInt(`0x${Buffer.from(ordered).toString('hex')}`);
};

// One SHA-256 block holds at most 55 input bytes: the padding takes a 0x80 byte
// and an 8-byte length.
const ONE_BLOCK_BYTES = 55;

const secrets = (): Uint8Array[] => {
  const rng = new SeededRandom(SEED);
  return [filled(0x00), filled(0xff), ...Array.from({ length: RUNS }, () => rng.bytes(32))];
};

describe(`holder commitment over random secrets (seed ${SEED})`, () => {
  it('holderCommitmentOf equals the holderCommitment circuit', () => {
    secrets().forEach((secret, run) => {
      expect(holderCommitmentOf(secret), `run ${run}`).toEqual(
        pureCircuits.holderCommitment(secret),
      );
    });
  });

  it('is a plain SHA-256 of the tag then the secret, in one block', () => {
    const tag = new TextEncoder().encode('thoth:holder-commit:v1');
    expect(tag.length + 32).toBeLessThanOrEqual(ONE_BLOCK_BYTES);
    secrets().forEach((secret, run) => {
      const digest = createHash('sha256').update(tag).update(secret).digest();
      expect(pureCircuits.holderCommitment(secret), `run ${run}`).toEqual(new Uint8Array(digest));
    });
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
