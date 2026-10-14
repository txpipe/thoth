// Byte-value slot tests for the bytes mock (V = 3, B = 2, K = 21): wire parity
// between `claimToMessage` and the compiled `buildMessage`, the absent-slot law
// in the simulator, byte-value predicates (reassembly), signature coverage over
// the halves, and the unchanged W = 0 layout.
import { randomBytes } from 'node:crypto';
import type { JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import { claimToMessage } from '@thoth/core/claim';
import { beforeEach, describe, expect, it } from 'vitest';
import type { A_Claim } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits as mockPureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import type { B_Claim } from '../artifacts/mock_attestation_bytes/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import {
  bytesIdOf,
  DEFAULT_BYTE_VALUE,
  DEFAULT_HOLDER_SECRET,
  DUMMY_SIGNATURE,
  flip,
  makeByteClaim,
  makeClaim,
  makeNotaryKey,
  mergeHalves,
  padded32,
  splitHalves,
  toBytesClaim,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationBytesSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((key) => key.pk);
const holder = DEFAULT_HOLDER_SECRET;
const ZERO32 = new Uint8Array(32);
const ZERO16 = ZERO32.slice(0, 16);

// A value whose bytes differ across the 16-byte half boundary, so a swapped or
// reversed half cannot pass the split/reassembly assertions.
const fullSpan = (): Uint8Array => Uint8Array.from({ length: 32 }, (_, i) => i);

// Little-endian value of a byte vector, as Compact's `convertBytesToUint` reads
// it (first byte least significant), computed independently of the encoder.
const le = (bytes: Uint8Array): bigint =>
  bytes.reduce((acc, byte, i) => acc + BigInt(byte) * 256n ** BigInt(i), 0n);

// Reinterpret the bytes mock's contract shape as the kind-facing core shape:
// collapse each byte slot's duplicated per-half flags to one and reassemble its
// two halves. `W = 1` here, so the single byte slot is halves 0 and 1.
const coreOf = (claim: B_Claim) => ({
  ...claim,
  present: [...claim.present, claim.bytePresent[0] ?? false],
  byteValues: [mergeHalves(claim.byteHalves[0], claim.byteHalves[1])],
});

type Submission = {
  claim: B_Claim;
  signatures: JubjubSchnorrSignature[];
  commitRand: Uint8Array;
};

// A threshold signature set over the claim's own compiled message: the first
// two keys sign, the third slot stays empty (never verifies).
const signed = (claim: B_Claim): Submission => {
  const message = pureCircuits.message(claim);
  return {
    claim,
    signatures: [
      signMessage(notaryKeys[0].sk, message).signature,
      signMessage(notaryKeys[1].sk, message).signature,
      DUMMY_SIGNATURE,
    ],
    commitRand: randomBytes(32),
  };
};

let sim: MockAttestationBytesSim;

const submit = (submission: Submission) =>
  sim.call('verifyAttestation', { ...submission, holderSecret: holder });

describe('bytes claim wire', () => {
  it('matches claimToMessage field-for-field, flags duplicated and halves adjacent', () => {
    const claim = makeByteClaim();
    const message = pureCircuits.message(claim);
    expect(claimToMessage(coreOf(claim))).toEqual(message);
    expect(message).toHaveLength(21);
    // [present(3): 1,0,0][bytePresent(2): 1,1][values(3)][low half][high half]
    expect(message.slice(11, 16)).toEqual([1n, 0n, 0n, 1n, 1n]);
    expect(message.slice(16, 19)).toEqual([12345n, 0n, 0n]);
    // "abc" occupies the low half (non-zero); the trailing half is zero padding,
    // so the low field must come first.
    expect(message[19]).not.toBe(0n);
    expect(message[20]).toBe(0n);
  });

  it('round-trips a core claim through the contract shape', () => {
    const claim = makeByteClaim({ byteValue: fullSpan() });
    const core = coreOf(claim);
    expect(toBytesClaim(core)).toEqual(claim);
  });

  it('encodes a full-span value as little-endian bytes 0–15 / 16–31 halves', () => {
    const value = fullSpan();
    const claim = makeByteClaim({ byteValue: value });
    const [low, high] = splitHalves(value);
    const lowField = le(low);
    const highField = le(high);
    // Distinct, non-zero halves — a swap or reversal fails both encoders.
    expect(lowField).not.toBe(highField);
    expect(claimToMessage(coreOf(claim)).slice(19, 21)).toEqual([lowField, highField]);
    expect(pureCircuits.message(claim).slice(19, 21)).toEqual([lowField, highField]);
  });

  it('pins an absent byte flag to two zero fields even with halves present', () => {
    const claim = makeByteClaim({ bytePresent: [false, false] });
    expect(pureCircuits.message(claim).slice(14, 16)).toEqual([0n, 0n]);
  });

  it('keeps the pre-feature numeric-only message for a B = 0 claim', () => {
    const claim: A_Claim = makeClaim();
    const message = claimToMessage({ ...claim, byteValues: [] });
    expect(message).toHaveLength(17);
    expect(message).toEqual(mockPureCircuits.message(claim));
  });
});

describe('the absent-slot law in the simulator', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  it('accepts the honest byte-carrying claim', async () => {
    const submission = signed(makeByteClaim());
    await submit(submission);
    expect(
      sim.ledgerView().B_claimsVault.member(bytesIdOf(submission.claim, submission.commitRand)),
    ).toBe(true);
  });

  it('accepts a present value whose trailing half is all zeros (zero-padded)', async () => {
    const submission = signed(makeByteClaim()); // "abc" → high half is 16 zero bytes
    const [, high] = splitHalves(DEFAULT_BYTE_VALUE);
    expect(high).toEqual(ZERO16);
    await submit(submission);
    expect(
      sim.ledgerView().B_claimsVault.member(bytesIdOf(submission.claim, submission.commitRand)),
    ).toBe(true);
  });

  it('accepts a present all-zero byte value', async () => {
    const submission = signed(makeByteClaim({ byteValue: ZERO32 }));
    await submit(submission);
    expect(
      sim.ledgerView().B_claimsVault.member(bytesIdOf(submission.claim, submission.commitRand)),
    ).toBe(true);
  });

  it('rejects a claim whose absent halves carry non-zero bytes', async () => {
    await expect(submit(signed(makeByteClaim({ bytePresent: [false, false] })))).rejects.toThrow(
      'Absent slot has nonzero value',
    );
  });

  it('rejects a claim whose absent low half alone is non-zero', async () => {
    await expect(submit(signed(makeByteClaim({ bytePresent: [false, true] })))).rejects.toThrow(
      'Absent slot has nonzero value',
    );
  });

  it('accepts an absent slot whose halves are all zero', async () => {
    const submission = signed(
      makeByteClaim({ bytePresent: [false, false], byteHalves: [ZERO16, ZERO16] }),
    );
    await submit(submission);
    expect(
      sim.ledgerView().B_claimsVault.member(bytesIdOf(submission.claim, submission.commitRand)),
    ).toBe(true);
  });
});

describe('byte-value predicates', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  const vault = async (byteValue: Uint8Array): Promise<Submission> => {
    const submission = signed(makeByteClaim({ byteValue }));
    await submit(submission);
    return submission;
  };

  it('openAndReadBytes accepts the matching value and rejects another', async () => {
    const stored = await vault(padded32('abc'));
    const id = bytesIdOf(stored.claim, stored.commitRand);
    const state = { ...stored, holderSecret: holder };
    await sim.call('openAndReadBytes', state, id, padded32('abc'));
    await expect(sim.call('openAndReadBytes', state, id, padded32('xyz'))).rejects.toThrow(
      'byteValue[0] mismatch',
    );
  });

  it('reassembles a value whose content spans both halves, in order', async () => {
    const value = fullSpan();
    const stored = await vault(value);
    const id = bytesIdOf(stored.claim, stored.commitRand);
    const state = { ...stored, holderSecret: holder };
    // The contract reassembles `[bytes 0–15, bytes 16–31]`, recovering the value.
    await sim.call('openAndReadBytes', state, id, value);
    // A high-half mutation is rejected (the low/high test only touches low)...
    await expect(sim.call('openAndReadBytes', state, id, flip(value, 20))).rejects.toThrow(
      'byteValue[0] mismatch',
    );
    // ...and so is the halves swapped, so the order is pinned, not just the set.
    const swapped = new Uint8Array([...value.slice(16), ...value.slice(0, 16)]);
    await expect(sim.call('openAndReadBytes', state, id, swapped)).rejects.toThrow(
      'byteValue[0] mismatch',
    );
  });

  it('accepts two claims with equal values and rejects a claim with another value', async () => {
    const first = await vault(padded32('abc'));
    const second = await vault(padded32('abc'));
    const other = await vault(padded32('xyz'));
    const expected = padded32('abc');
    await sim.call(
      'openAndReadBytes',
      { ...first, holderSecret: holder },
      bytesIdOf(first.claim, first.commitRand),
      expected,
    );
    await sim.call(
      'openAndReadBytes',
      { ...second, holderSecret: holder },
      bytesIdOf(second.claim, second.commitRand),
      expected,
    );
    await expect(
      sim.call(
        'openAndReadBytes',
        { ...other, holderSecret: holder },
        bytesIdOf(other.claim, other.commitRand),
        expected,
      ),
    ).rejects.toThrow('byteValue[0] mismatch');
  });
});

describe('signature and identity coverage', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  it.each([
    ['low', 3],
    ['high', 19],
  ])(
    'rejects a single-byte mutation of the %s half under the honest signatures',
    async (_, byteIndex) => {
      const value = fullSpan();
      const claim = makeByteClaim({ byteValue: value });
      const submission = signed(claim);
      const halves = splitHalves(value);
      const mutated =
        byteIndex < 16
          ? [flip(halves[0], byteIndex), halves[1]]
          : [halves[0], flip(halves[1], byteIndex - 16)];
      await expect(
        submit({ ...submission, claim: { ...claim, byteHalves: mutated } }),
      ).rejects.toThrow('Insufficient valid signatures');
    },
  );

  it('accepts claims differing only in byte value, then rejects the replay', async () => {
    const first = signed(makeByteClaim({ byteValue: padded32('abc') }));
    const second = signed(makeByteClaim({ byteValue: padded32('xyz') }));
    await submit(first);
    await submit(second);
    expect(sim.ledgerView().B_nullifiers.size()).toBe(2n);
    await expect(submit(first)).rejects.toThrow('Observation replay');
  });
});
