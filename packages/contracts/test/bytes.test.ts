// Byte-slot tests for the bytes mock (V = 3, W = 1): the byte value in the
// message and the nullifier, the absent-slot law in the simulator, byte-value
// predicates, signature coverage over the value, and that the salted nullifier
// does not confirm a guessed value.
import { claimToMessage, toContractClaim } from '@txpipe/thoth-core/claim';
import { beforeEach, describe, expect, it } from 'vitest';
import { pureCircuits as mockPureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import type { B_Claim } from '../artifacts/mock_attestation_bytes/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import {
  atSlots,
  DEFAULT_HOLDER_SECRET,
  flip,
  makeByteClaim,
  makeClaim,
  makeNotaryKey,
  nullifierOfByteClaim,
  padded32,
} from './helpers/fixtures.js';
import { createPrivateState, type SlotSignature } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationBytesSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((key) => key.pk);
const holder = DEFAULT_HOLDER_SECRET;
const ZERO32 = new Uint8Array(32);

// A value with a different byte at every position, so a reordered value
// cannot pass the comparisons below.
const fullSpan = (): Uint8Array => Uint8Array.from({ length: 32 }, (_, i) => i);

// 32 zero bytes but byte `i`. A circuit holds bytes 0-30 apart from byte 31,
// so the first, a middle and the last byte each get a case.
const onlyByte = (i: number): Uint8Array => flip(ZERO32, i);
const EDGE_BYTES = [0, 19, 31];

// Reinterpret the bytes mock's contract shape as the kind-facing core shape:
// one `present` mask, the numeric flags then the byte flag.
const coreOf = (claim: B_Claim) => ({
  ...claim,
  present: [...claim.present, ...claim.bytePresent],
});

type Submission = {
  claim: B_Claim;
  signatures: SlotSignature[];
};

// A threshold signature set over the claim's own compiled message: slots 0
// and 1 sign, slot 2 does not.
const signed = (claim: B_Claim): Submission => {
  const message = pureCircuits.message(claim);
  return {
    claim,
    signatures: atSlots([
      signMessage(notaryKeys[0].sk, message).signature,
      signMessage(notaryKeys[1].sk, message).signature,
      null,
    ]),
  };
};

let sim: MockAttestationBytesSim;

const submit = (submission: Submission) =>
  sim.call('verifyAttestation', { ...submission, holderSecret: holder });

describe('bytes claim wire', () => {
  it('signs the byte-slot count in the layout fields', () => {
    const claim = makeByteClaim();
    expect(pureCircuits.message(claim).slice(0, 3)).toEqual([1n, 3n, 1n]);
    expect(mockPureCircuits.message(makeClaim()).slice(0, 3)).toEqual([1n, 3n, 0n]);
  });

  it('round-trips a core claim through the contract shape', () => {
    const claim = makeByteClaim({ byteValue: fullSpan() });
    const core = coreOf(claim);
    expect(toContractClaim(core)).toEqual(claim);
    expect(pureCircuits.message(toContractClaim(core))).toEqual(claimToMessage(core));
  });

  it('hashes every byte of a byte value, in order', () => {
    const claim = makeByteClaim({ byteValue: fullSpan() });
    const reversed = { ...claim, byteValues: [fullSpan().reverse()] };
    expect(pureCircuits.nullifierOf(reversed)).not.toEqual(pureCircuits.nullifierOf(claim));
  });

  it('hashes an absent byte flag even with the value present', () => {
    const claim = makeByteClaim();
    expect(pureCircuits.nullifierOf({ ...claim, bytePresent: [false] })).not.toEqual(
      pureCircuits.nullifierOf(claim),
    );
  });
});

describe('the absent-slot law in the simulator', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  it('accepts the honest byte-carrying claim', async () => {
    const submission = signed(makeByteClaim());
    await submit(submission);
    expect(sim.ledgerView().B_claimsVault.member(nullifierOfByteClaim(submission.claim))).toBe(
      true,
    );
  });

  it('accepts a present all-zero byte value', async () => {
    const submission = signed(makeByteClaim({ byteValue: ZERO32 }));
    await submit(submission);
    expect(sim.ledgerView().B_claimsVault.member(nullifierOfByteClaim(submission.claim))).toBe(
      true,
    );
  });

  it('rejects a claim whose absent byte slot carries a non-zero value', async () => {
    await expect(submit(signed(makeByteClaim({ bytePresent: [false] })))).rejects.toThrow(
      'Absent slot has nonzero value',
    );
  });

  it.each(EDGE_BYTES)('rejects an absent byte slot whose only non-zero byte is %i', async (i) => {
    const claim = makeByteClaim({ bytePresent: [false], byteValue: onlyByte(i) });
    await expect(submit(signed(claim))).rejects.toThrow('Absent slot has nonzero value');
  });

  it('accepts an absent byte slot whose value is all zero', async () => {
    const submission = signed(makeByteClaim({ bytePresent: [false], byteValue: ZERO32 }));
    await submit(submission);
    expect(sim.ledgerView().B_claimsVault.member(nullifierOfByteClaim(submission.claim))).toBe(
      true,
    );
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
    const nullifier = nullifierOfByteClaim(stored.claim);
    const state = { ...stored, holderSecret: holder };
    await sim.call('openAndReadBytes', state, nullifier, padded32('abc'));
    await expect(sim.call('openAndReadBytes', state, nullifier, padded32('xyz'))).rejects.toThrow(
      'byteValue[0] mismatch',
    );
  });

  it('compares every byte of the value, in order', async () => {
    const value = fullSpan();
    const stored = await vault(value);
    const nullifier = nullifierOfByteClaim(stored.claim);
    const state = { ...stored, holderSecret: holder };
    await sim.call('openAndReadBytes', state, nullifier, value);
    for (const i of EDGE_BYTES) {
      await expect(sim.call('openAndReadBytes', state, nullifier, flip(value, i))).rejects.toThrow(
        'byteValue[0] mismatch',
      );
    }
    await expect(
      sim.call('openAndReadBytes', state, nullifier, fullSpan().reverse()),
    ).rejects.toThrow('byteValue[0] mismatch');
  });

  it('accepts two claims with equal values and rejects a claim with another value', async () => {
    const first = await vault(padded32('abc'));
    const second = await vault(padded32('abc'));
    const other = await vault(padded32('xyz'));
    const expected = padded32('abc');
    await sim.call(
      'openAndReadBytes',
      { ...first, holderSecret: holder },
      nullifierOfByteClaim(first.claim),
      expected,
    );
    await sim.call(
      'openAndReadBytes',
      { ...second, holderSecret: holder },
      nullifierOfByteClaim(second.claim),
      expected,
    );
    await expect(
      sim.call(
        'openAndReadBytes',
        { ...other, holderSecret: holder },
        nullifierOfByteClaim(other.claim),
        expected,
      ),
    ).rejects.toThrow('byteValue[0] mismatch');
  });
});

describe('signature and identity coverage', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  it.each(EDGE_BYTES)(
    'rejects a change to byte %i of the value under the honest signatures',
    async (i) => {
      const claim = makeByteClaim({ byteValue: fullSpan() });
      const submission = signed(claim);
      const mutated = { ...claim, byteValues: [flip(fullSpan(), i)] };
      await expect(submit({ ...submission, claim: mutated })).rejects.toThrow(
        'Insufficient valid signatures',
      );
    },
  );

  it('rejects a claim whose byte flag changed after signing', async () => {
    const claim = makeByteClaim({ byteValue: new Uint8Array(32) });
    const submission = signed(claim);
    await expect(
      submit({ ...submission, claim: { ...claim, bytePresent: [false] } }),
    ).rejects.toThrow('Insufficient valid signatures');
  });

  it('accepts claims differing only in byte value, then rejects the replay', async () => {
    const first = signed(makeByteClaim({ byteValue: padded32('abc') }));
    const second = signed(makeByteClaim({ byteValue: padded32('xyz') }));
    await submit(first);
    await submit(second);
    expect(sim.ledgerView().B_claimsVault.size()).toBe(2n);
    await expect(submit(first)).rejects.toThrow('Observation replay');
  });
});

describe('nullifier privacy', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  it('does not confirm a guessed byte value from the public fields', async () => {
    const claim = makeByteClaim({ byteValue: padded32('alice-github') });
    await submit(signed(claim));
    const vault = sim.ledgerView().B_claimsVault;
    const nullifierOf = (guess: string, salt: Uint8Array) =>
      pureCircuits.nullifierOf({ ...claim, salt, byteValues: [padded32(guess)] });
    // With the secret salt, the true value is the stored nullifier.
    expect(vault.member(nullifierOf('alice-github', claim.salt))).toBe(true);
    // An observer knows every field but the salt; no salt it can name confirms a guess.
    const candidates = ['bob-github', 'alice-github', 'carol-github', 'dave-github'];
    const publicSalts = [new Uint8Array(32), claim.appId, claim.policyHash, claim.subjectHash];
    const confirmed = candidates.filter((candidate) =>
      publicSalts.some((salt) => vault.member(nullifierOf(candidate, salt))),
    );
    expect(confirmed).toEqual([]);
  });
});
