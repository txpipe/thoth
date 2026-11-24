// Byte-value slot tests for the bytes mock (V = 3, W = 1): wire parity
// between `claimToMessage` / `nullifierOf` and the compiled `buildMessage` /
// `nullifierOf`, layout binding, the absent-slot law in the simulator,
// byte-value predicates, signature coverage over every byte, the W = 0
// layout, and that the salted nullifier does not confirm a guessed value.
import { claimToMessage, nullifierOf, toContractClaim } from '@thoth/core/claim';
import { beforeEach, describe, expect, it } from 'vitest';
import type { A_Claim } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits as mockPureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import type { B_Claim } from '../artifacts/mock_attestation_bytes/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import {
  bySlot,
  bytesIdOf,
  DEFAULT_HOLDER_SECRET,
  flip,
  makeByteClaim,
  makeClaim,
  makeNotaryKey,
  padded32,
} from './helpers/fixtures.js';
import { createPrivateState, type SlotSignature } from './helpers/private-state.js';
import { coreOf, messageOf, signMessage } from './helpers/sign.js';
import { MockAttestationBytesSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((key) => key.pk);
const holder = DEFAULT_HOLDER_SECRET;
const ZERO32 = new Uint8Array(32);

// A value whose 32 bytes all differ, so a swapped or reversed byte order
// cannot pass the assertions below.
const fullSpan = (): Uint8Array => Uint8Array.from({ length: 32 }, (_, i) => i);

type Submission = {
  claim: B_Claim;
  signatures: SlotSignature[];
};

// A threshold signature set over a message: the keys in slots 0 and 1 sign,
// slot 2 does not.
const signedOver = (claim: B_Claim, message: readonly bigint[]): Submission => ({
  claim,
  signatures: bySlot([
    signMessage(notaryKeys[0].sk, message).signature,
    signMessage(notaryKeys[1].sk, message).signature,
    null,
  ]),
});

// The same, over the message an attestor signs for the claim.
const signed = (claim: B_Claim): Submission => signedOver(claim, messageOf(claim));

let sim: MockAttestationBytesSim;

const submit = (submission: Submission) =>
  sim.call('verifyAttestation', { ...submission, holderSecret: holder });

describe('bytes claim wire', () => {
  it('matches claimToMessage and nullifierOf, layout V = 3, W = 1', () => {
    const claim = makeByteClaim({ byteValue: fullSpan() });
    const message = pureCircuits.message(claim);
    expect(nullifierOf(coreOf(claim))).toEqual(pureCircuits.nullifierOf(claim));
    expect(message).toEqual({
      version: 1n,
      v: 3n,
      w: 1n,
      nullifier: pureCircuits.nullifierOf(claim),
      holder: claim.holder,
    });
    expect(claimToMessage(coreOf(claim)).slice(0, 3)).toEqual([1n, 3n, 1n]);
  });

  it('round-trips a core claim through the contract shape', () => {
    const claim = makeByteClaim({ byteValue: fullSpan() });
    const core = coreOf(claim);
    expect(toContractClaim(core)).toEqual(claim);
    expect(pureCircuits.nullifierOf(toContractClaim(core))).toEqual(nullifierOf(core));
  });

  it('hashes the byte value whole, in order, after the numeric values', () => {
    const claim = makeByteClaim({ byteValue: fullSpan() });
    const nullifier = pureCircuits.nullifierOf(claim);
    for (const index of [0, 15, 16, 30, 31]) {
      const byteValues = [flip(fullSpan(), index)];
      expect(pureCircuits.nullifierOf({ ...claim, byteValues })).not.toEqual(nullifier);
    }
    const reversed = { ...claim, byteValues: [fullSpan().reverse()] };
    expect(pureCircuits.nullifierOf(reversed)).not.toEqual(nullifier);
  });

  it('signs the byte flag apart from the value', () => {
    const claim = makeByteClaim({ byteValue: ZERO32 });
    expect(pureCircuits.message({ ...claim, bytePresent: [false] })).not.toEqual(
      pureCircuits.message(claim),
    );
  });

  it('signs a zero byte-slot count for a W = 0 claim', () => {
    const claim: A_Claim = makeClaim();
    const message = claimToMessage({ ...claim, byteValues: [] });
    expect(message).toHaveLength(7);
    expect(message.slice(1, 3)).toEqual([3n, 0n]);
    expect(mockPureCircuits.message(claim)).toMatchObject({ v: 3n, w: 0n });
  });

  it('pins the numeric-only (W = 0) nullifier against serialization drift', () => {
    // For W = 0 the empty byte vectors contribute no bytes, so this is the
    // numeric-only module's nullifier, which the attestors sign and the vault
    // is keyed by; a struct reorder or added field turns it red.
    const b = (byte: number) => new Uint8Array(32).fill(byte);
    const claim: A_Claim = {
      version: 1n,
      appId: b(0x11),
      policyHash: b(0x22),
      windowStart: 100n,
      windowEnd: 200n,
      subjectHash: b(0x33),
      holder: b(0x44),
      salt: b(0x55),
      present: [true, false, true],
      values: [7n, 8n, 9n],
      bytePresent: [],
      byteValues: [],
    };
    expect(Buffer.from(mockPureCircuits.nullifierOf(claim)).toString('hex')).toBe(
      'b91ebaa1e6cbc13692b83d1b3b3867afd0a8427438b8714e681607a7ef963bcb',
    );
  });
});

describe('layout binding', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  // Two layouts whose observation identities have one length can hash to one
  // nullifier (`@thoth/core`'s claim tests build V = 11, W = 0 against V = 0,
  // W = 3). No other layout has this mock's identity length (9V + 33W = 60),
  // so each case signs the deployed claim's own nullifier and holder under
  // another layout: what an attestor signs for a claim of that layout whose
  // identity serializes to the same bytes.
  it.each([
    [3n, 0n],
    [0n, 1n],
    [11n, 0n],
    [0n, 3n],
  ])('rejects honest signatures over the same nullifier under V = %i, W = %i', async (v, w) => {
    const claim = makeByteClaim();
    const deployed = messageOf(claim);
    expect(deployed.slice(1, 3)).toEqual([3n, 1n]);
    const message = [deployed[0] ?? 1n, v, w, ...deployed.slice(3)];
    await expect(submit(signedOver(claim, message))).rejects.toThrow(
      'Insufficient valid signatures',
    );
    // The same claim signed under its own layout is accepted.
    await submit(signed(claim));
  });
});

describe('the absent-slot law in the simulator', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  const accepted = async (submission: Submission) => {
    await submit(submission);
    expect(sim.ledgerView().B_claimsVault.member(bytesIdOf(submission.claim))).toBe(true);
  };

  it('accepts the honest byte-carrying claim', async () => {
    await accepted(signed(makeByteClaim()));
  });

  it('accepts a present all-zero byte value', async () => {
    await accepted(signed(makeByteClaim({ byteValue: ZERO32 })));
  });

  it('rejects an absent byte slot that carries non-zero bytes', async () => {
    await expect(submit(signed(makeByteClaim({ bytePresent: [false] })))).rejects.toThrow(
      'Absent slot has nonzero value',
    );
  });

  it.each([0, 30, 31])(
    'rejects an absent byte slot whose only non-zero byte is byte %i',
    async (index) => {
      const byteValue = new Uint8Array(32);
      byteValue[index] = 1;
      await expect(
        submit(signed(makeByteClaim({ bytePresent: [false], byteValue }))),
      ).rejects.toThrow('Absent slot has nonzero value');
    },
  );

  it('accepts an absent slot that is all zero', async () => {
    await accepted(signed(makeByteClaim({ bytePresent: [false], byteValue: ZERO32 })));
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
    const id = bytesIdOf(stored.claim);
    const state = { ...stored, holderSecret: holder };
    await sim.call('openAndReadBytes', state, id, padded32('abc'));
    await expect(sim.call('openAndReadBytes', state, id, padded32('xyz'))).rejects.toThrow(
      'byteValue[0] mismatch',
    );
  });

  it('compares a full-span value byte for byte, in order', async () => {
    const value = fullSpan();
    const stored = await vault(value);
    const id = bytesIdOf(stored.claim);
    const state = { ...stored, holderSecret: holder };
    await sim.call('openAndReadBytes', state, id, value);
    // A mutation at either end of the value is rejected...
    for (const index of [0, 30, 31]) {
      await expect(sim.call('openAndReadBytes', state, id, flip(value, index))).rejects.toThrow(
        'byteValue[0] mismatch',
      );
    }
    // ...and so is the reversed value, so the order is pinned, not just the set.
    await expect(
      sim.call('openAndReadBytes', state, id, Uint8Array.from(value).reverse()),
    ).rejects.toThrow('byteValue[0] mismatch');
  });

  it.each([
    {
      field: 'byteValues',
      mutate: (c: B_Claim) => ({ ...c, byteValues: [flip(c.byteValues[0] ?? ZERO32, 31)] }),
    },
    { field: 'bytePresent', mutate: (c: B_Claim) => ({ ...c, bytePresent: [false] }) },
  ])('rejects an opening witness with $field changed', async ({ mutate }) => {
    const stored = await vault(padded32('abc'));
    const tampered = { ...stored, claim: mutate(stored.claim), holderSecret: holder };
    await expect(
      sim.call('openAndReadBytes', tampered, bytesIdOf(stored.claim), padded32('abc')),
    ).rejects.toThrow('Claim does not match nullifier');
  });

  it('accepts two claims with equal values and rejects a claim with another value', async () => {
    const first = await vault(padded32('abc'));
    const second = await vault(padded32('abc'));
    const other = await vault(padded32('xyz'));
    const expected = padded32('abc');
    await sim.call(
      'openAndReadBytes',
      { ...first, holderSecret: holder },
      bytesIdOf(first.claim),
      expected,
    );
    await sim.call(
      'openAndReadBytes',
      { ...second, holderSecret: holder },
      bytesIdOf(second.claim),
      expected,
    );
    await expect(
      sim.call(
        'openAndReadBytes',
        { ...other, holderSecret: holder },
        bytesIdOf(other.claim),
        expected,
      ),
    ).rejects.toThrow('byteValue[0] mismatch');
  });
});

describe('signature and identity coverage', () => {
  beforeEach(async () => {
    sim = await MockAttestationBytesSim.create(createPrivateState<B_Claim>(holder), registryKeys);
  });

  it.each([0, 15, 30, 31])(
    'rejects a mutation of byte %i of the value under the honest signatures',
    async (byteIndex) => {
      const value = fullSpan();
      const claim = makeByteClaim({ byteValue: value });
      const submission = signed(claim);
      await expect(
        submit({ ...submission, claim: { ...claim, byteValues: [flip(value, byteIndex)] } }),
      ).rejects.toThrow('Insufficient valid signatures');
    },
  );

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
    // The vault is keyed by the public nullifier.
    const nullifiers = sim.ledgerView().B_claimsVault;
    const nullifierOf = (guess: string, salt: Uint8Array) =>
      pureCircuits.nullifierOf({ ...claim, salt, byteValues: [padded32(guess)] });
    // With the secret salt, the true value is the stored nullifier.
    expect(nullifiers.member(nullifierOf('alice-github', claim.salt))).toBe(true);
    // An observer knows every field but the salt; no salt it can name confirms a guess.
    const candidates = ['bob-github', 'alice-github', 'carol-github', 'dave-github'];
    const publicSalts = [new Uint8Array(32), claim.appId, claim.policyHash, claim.subjectHash];
    const confirmed = candidates.filter((candidate) =>
      publicSalts.some((salt) => nullifiers.member(nullifierOf(candidate, salt))),
    );
    expect(confirmed).toEqual([]);
  });
});
