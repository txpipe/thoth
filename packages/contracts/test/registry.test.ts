// Registry tests: the deploy-time `keysDistinct` check (duplicate and
// empty-slot pinning), the double-init guard, and the N named signatures a
// claim is verified with.
import {
  CompactTypeField,
  CompactTypeVector,
  createConstructorContext,
  type JubjubSchnorrSignature,
  jubjubSchnorrVerify,
} from '@midnight-ntwrk/compact-runtime';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import { Contract as DoubleInitContract } from '../artifacts/mock_registry_double_init/contract/index.js';
import {
  DEFAULT_HOLDER_SECRET,
  EMPTY_KEY_SIGNATURE,
  makeClaim,
  makeNotaryKey,
  type NotaryKey,
  nullifierOfClaim,
  signClaim,
} from './helpers/fixtures.js';
import {
  createPrivateState,
  type PrivateState,
  type SlotSignature,
} from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const holder = DEFAULT_HOLDER_SECRET;

const ps = (overrides: Partial<PrivateState> = {}): PrivateState => ({
  ...createPrivateState(holder),
  ...overrides,
});

describe('registry init', () => {
  const [a, b, c] = notaryKeys;
  // default<JubjubPoint> as compiled: the identity point {x: 0n, y: 1n}.
  const empty = { x: 0n, y: 1n };

  it('accepts distinct keys', () => {
    expect(pureCircuits.keysDistinct([a.pk, b.pk, c.pk])).toBe(true);
  });

  it('accepts empty slots alongside distinct keys', () => {
    expect(pureCircuits.keysDistinct([a.pk, b.pk, empty])).toBe(true);
  });

  it('accepts unfilled slots duplicating the default point', () => {
    expect(pureCircuits.keysDistinct([empty, a.pk, empty])).toBe(true);
  });

  it('rejects one key pinned in two slots', () => {
    expect(pureCircuits.keysDistinct([a.pk, a.pk, b.pk])).toBe(false);
  });

  it('rejects a duplicate key when every other slot is empty', () => {
    expect(pureCircuits.keysDistinct([empty, a.pk, a.pk])).toBe(false);
  });

  it('blocks deployment with duplicate keys', async () => {
    await expect(
      MockAttestationSim.create(createPrivateState(holder), [a.pk, a.pk, b.pk]),
    ).rejects.toThrow('Duplicate registry keys');
  });

  it('rejects a second initRegistry call', async () => {
    // `initRegistry` writes a sealed ledger, so only a constructor can call it;
    // this mock's constructor calls it twice.
    const contract = new DoubleInitContract<null>({
      seedKeys: ({ privateState }) => [privateState, [a.pk, b.pk, c.pk]],
    });
    await expect(
      contract.initialState(createConstructorContext(null, '0'.repeat(64))),
    ).rejects.toThrow('Registry already initialized');
  });

  it('still deploys with empty slots', async () => {
    await MockAttestationSim.create(createPrivateState(holder), [a.pk, b.pk, empty]);
  });

  it('accepts a threshold claim with an empty slot', async () => {
    const sim = await MockAttestationSim.create(createPrivateState(holder), [a.pk, b.pk, empty]);
    const claim = makeClaim();
    const signed = signClaim(claim, [a, b, null]);
    await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    expect(sim.ledgerView().A_claimsVault.member(nullifierOfClaim(claim))).toBe(true);
  });
});

describe('named signatures', () => {
  const [a, b, c] = notaryKeys;
  const empty = { x: 0n, y: 1n };
  const claim = makeClaim();
  const sig = (key: NotaryKey) => signMessage(key.sk, pureCircuits.message(claim)).signature;
  const named = (...entries: [number, JubjubSchnorrSignature][]): SlotSignature[] =>
    entries.map(([slot, signature]) => ({ registryIndex: BigInt(slot), signature }));

  const submit = async (signatures: SlotSignature[], keys = [a.pk, b.pk, c.pk]) => {
    const sim = await MockAttestationSim.create(createPrivateState(holder), keys);
    await sim.call('verifyAttestation', ps({ claim, signatures }));
    return sim;
  };

  it.each([
    [0, 1],
    [0, 2],
    [1, 2],
  ])('accepts exactly N signatures from slots %i and %i, with no dummy', async (i, j) => {
    const keys = [a, b, c];
    const sim = await submit(named([i, sig(keys[i] as NotaryKey)], [j, sig(keys[j] as NotaryKey)]));
    expect(sim.ledgerView().A_claimsVault.member(nullifierOfClaim(claim))).toBe(true);
  });

  it('rejects a repeated slot', async () => {
    await expect(submit(named([0, sig(a)], [0, sig(a)]))).rejects.toThrow(
      'Registry slots not increasing',
    );
  });

  it('rejects slots out of order', async () => {
    await expect(submit(named([1, sig(b)], [0, sig(a)]))).rejects.toThrow(
      'Registry slots not increasing',
    );
  });

  // The highest slot then 0: one past 65,535 must not wrap to 0 in the order check.
  it('rejects the highest slot followed by slot 0', async () => {
    await expect(submit(named([65_535, sig(b)], [0, sig(a)]))).rejects.toThrow(
      'Registry slots not increasing',
    );
  });

  it('rejects an empty slot, even with a signature that verifies for the empty key', async () => {
    const msg = pureCircuits.message(claim);
    expect(
      jubjubSchnorrVerify(
        new CompactTypeVector(msg.length, CompactTypeField),
        msg,
        empty,
        EMPTY_KEY_SIGNATURE,
      ),
    ).toBe(true);
    await expect(
      submit(named([0, sig(a)], [2, EMPTY_KEY_SIGNATURE]), [a.pk, b.pk, empty]),
    ).rejects.toThrow('Empty registry slot');
  });

  it.each([3, 255, 65_535])('rejects the out-of-range slot %i', async (slot) => {
    await expect(submit(named([0, sig(a)], [slot, sig(b)]))).rejects.toThrow(
      'Registry slot out of range',
    );
  });

  it('rejects a valid signature presented under another slot', async () => {
    await expect(submit(named([0, sig(a)], [2, sig(b)]))).rejects.toThrow(
      'Insufficient valid signatures',
    );
  });

  it('rejects two valid signatures swapped between their slots', async () => {
    await expect(submit(named([0, sig(b)], [1, sig(a)]))).rejects.toThrow(
      'Insufficient valid signatures',
    );
  });

  it.each([1, 3])('rejects %i signatures where the threshold is 2', async (count) => {
    const all = named([0, sig(a)], [1, sig(b)], [2, sig(c)]);
    await expect(submit(all.slice(0, count))).rejects.toThrow(/getSignatures return value/);
  });

  // Which attestors signed is private: two submissions of one claim from
  // different slots leave the same public transcript and public outputs.
  it('discloses nothing that depends on which slots signed', async () => {
    const proofOf = async (signatures: SlotSignature[]) => {
      const sim = await MockAttestationSim.create(createPrivateState(holder), [a.pk, b.pk, c.pk]);
      sim.now = Number(claim.windowEnd);
      return sim.callForProof('verifyAttestation', ps({ claim, signatures }));
    };
    const low = await proofOf(named([0, sig(a)], [1, sig(b)]));
    const high = await proofOf(named([1, sig(b)], [2, sig(c)]));
    expect(high.publicTranscript).toEqual(low.publicTranscript);
    expect(high.output).toEqual(low.output);
    expect(high.input).toEqual(low.input);
  });
});
