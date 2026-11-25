import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import type { A_Claim } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  ACCEPTED_POLICIES,
  DEFAULT_HOLDER_SECRET,
  flip,
  holderOf,
  idOf,
  makeClaim,
  makeNotaryKey,
  OTHER_APP_ID,
  POLICY_A,
  POLICY_B,
  signClaim,
  UNSEALED_POLICY,
} from './helpers/fixtures.js';
import {
  createPrivateState,
  type PrivateState,
  privateStateWith,
} from './helpers/private-state.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
const holder = DEFAULT_HOLDER_SECRET;

let sim: MockAttestationSim;

const ps = (overrides: Partial<PrivateState> = {}): PrivateState =>
  privateStateWith(holder, overrides);

describe('mock attestation', () => {
  beforeEach(async () => {
    sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys);
  });

  describe('buildMessage (frozen wire shape)', () => {
    it('returns exactly K=20 fields in the frozen order', () => {
      const claim = makeClaim({ values: [100n, 200n, 300n], present: [true, true, true] });
      const msg = pureCircuits.message(claim);
      expect(msg).toHaveLength(20);
      // [version, appId0, appId1, policyHash0, policyHash1, windowStart, windowEnd,
      //  subjectHash0, subjectHash1, holder0, holder1, salt0, salt1, B, p0, p1, p2, v0, v1, v2]
      // APP_ID is 32 × 0xa1 and POLICY_A 32 × 0xb1, so each half repeats the byte.
      const half = (byte: string): bigint => BigInt(`0x${byte.repeat(16)}`);
      expect(msg.slice(0, 7)).toEqual([
        1n,
        half('a1'),
        half('a1'),
        half('b1'),
        half('b1'),
        claim.windowStart,
        claim.windowEnd,
      ]);
      // B = 0: the numeric-only layout signs a zero byte-half count.
      expect(msg.slice(13)).toEqual([0n, 1n, 1n, 1n, 100n, 200n, 300n]);
    });

    it('pins each 16-byte half to its slot (little-endian)', () => {
      const subjectHash = new Uint8Array(32);
      subjectHash[0] = 1;
      subjectHash[16] = 2;
      const msg = pureCircuits.message(makeClaim({ subjectHash }));
      expect(msg.slice(7, 9)).toEqual([1n, 2n]);
    });

    it('pins every holder byte to its two signed header slots', () => {
      const holder = new Uint8Array(32);
      holder[0] = 3;
      holder[15] = 4;
      holder[16] = 5;
      holder[31] = 6;
      const msg = pureCircuits.message(makeClaim({ holder }));
      expect(msg.slice(9, 11)).toEqual([3n + (4n << 120n), 5n + (6n << 120n)]);
    });

    it('signs the salt in the two header slots after the holder', () => {
      const salt = new Uint8Array(32);
      salt[0] = 7;
      salt[16] = 8;
      expect(pureCircuits.message(makeClaim({ salt })).slice(11, 13)).toEqual([7n, 8n]);
    });

    it('distinguishes the window start from the window end', () => {
      const claim = makeClaim({ windowStart: 100n, windowEnd: 200n });
      const swapped = { ...claim, windowStart: 200n, windowEnd: 100n };
      expect(pureCircuits.message(swapped)).not.toEqual(pureCircuits.message(claim));
    });

    it('distinguishes a change to every byte of every 32-byte field', () => {
      const claim = makeClaim();
      const msg = pureCircuits.message(claim);
      for (const field of ['appId', 'policyHash', 'subjectHash', 'holder', 'salt'] as const) {
        for (let i = 0; i < 32; i++) {
          expect(pureCircuits.message({ ...claim, [field]: flip(claim[field], i) })).not.toEqual(
            msg,
          );
        }
      }
    });

    it('distinguishes absent (present all false) from a genuine 0 value', () => {
      const absent = makeClaim({ values: [0n, 0n, 0n], present: [false, false, false] });
      const presentZero = makeClaim({ values: [0n, 0n, 0n], present: [true, false, false] });
      expect(pureCircuits.message(absent)).not.toEqual(pureCircuits.message(presentZero));
      expect(pureCircuits.message(presentZero)[14]).toBe(1n);
    });
  });

  describe('verifyAttestation', () => {
    it.each([0, 1, 2])('rejects a nonzero value in absent slot %i', async (slot) => {
      const values = [0n, 0n, 0n];
      values[slot] = 1n;
      const claim = makeClaim({ values, present: [false, false, false] });
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await expect(sim.call('verifyAttestation', ps(signed))).rejects.toThrow(
        'Absent slot has nonzero value',
      );
    });

    it('rejects a caller who does not know the signed holder secret', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: randomBytes(32) })),
      ).rejects.toThrow('Holder mismatch');
    });

    it('accepts a claim bound to a fresh caller secret', async () => {
      const secret = randomBytes(32);
      const claim = makeClaim({ holder: pureCircuits.holderCommitment(secret) });
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: secret }));
      await sim.call(
        'openAndRead',
        ps({ ...signed, holderSecret: secret }),
        idOf(claim, signed.commitRand),
        12345n,
        0n,
      );
    });

    it('rejects replacing the signed holder even when the new caller knows its secret', async () => {
      const signed = signClaim(makeClaim(), notaryKeys, randomBytes(32));
      const secret = randomBytes(32);
      const claim = { ...signed.claim, holder: pureCircuits.holderCommitment(secret) };
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, claim, holderSecret: secret })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('accepts 2-of-3 valid signatures (threshold N=2)', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
    });

    it('rejects valid signatures made over a different message', async () => {
      const claim = makeClaim();
      const other = signClaim(makeClaim(), notaryKeys, randomBytes(32));
      await expect(
        sim.call('verifyAttestation', ps({ ...other, claim, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('accepts 3-of-3 valid signatures', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
    });

    it('rejects 1-of-3 valid signatures', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], null, null], randomBytes(32));
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects the same key signing into two slots (positional verification)', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[0], null], randomBytes(32));
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects a signature from an unregistered key', async () => {
      const outsider = makeNotaryKey();
      const claim = makeClaim();
      const signed = signClaim(claim, [outsider, outsider, null], randomBytes(32));
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects a tampered claim (value flipped)', async () => {
      const claim = makeClaim({ values: [12345n, 0n, 0n], present: [true, false, false] });
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      const tampered = {
        claim: { ...signed.claim, values: [54321n, 0n, 0n] },
        commitRand: signed.commitRand,
      };
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, ...tampered, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    // Replaying accepted signatures with a mutated byte must fail the signature
    // check. Every byte of the subject hash contributes to the observation
    // identity, so omitting a byte from the signed message would allow replay.
    it.each([
      {
        name: 'subjectHash[31]',
        mutate: (c: A_Claim) => ({ ...c, subjectHash: flip(c.subjectHash, 31) }),
      },
    ])('rejects a replay of accepted signatures with $name mutated', async ({ mutate }) => {
      const signed = signClaim(makeClaim(), [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      const replayed = { ...signed, claim: mutate(signed.claim) };
      await expect(
        sim.call('verifyAttestation', ps({ ...replayed, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects an unsupported version', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      const bad = { ...signed, claim: { ...signed.claim, version: 2n } };
      await expect(
        sim.call('verifyAttestation', ps({ ...bad, holderSecret: holder })),
      ).rejects.toThrow('Unsupported claim version');
    });

    it("rejects a claim stored in one app when replayed into another app's contract", async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await sim.call('verifyAttestation', ps(signed));
      const otherApp = await MockAttestationSim.create(createPrivateState(holder), registryKeys, {
        appId: OTHER_APP_ID,
      });
      await expect(otherApp.call('verifyAttestation', ps(signed))).rejects.toThrow(
        'App id mismatch',
      );
    });

    it('seals the deploy-time app id', async () => {
      const deployed = await MockAttestationSim.create(createPrivateState(holder), registryKeys, {
        appId: OTHER_APP_ID,
      });
      expect(deployed.ledgerView().A_appId).toEqual(OTHER_APP_ID);
    });

    it('rejects a claim whose policyHash is not in the sealed set', async () => {
      const claim = makeClaim({ policyHash: UNSEALED_POLICY });
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder })),
      ).rejects.toThrow('Unaccepted policy');
    });

    it('accepts a claim under any sealed policy hash', async () => {
      for (const policyHash of ACCEPTED_POLICIES) {
        const claim = makeClaim({ policyHash });
        const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
        await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
        expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
      }
    });

    it('seals exactly the deploy-time policy hashes', async () => {
      const deployed = await MockAttestationSim.create(createPrivateState(holder), registryKeys, {
        policyHashes: [POLICY_B, POLICY_B],
      });
      const policies = deployed.ledgerView().A_policyHashes;
      expect(policies.member(POLICY_B)).toBe(true);
      expect(policies.member(POLICY_A)).toBe(false);
      expect(policies.size()).toBe(1n);
    });

    it.each([
      { name: 'all absent', values: [0n, 0n, 0n], present: [false, false, false] },
      { name: 'all measured zeros', values: [0n, 0n, 0n], present: [true, true, true] },
      { name: 'mixed presence', values: [0n, 200n, 0n], present: [true, true, false] },
    ])('accepts valid slots with $name', async ({ values, present }) => {
      const claim = makeClaim({ values, present });
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
    });
  });

  describe('observation replay', () => {
    it('rejects the same observation and salt signed for a fresh holder', async () => {
      const claim = makeClaim();
      await sim.call('verifyAttestation', ps(signClaim(claim, notaryKeys, randomBytes(32))));
      const freshSecret = randomBytes(32);
      const replay = {
        ...claim,
        holder: pureCircuits.holderCommitment(freshSecret),
      };
      await expect(
        sim.call(
          'verifyAttestation',
          ps({
            ...signClaim(replay, notaryKeys, randomBytes(32)),
            holderSecret: freshSecret,
          }),
        ),
      ).rejects.toThrow('Observation replay');
    });

    it('rejects the same observation with fresh vault randomness', async () => {
      const claim = makeClaim();
      await sim.call('verifyAttestation', ps(signClaim(claim, notaryKeys, randomBytes(32))));
      await expect(
        sim.call('verifyAttestation', ps(signClaim(claim, notaryKeys, randomBytes(32)))),
      ).rejects.toThrow('Observation replay');
    });

    it.each([
      { name: 'policyHash', mutate: (c: A_Claim) => ({ ...c, policyHash: POLICY_B }) },
      {
        name: 'subjectHash',
        mutate: (c: A_Claim) => ({ ...c, subjectHash: flip(c.subjectHash, 31) }),
      },
      { name: 'windowStart', mutate: (c: A_Claim) => ({ ...c, windowStart: c.windowStart + 1n }) },
      { name: 'windowEnd', mutate: (c: A_Claim) => ({ ...c, windowEnd: c.windowEnd - 1n }) },
      { name: 'salt', mutate: (c: A_Claim) => ({ ...c, salt: flip(c.salt, 0) }) },
      ...[0, 1, 2].flatMap((slot) => [
        {
          name: `values[${slot}]`,
          mutate: (c: A_Claim) => ({
            ...c,
            values: c.values.map((value, i) => (i === slot ? value + 1n : value)),
          }),
        },
        {
          name: `present[${slot}]`,
          mutate: (c: A_Claim) => ({
            ...c,
            present: c.present.map((value, i) => (i === slot ? !value : value)),
          }),
        },
      ]),
    ])('accepts a distinct observation after changing $name', async ({ mutate }) => {
      const claim = makeClaim({ values: [0n, 0n, 0n], present: [true, true, true] });
      await sim.call('verifyAttestation', ps(signClaim(claim, notaryKeys, randomBytes(32))));
      const distinct = mutate(claim);
      const signed = signClaim(distinct, notaryKeys, randomBytes(32));
      await sim.call('verifyAttestation', ps(signed));
      expect(sim.ledgerView().A_claimsVault.member(idOf(distinct, signed.commitRand))).toBe(true);
      expect(sim.ledgerView().A_nullifiers.size()).toBe(2n);
    });

    it('rejects a second submission of the same observation', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      const psState = ps({ ...signed, holderSecret: holder });
      await sim.call('verifyAttestation', psState);
      await expect(sim.call('verifyAttestation', psState)).rejects.toThrow('Observation replay');
    });
  });

  // ADR 0005: the window is when the attestor observed. The contract bounds
  // its length and checks it against the block time, with no zero-disable.
  describe('observation window', () => {
    const NOW = 1_800_000_000n;
    const FRESHNESS = 3600n;
    const MAX_WINDOW = 120n;

    const attWith = (claim: A_Claim) => {
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      return ps({ ...signed, holderSecret: holder });
    };

    // Submit a claim observed over [windowStart, windowEnd] at block time `at`.
    const submit = (windowStart: bigint, windowEnd: bigint, at = NOW) => {
      sim.now = Number(at);
      return sim.call('verifyAttestation', attWith(makeClaim({ windowStart, windowEnd })));
    };

    beforeEach(async () => {
      sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys, {
        freshnessWindow: FRESHNESS,
        maxWindow: MAX_WINDOW,
      });
    });

    it('accepts a block time inside the window', async () => {
      await submit(NOW - 10n, NOW + 10n);
    });

    it('accepts a block time at the window start', async () => {
      await submit(NOW, NOW + 10n);
    });

    it('accepts a block time after the window within the freshness window', async () => {
      await submit(NOW - 60n, NOW - 50n, NOW - 50n + FRESHNESS - 1n);
    });

    it('accepts a window exactly maxWindow long', async () => {
      await submit(NOW - MAX_WINDOW, NOW);
    });

    it('accepts a zero-length window', async () => {
      await submit(NOW, NOW);
    });

    it('rejects a window longer than maxWindow', async () => {
      await expect(submit(NOW - MAX_WINDOW - 1n, NOW)).rejects.toThrow('Window too long');
    });

    it('rejects a window that ends before it starts', async () => {
      await expect(submit(NOW, NOW - 1n)).rejects.toThrow('Window inverted');
    });

    it('rejects a window that starts after the block time', async () => {
      await expect(submit(NOW + 1n, NOW + 10n)).rejects.toThrow('Window in the future');
    });

    it('rejects a block time at windowEnd plus freshnessWindow', async () => {
      await expect(submit(NOW - 60n, NOW - 50n, NOW - 50n + FRESHNESS)).rejects.toThrow(
        'Window too old',
      );
    });

    it('rejects a replay of accepted signatures with the window shifted', async () => {
      const signed = signClaim(
        makeClaim({ windowStart: NOW - 10n, windowEnd: NOW }),
        [notaryKeys[0], notaryKeys[1], null],
        randomBytes(32),
      );
      sim.now = Number(NOW);
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      const shifted = { ...signed.claim, windowStart: NOW - 5n, windowEnd: NOW + 5n };
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, claim: shifted, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    // freshnessWindow = 0 does not disable the check: the block time must then
    // fall inside the window itself.
    describe('with a zero freshnessWindow', () => {
      beforeEach(async () => {
        sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys, {
          freshnessWindow: 0n,
          maxWindow: MAX_WINDOW,
        });
      });

      it('accepts a block time before the window end', async () => {
        await submit(NOW - 10n, NOW + 1n);
      });

      it('rejects a block time at the window end', async () => {
        await expect(submit(NOW - 10n, NOW)).rejects.toThrow('Window too old');
      });

      it('rejects a stale window', async () => {
        await expect(submit(NOW - 60n, NOW - 50n)).rejects.toThrow('Window too old');
      });
    });
  });

  describe('claim vault content', () => {
    it('stores holder and window under the claim id', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      const entry = sim.ledgerView().A_claimsVault.lookup(idOf(claim, signed.commitRand));
      expect(entry.holder).toBe(holderOf(holder));
      expect(entry.windowStart).toBe(claim.windowStart);
      expect(entry.windowEnd).toBe(claim.windowEnd);
    });
  });

  describe('openClaim', () => {
    const store = async (claim = makeClaim()) => {
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      return signed;
    };

    it('re-hydrates the claim and reads multiple value slots', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 222n, 333n], present: [true, true, true] }),
      );
      const id = idOf(signed.claim, signed.commitRand);
      await sim.call('openAndRead', ps({ ...signed, holderSecret: holder }), id, 111n, 222n);
    });

    it('reads per-slot presence directly (present[i] is native)', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 0n, 333n], present: [true, false, true] }),
      );
      const id = idOf(signed.claim, signed.commitRand);
      await sim.call(
        'openAndReadPresence',
        ps({ ...signed, holderSecret: holder }),
        id,
        true,
        false,
      );
    });

    it('rejects a presence mismatch on a slot', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }),
      );
      const id = idOf(signed.claim, signed.commitRand);
      await expect(
        sim.call('openAndReadPresence', ps({ ...signed, holderSecret: holder }), id, true, true),
      ).rejects.toThrow('present[1] mismatch');
    });

    it('accepts a claim where the required metric 0 is present', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }),
      );
      const id = idOf(signed.claim, signed.commitRand);
      await sim.call('openAndRequireMetric0', ps({ ...signed, holderSecret: holder }), id, 111n);
    });

    it('rejects a claim where the required metric 0 is absent', async () => {
      const signed = await store(
        makeClaim({ values: [0n, 222n, 333n], present: [false, true, true] }),
      );
      const id = idOf(signed.claim, signed.commitRand);
      await expect(
        sim.call('openAndRequireMetric0', ps({ ...signed, holderSecret: holder }), id, 0n),
      ).rejects.toThrow('metric 0 not present');
    });

    it('rejects a claim where the required metric 0 value mismatches', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }),
      );
      const id = idOf(signed.claim, signed.commitRand);
      await expect(
        sim.call('openAndRequireMetric0', ps({ ...signed, holderSecret: holder }), id, 222n),
      ).rejects.toThrow('value[0] mismatch');
    });

    it('rejects an unknown claim', async () => {
      const signed = await store();
      const wrongId = randomBytes(32);
      await expect(
        sim.call('openAndRead', ps({ ...signed, holderSecret: holder }), wrongId, 12345n, 0n),
      ).rejects.toThrow('Unknown claim');
    });

    it('rejects a claim not bound to the caller', async () => {
      const signed = await store();
      const id = idOf(signed.claim, signed.commitRand);
      const otherHolder = randomBytes(32);
      await expect(
        sim.call('openAndRead', ps({ ...signed, holderSecret: otherHolder }), id, 12345n, 0n),
      ).rejects.toThrow('Claim not bound to caller');
    });

    it('rejects a claim that does not match the id', async () => {
      const signed = await store(
        makeClaim({ values: [12345n, 0n, 0n], present: [true, false, false] }),
      );
      const id = idOf(signed.claim, signed.commitRand);
      const tampered = {
        ...signed,
        claim: { ...signed.claim, values: [54321n, 0n, 0n] },
      };
      await expect(
        sim.call('openAndRead', ps({ ...tampered, holderSecret: holder }), id, 54321n, 0n),
      ).rejects.toThrow('Claim does not match id');
    });

    it('is repeatable (no nullifier consumed)', async () => {
      const signed = await store(
        makeClaim({ values: [999n, 0n, 0n], present: [true, false, false] }),
      );
      const id = idOf(signed.claim, signed.commitRand);
      const state = ps({ ...signed, holderSecret: holder });
      await sim.call('openAndRead', state, id, 999n, 0n);
      await sim.call('openAndRead', state, id, 999n, 0n);
    });
  });

  // ADR 0001: the app supplies the subject privately and the circuit binds it
  // to the vaulted claim through `subjectHash`, pinning only the host.
  describe('source binding (subjectHash)', () => {
    const subject = {
      method: randomBytes(32),
      host: randomBytes(32),
      path: randomBytes(32),
      body: randomBytes(32),
    };

    const storeAbout = async () => {
      const claim = makeClaim({ subjectHash: pureCircuits.subjectHash(subject) });
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      return { signed, id: idOf(signed.claim, signed.commitRand) };
    };

    it('accepts the subject the claim is about under the pinned host', async () => {
      const { signed, id } = await storeAbout();
      await sim.call(
        'openAndBindHost',
        ps({ ...signed, holderSecret: holder }),
        id,
        subject,
        subject.host,
      );
    });

    it('rejects a subject the claim is not about', async () => {
      const { signed, id } = await storeAbout();
      const other = { ...subject, path: flip(subject.path, 0) };
      await expect(
        sim.call(
          'openAndBindHost',
          ps({ ...signed, holderSecret: holder }),
          id,
          other,
          subject.host,
        ),
      ).rejects.toThrow('Subject mismatch');
    });

    it('rejects the right subject under another host', async () => {
      const { signed, id } = await storeAbout();
      await expect(
        sim.call(
          'openAndBindHost',
          ps({ ...signed, holderSecret: holder }),
          id,
          subject,
          flip(subject.host, 0),
        ),
      ).rejects.toThrow('Host not accepted');
    });
  });
});
