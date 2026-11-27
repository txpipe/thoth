import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, expectTypeOf, it } from 'vitest';
import type { A_Claim, A_Observation } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  ACCEPTED_POLICIES,
  DEFAULT_HOLDER_SECRET,
  flip,
  holderOf,
  makeClaim,
  makeNotaryKey,
  nullifierOfClaim,
  OTHER_APP_ID,
  POLICY_A,
  POLICY_B,
  signClaim,
  UNSEALED_POLICY,
} from './helpers/fixtures.js';
import { createPrivateState, type PrivateState } from './helpers/private-state.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
// A threshold of signers: slots 0 and 1 sign, slot 2 does not.
const signers = [notaryKeys[0], notaryKeys[1], null] as const;
const holder = DEFAULT_HOLDER_SECRET;

let sim: MockAttestationSim;

const ps = (overrides: Partial<PrivateState> = {}): PrivateState => ({
  ...createPrivateState(holder),
  ...overrides,
});

describe('mock attestation', () => {
  beforeEach(async () => {
    sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys);
  });

  describe('buildMessage (wire layout)', () => {
    // Little-endian value of a byte vector (first byte least significant),
    // computed independently of the encoders.
    const le = (bytes: Uint8Array): bigint =>
      bytes.reduce((acc, byte, i) => acc + BigInt(byte) * 256n ** BigInt(i), 0n);

    it('signs the version, the layout, the nullifier and the holder as seven fields', () => {
      const holder = new Uint8Array(32);
      holder[0] = 3;
      holder[30] = 4;
      holder[31] = 6;
      const claim = makeClaim({ holder });
      const nullifier = pureCircuits.nullifierOf(claim);
      expect(pureCircuits.message(claim)).toEqual([
        1n,
        3n, // V
        0n, // W
        BigInt(nullifier[31] ?? -1),
        le(nullifier.slice(0, 31)),
        6n,
        3n + (4n << 240n),
      ]);
    });

    it('changes with every byte of the holder', () => {
      const claim = makeClaim();
      const msg = pureCircuits.message(claim);
      for (let i = 0; i < 32; i++) {
        expect(pureCircuits.message({ ...claim, holder: flip(claim.holder, i) })).not.toEqual(msg);
      }
    });

    it('changes with the version', () => {
      const claim = makeClaim();
      expect(pureCircuits.message({ ...claim, version: 2n })[0]).toBe(2n);
    });

    it('changes with every byte of every 32-byte field of the observation identity', () => {
      const claim = makeClaim();
      const msg = pureCircuits.message(claim);
      for (const field of ['appId', 'policyHash', 'subjectHash', 'salt'] as const) {
        for (let i = 0; i < 32; i++) {
          expect(pureCircuits.message({ ...claim, [field]: flip(claim[field], i) })).not.toEqual(
            msg,
          );
        }
      }
    });

    it('distinguishes the window start from the window end', () => {
      const claim = makeClaim({ windowStart: 100n, windowEnd: 200n });
      const swapped = { ...claim, windowStart: 200n, windowEnd: 100n };
      expect(pureCircuits.message(swapped)).not.toEqual(pureCircuits.message(claim));
    });

    it('distinguishes absent (present all false) from a genuine 0 value', () => {
      const absent = makeClaim({ values: [0n, 0n, 0n], present: [false, false, false] });
      const presentZero = makeClaim({ values: [0n, 0n, 0n], present: [true, false, false] });
      expect(pureCircuits.message(absent)).not.toEqual(pureCircuits.message(presentZero));
    });
  });

  describe('verifyAttestation', () => {
    it.each([0, 1, 2])('rejects a nonzero value in absent slot %i', async (slot) => {
      const values = [0n, 0n, 0n];
      values[slot] = 1n;
      const claim = makeClaim({ values, present: [false, false, false] });
      const signed = signClaim(claim, signers);
      await expect(sim.call('verifyAttestation', ps(signed))).rejects.toThrow(
        'Absent slot has nonzero value',
      );
    });

    it('rejects a caller who does not know the signed holder secret', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, signers);
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: randomBytes(32) })),
      ).rejects.toThrow('Holder mismatch');
    });

    it('accepts a claim bound to a fresh caller secret', async () => {
      const secret = randomBytes(32);
      const claim = makeClaim({ holder: pureCircuits.holderCommitment(secret) });
      const signed = signClaim(claim, signers);
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: secret }));
      await sim.call(
        'openAndRead',
        ps({ ...signed, holderSecret: secret }),
        nullifierOfClaim(claim),
        12345n,
        0n,
      );
    });

    it('rejects replacing the signed holder even when the new caller knows its secret', async () => {
      const signed = signClaim(makeClaim(), signers);
      const secret = randomBytes(32);
      const claim = { ...signed.claim, holder: pureCircuits.holderCommitment(secret) };
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, claim, holderSecret: secret })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('accepts 2-of-3 valid signatures (threshold N=2)', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, signers);
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(nullifierOfClaim(claim))).toBe(true);
    });

    it('rejects valid signatures made over a different message', async () => {
      const claim = makeClaim();
      const other = signClaim(makeClaim(), signers);
      await expect(
        sim.call('verifyAttestation', ps({ ...other, claim, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects one key signing under two slots', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[0], null]);
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects a signature from an unregistered key', async () => {
      const outsider = makeNotaryKey();
      const claim = makeClaim();
      const signed = signClaim(claim, [outsider, outsider, null]);
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    // Every field but `holder` and `version` reaches the signature only through
    // the nullifier, so changing any of them after signing must fail the check.
    it.each([
      { name: 'policyHash', mutate: (c: A_Claim) => ({ ...c, policyHash: POLICY_B }) },
      ...[0, 31].map((i) => ({
        name: `subjectHash[${i}]`,
        mutate: (c: A_Claim) => ({ ...c, subjectHash: flip(c.subjectHash, i) }),
      })),
      ...[0, 31].map((i) => ({
        name: `salt[${i}]`,
        mutate: (c: A_Claim) => ({ ...c, salt: flip(c.salt, i) }),
      })),
      { name: 'windowStart', mutate: (c: A_Claim) => ({ ...c, windowStart: c.windowStart - 1n }) },
      { name: 'windowEnd', mutate: (c: A_Claim) => ({ ...c, windowEnd: c.windowEnd - 1n }) },
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
    ])('rejects a claim whose $name changed after signing', async ({ mutate }) => {
      const claim = makeClaim({ values: [1n, 2n, 3n], present: [true, true, true] });
      const signed = signClaim(claim, signers);
      await expect(
        sim.call(
          'verifyAttestation',
          ps({ ...signed, claim: mutate(claim), holderSecret: holder }),
        ),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects a claim whose appId changed after signing', async () => {
      // A contract sealed to the changed app id, so only the signature can reject it.
      const otherApp = await MockAttestationSim.create(createPrivateState(holder), registryKeys, {
        appId: OTHER_APP_ID,
      });
      const signed = signClaim(makeClaim(), signers);
      const claim = { ...signed.claim, appId: OTHER_APP_ID };
      await expect(
        otherApp.call('verifyAttestation', ps({ ...signed, claim, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects a claim whose version changed after signing', async () => {
      // Signed as version 2 and presented as the supported version 1, so only the
      // signature can reject it.
      const signed = signClaim(makeClaim({ version: 2n }), signers);
      const claim = { ...signed.claim, version: 1n };
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, claim, holderSecret: holder })),
      ).rejects.toThrow('Insufficient valid signatures');
    });

    it('rejects an unsupported version', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, signers);
      const bad = { ...signed, claim: { ...signed.claim, version: 2n } };
      await expect(
        sim.call('verifyAttestation', ps({ ...bad, holderSecret: holder })),
      ).rejects.toThrow('Unsupported claim version');
    });

    it("rejects a claim stored in one app when replayed into another app's contract", async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, signers);
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
      const signed = signClaim(claim, signers);
      await expect(
        sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder })),
      ).rejects.toThrow('Unaccepted policy');
    });

    it('accepts a claim under any sealed policy hash', async () => {
      for (const policyHash of ACCEPTED_POLICIES) {
        const claim = makeClaim({ policyHash });
        const signed = signClaim(claim, signers);
        await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
        expect(sim.ledgerView().A_claimsVault.member(nullifierOfClaim(claim))).toBe(true);
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
      const signed = signClaim(claim, signers);
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(nullifierOfClaim(claim))).toBe(true);
    });
  });

  describe('observation replay', () => {
    it('rejects the same observation and salt signed for a fresh holder', async () => {
      const claim = makeClaim();
      await sim.call('verifyAttestation', ps(signClaim(claim, signers)));
      const freshSecret = randomBytes(32);
      const replay = {
        ...claim,
        holder: pureCircuits.holderCommitment(freshSecret),
      };
      await expect(
        sim.call(
          'verifyAttestation',
          ps({
            ...signClaim(replay, signers),
            holderSecret: freshSecret,
          }),
        ),
      ).rejects.toThrow('Observation replay');
    });

    it('rejects a resubmission of the accepted claim and keeps its vault entry', async () => {
      const signed = signClaim(makeClaim(), signers);
      await sim.call('verifyAttestation', ps(signed));
      const nullifier = nullifierOfClaim(signed.claim);
      const before = sim.ledgerView().A_claimsVault.lookup(nullifier);
      await expect(sim.call('verifyAttestation', ps(signed))).rejects.toThrow('Observation replay');
      expect(sim.ledgerView().A_claimsVault.size()).toBe(1n);
      expect(sim.ledgerView().A_claimsVault.lookup(nullifier)).toEqual(before);
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
      await sim.call('verifyAttestation', ps(signClaim(claim, signers)));
      const distinct = mutate(claim);
      const signed = signClaim(distinct, signers);
      await sim.call('verifyAttestation', ps(signed));
      expect(sim.ledgerView().A_claimsVault.member(nullifierOfClaim(distinct))).toBe(true);
      expect(sim.ledgerView().A_claimsVault.size()).toBe(2n);
    });
  });

  // ADR 0005: the window is when the attestor observed. The contract bounds
  // its length and checks it against the block time, with no zero-disable.
  describe('observation window', () => {
    const NOW = 1_800_000_000n;
    const FRESHNESS = 3600n;
    const MAX_WINDOW = 120n;

    const attWith = (claim: A_Claim) => {
      const signed = signClaim(claim, signers);
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
      const signed = signClaim(makeClaim({ windowStart: NOW - 10n, windowEnd: NOW }), signers);
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
    it('stores holder and window under the nullifier', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, signers);
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      const vault = sim.ledgerView().A_claimsVault;
      expect(vault.size()).toBe(1n);
      const entry = vault.lookup(nullifierOfClaim(claim));
      expect(entry.holder).toBe(holderOf(holder));
      expect(entry.windowStart).toBe(claim.windowStart);
      expect(entry.windowEnd).toBe(claim.windowEnd);
    });
  });

  describe('openClaim', () => {
    const store = async (claim = makeClaim()) => {
      const signed = signClaim(claim, signers);
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      return signed;
    };

    it('re-hydrates the claim and reads multiple value slots', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 222n, 333n], present: [true, true, true] }),
      );
      const nullifier = nullifierOfClaim(signed.claim);
      await sim.call('openAndRead', ps({ ...signed, holderSecret: holder }), nullifier, 111n, 222n);
    });

    it('reads per-slot presence directly (present[i] is native)', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 0n, 333n], present: [true, false, true] }),
      );
      const nullifier = nullifierOfClaim(signed.claim);
      await sim.call(
        'openAndReadPresence',
        ps({ ...signed, holderSecret: holder }),
        nullifier,
        true,
        false,
      );
    });

    it('rejects a presence mismatch on a slot', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }),
      );
      const nullifier = nullifierOfClaim(signed.claim);
      await expect(
        sim.call(
          'openAndReadPresence',
          ps({ ...signed, holderSecret: holder }),
          nullifier,
          true,
          true,
        ),
      ).rejects.toThrow('present[1] mismatch');
    });

    it('accepts a claim where the required metric 0 is present', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }),
      );
      const nullifier = nullifierOfClaim(signed.claim);
      await sim.call(
        'openAndRequireMetric0',
        ps({ ...signed, holderSecret: holder }),
        nullifier,
        111n,
      );
    });

    it('rejects a claim where the required metric 0 is absent', async () => {
      const signed = await store(
        makeClaim({ values: [0n, 222n, 333n], present: [false, true, true] }),
      );
      const nullifier = nullifierOfClaim(signed.claim);
      await expect(
        sim.call('openAndRequireMetric0', ps({ ...signed, holderSecret: holder }), nullifier, 0n),
      ).rejects.toThrow('metric 0 not present');
    });

    it('rejects a claim where the required metric 0 value mismatches', async () => {
      const signed = await store(
        makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }),
      );
      const nullifier = nullifierOfClaim(signed.claim);
      await expect(
        sim.call('openAndRequireMetric0', ps({ ...signed, holderSecret: holder }), nullifier, 222n),
      ).rejects.toThrow('value[0] mismatch');
    });

    // Checked by `npm run types`: a predicate that reads either field off the
    // result does not compile.
    it('returns every claim field but holder and version', () => {
      expectTypeOf<A_Observation>().toEqualTypeOf<Omit<A_Claim, 'holder' | 'version'>>();
    });

    it('rejects an unknown nullifier', async () => {
      const signed = await store();
      await expect(
        sim.call(
          'openAndRead',
          ps({ ...signed, holderSecret: holder }),
          randomBytes(32),
          12345n,
          0n,
        ),
      ).rejects.toThrow('Unknown claim');
    });

    it('rejects a caller whose secret does not own the entry', async () => {
      const signed = await store();
      const nullifier = nullifierOfClaim(signed.claim);
      const otherHolder = randomBytes(32);
      await expect(
        sim.call(
          'openAndRead',
          ps({ ...signed, holderSecret: otherHolder }),
          nullifier,
          12345n,
          0n,
        ),
      ).rejects.toThrow('Claim not bound to caller');
    });

    it('rejects a claim that does not hash to the nullifier', async () => {
      const signed = await store(
        makeClaim({ values: [12345n, 0n, 0n], present: [true, false, false] }),
      );
      const nullifier = nullifierOfClaim(signed.claim);
      const tampered = {
        ...signed,
        claim: { ...signed.claim, values: [54321n, 0n, 0n] },
      };
      await expect(
        sim.call('openAndRead', ps({ ...tampered, holderSecret: holder }), nullifier, 54321n, 0n),
      ).rejects.toThrow('Claim does not match nullifier');
    });

    it("rejects the caller's other vaulted claim under this nullifier", async () => {
      const first = await store(makeClaim({ values: [1n, 0n, 0n] }));
      const second = await store(makeClaim({ values: [2n, 0n, 0n] }));
      await expect(
        sim.call(
          'openAndRead',
          ps({ ...second, holderSecret: holder }),
          nullifierOfClaim(first.claim),
          2n,
          0n,
        ),
      ).rejects.toThrow('Claim does not match nullifier');
    });

    // The nullifier binds neither field, so `openClaim` returns neither and
    // does not check the witness's copies.
    it('opens whatever holder and version the witness claim carries', async () => {
      const signed = await store();
      const claim = { ...signed.claim, holder: randomBytes(32), version: 7n };
      await sim.call(
        'openAndRead',
        ps({ ...signed, claim, holderSecret: holder }),
        nullifierOfClaim(signed.claim),
        12345n,
        0n,
      );
    });

    it('is repeatable and consumes nothing', async () => {
      const signed = await store(
        makeClaim({ values: [999n, 0n, 0n], present: [true, false, false] }),
      );
      const nullifier = nullifierOfClaim(signed.claim);
      const before = sim.ledgerView().A_claimsVault.lookup(nullifier);
      const state = ps({ ...signed, holderSecret: holder });
      await sim.call('openAndRead', state, nullifier, 999n, 0n);
      await sim.call('openAndRead', state, nullifier, 999n, 0n);
      expect(sim.ledgerView().A_claimsVault.size()).toBe(1n);
      expect(sim.ledgerView().A_claimsVault.lookup(nullifier)).toEqual(before);
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
      const signed = signClaim(claim, signers);
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      return { signed, nullifier: nullifierOfClaim(signed.claim) };
    };

    it('accepts the subject the claim is about under the pinned host', async () => {
      const { signed, nullifier } = await storeAbout();
      await sim.call(
        'openAndBindHost',
        ps({ ...signed, holderSecret: holder }),
        nullifier,
        subject,
        subject.host,
      );
    });

    it('rejects a subject the claim is not about', async () => {
      const { signed, nullifier } = await storeAbout();
      const other = { ...subject, path: flip(subject.path, 0) };
      await expect(
        sim.call(
          'openAndBindHost',
          ps({ ...signed, holderSecret: holder }),
          nullifier,
          other,
          subject.host,
        ),
      ).rejects.toThrow('Subject mismatch');
    });

    it('rejects the right subject under another host', async () => {
      const { signed, nullifier } = await storeAbout();
      await expect(
        sim.call(
          'openAndBindHost',
          ps({ ...signed, holderSecret: holder }),
          nullifier,
          subject,
          flip(subject.host, 0),
        ),
      ).rejects.toThrow('Host not accepted');
    });
  });
});
