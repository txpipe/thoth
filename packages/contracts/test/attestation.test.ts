import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import type { A_Claim } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  ACCEPTED_POLICIES,
  flip,
  holderOf,
  idOf,
  makeClaim,
  makeNotaryKey,
  nowSeconds,
  POLICY_A,
  POLICY_B,
  signClaim,
  UNSEALED_POLICY,
} from './helpers/fixtures.js';
import { createPrivateState, type PrivateState } from './helpers/private-state.js';
import { MockAttestationSim } from './helpers/sim.js';

const DAY = 86400n;
const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
const holder = randomBytes(32);

let sim: MockAttestationSim;

const ps = (overrides: Partial<PrivateState> = {}): PrivateState => ({
  ...createPrivateState(holder),
  ...overrides,
});

describe('mock attestation', () => {
  beforeEach(async () => {
    sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys);
  });

  describe('buildMessage (frozen wire shape)', () => {
    it('returns exactly K=16 fields in the frozen order', () => {
      const claim = makeClaim({ values: [100n, 200n, 300n], present: [true, true, true] });
      const msg = pureCircuits.message(claim);
      expect(msg).toHaveLength(16);
      // [version, appId0, appId1, policyHash0, policyHash1, timestamp,
      //  nonce0, nonce1, subjectHash0, subjectHash1, p0, p1, p2, v0, v1, v2]
      // APP_ID is 32 × 0xa1 and POLICY_A 32 × 0xb1, so each half repeats the byte.
      const half = (byte: string): bigint => BigInt(`0x${byte.repeat(16)}`);
      expect(msg.slice(0, 6)).toEqual([
        1n,
        half('a1'),
        half('a1'),
        half('b1'),
        half('b1'),
        claim.timestamp,
      ]);
      expect(msg.slice(10)).toEqual([1n, 1n, 1n, 100n, 200n, 300n]);
    });

    it('pins each 16-byte half to its slot (little-endian)', () => {
      const nonce = new Uint8Array(32);
      nonce[0] = 1;
      const subjectHash = new Uint8Array(32);
      subjectHash[16] = 2;
      const msg = pureCircuits.message(makeClaim({ nonce, subjectHash }));
      expect(msg.slice(6, 10)).toEqual([1n, 0n, 0n, 2n]);
    });

    it('distinguishes a change to every byte of every 32-byte field', () => {
      const claim = makeClaim();
      const msg = pureCircuits.message(claim);
      for (const field of ['appId', 'policyHash', 'nonce', 'subjectHash'] as const) {
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
      expect(pureCircuits.message(presentZero)[10]).toBe(1n);
    });
  });

  describe('verifyAttestation', () => {
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
    // check: the nullifier and vault id key on all 32 bytes, so a byte the
    // message did not sign would let one attestment be vaulted repeatedly (#66).
    it.each([
      { name: 'nonce[0]', mutate: (c: A_Claim) => ({ ...c, nonce: flip(c.nonce, 0) }) },
      { name: 'nonce[31]', mutate: (c: A_Claim) => ({ ...c, nonce: flip(c.nonce, 31) }) },
      {
        name: 'subjectHash[31]',
        mutate: (c: A_Claim) => ({ ...c, subjectHash: flip(c.subjectHash, 31) }),
      },
      {
        name: 'nonce[31] and subjectHash[31]',
        mutate: (c: A_Claim) => ({
          ...c,
          nonce: flip(c.nonce, 31),
          subjectHash: flip(c.subjectHash, 31),
        }),
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
      const deployed = await MockAttestationSim.create(
        createPrivateState(holder),
        registryKeys,
        0n,
        [POLICY_B, POLICY_B],
      );
      const policies = deployed.ledgerView().A_policyHashes;
      expect(policies.member(POLICY_B)).toBe(true);
      expect(policies.member(POLICY_A)).toBe(false);
      expect(policies.size()).toBe(1n);
    });

    it('accepts a genuine-0 value when present flag set', async () => {
      const claim = makeClaim({ values: [0n, 200n, 0n], present: [false, true, false] });
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
    });
  });

  describe('nonce replay', () => {
    it('rejects a second use of the same nonce', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      const psState = ps({ ...signed, holderSecret: holder });
      await sim.call('verifyAttestation', psState);
      await expect(sim.call('verifyAttestation', psState)).rejects.toThrow('Nonce replay');
    });
  });

  describe('freshness window', () => {
    const WINDOW = 30n * DAY; // 30-day window, matching the sealed witness value

    const attWith = (claim: A_Claim, overrides: Partial<PrivateState> = {}) => {
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      return ps({ ...signed, holderSecret: holder, ...overrides });
    };

    beforeEach(async () => {
      sim = await MockAttestationSim.create(createPrivateState(holder), registryKeys, WINDOW);
    });

    it('accepts a timestamp inside the window', async () => {
      sim.now = Number(nowSeconds());
      await sim.call('verifyAttestation', attWith(makeClaim({ timestamp: nowSeconds() - 60n })));
    });

    it('rejects a future timestamp', async () => {
      sim.now = Number(nowSeconds());
      await expect(
        sim.call('verifyAttestation', attWith(makeClaim({ timestamp: nowSeconds() + 86400n }))),
      ).rejects.toThrow('Timestamp in the future');
    });

    it('rejects a stale timestamp (older than the 30-day window)', async () => {
      sim.now = Number(nowSeconds());
      await expect(
        sim.call('verifyAttestation', attWith(makeClaim({ timestamp: nowSeconds() - 31n * DAY }))),
      ).rejects.toThrow('Timestamp too old');
    });
  });

  describe('claim vault content', () => {
    it('stores holder and timestamp under the claim id', async () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      const entry = sim.ledgerView().A_claimsVault.lookup(idOf(claim, signed.commitRand));
      expect(entry.holder).toBe(holderOf(holder));
      expect(entry.timestamp).toBe(claim.timestamp);
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
