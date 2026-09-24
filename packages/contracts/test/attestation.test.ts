import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import type { A_Claim } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  holderOf,
  idOf,
  makeClaim,
  makeNotaryKey,
  nowSeconds,
  signClaim,
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
  beforeEach(() => {
    sim = new MockAttestationSim(createPrivateState(holder), registryKeys);
  });

  describe('buildMessage (frozen wire shape)', () => {
    it('returns exactly K=14 fields in the frozen order', () => {
      const claim = makeClaim({ values: [100n, 200n, 300n], present: [true, true, true] });
      const msg = pureCircuits.message(claim);
      expect(msg).toHaveLength(14);
      // [version, kind, policyDigest, requestBinding, holder, nonce, windowStart, windowEnd,
      //  p0, p1, p2, v0, v1, v2]
      expect(msg[0]).toBe(1n);
      expect(msg[1]).toBe(1n);
      expect(msg[6]).toBe(claim.windowStart);
      expect(msg[7]).toBe(claim.windowEnd);
      expect(msg.slice(8)).toEqual([1n, 1n, 1n, 100n, 200n, 300n]);
    });

    it('distinguishes absent (present all false) from a genuine 0 value', () => {
      const absent = makeClaim({ values: [0n, 0n, 0n], present: [false, false, false] });
      const presentZero = makeClaim({ values: [0n, 0n, 0n], present: [true, false, false] });
      expect(pureCircuits.message(absent)).not.toEqual(pureCircuits.message(presentZero));
      expect(pureCircuits.message(presentZero)[8]).toBe(1n);
    });
  });

  describe('verifyAttestation', () => {
    it('accepts 2-of-3 valid signatures (threshold N=2)', () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
    });

    it('accepts 3-of-3 valid signatures', () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
    });

    it('rejects 1-of-3 valid signatures', () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], null, null], randomBytes(32));
      expect(() => sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }))).toThrow(
        'Insufficient valid signatures',
      );
    });

    it('rejects a signature from an unregistered key', () => {
      const outsider = makeNotaryKey();
      const claim = makeClaim();
      const signed = signClaim(claim, [outsider, outsider, null], randomBytes(32));
      expect(() => sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }))).toThrow(
        'Insufficient valid signatures',
      );
    });

    it('rejects a tampered claim (value flipped)', () => {
      const claim = makeClaim({ values: [12345n, 0n, 0n], present: [true, false, false] });
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      const tampered = {
        claim: { ...signed.claim, values: [54321n, 0n, 0n] },
        commitRand: signed.commitRand,
      };
      expect(() =>
        sim.call('verifyAttestation', ps({ ...signed, ...tampered, holderSecret: holder })),
      ).toThrow('Insufficient valid signatures');
    });

    it('rejects an unsupported version', () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      const bad = { ...signed, claim: { ...signed.claim, version: 2n } };
      expect(() => sim.call('verifyAttestation', ps({ ...bad, holderSecret: holder }))).toThrow(
        'Unsupported claim version',
      );
    });

    it('rejects an unsupported kind', () => {
      const claim = makeClaim();
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      const bad = { ...signed, claim: { ...signed.claim, kind: 2n } };
      expect(() => sim.call('verifyAttestation', ps({ ...bad, holderSecret: holder }))).toThrow(
        'Unsupported kind',
      );
    });

    it('accepts a genuine-0 value when present flag set', () => {
      const claim = makeClaim({ values: [0n, 200n, 0n], present: [false, true, false] });
      const signed = signClaim(claim, [notaryKeys[0], notaryKeys[1], null], randomBytes(32));
      sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
    });
  });

  describe('nonce replay', () => {
    it('rejects a second use of the same nonce', () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      const psState = ps({ ...signed, holderSecret: holder });
      sim.call('verifyAttestation', psState);
      expect(() => sim.call('verifyAttestation', psState)).toThrow('Nonce replay');
    });
  });

  describe('freshness window', () => {
    const WINDOW = 30n * DAY; // 30-day window, matching the sealed witness value

    const attWith = (claim: A_Claim, overrides: Partial<PrivateState> = {}) => {
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      return ps({ ...signed, holderSecret: holder, ...overrides });
    };

    beforeEach(() => {
      sim = new MockAttestationSim(createPrivateState(holder), registryKeys, WINDOW);
    });

    it('accepts a window ending inside the freshness window', () => {
      sim.now = Number(nowSeconds());
      sim.call('verifyAttestation', attWith(makeClaim({ windowEnd: nowSeconds() - 60n })));
    });

    it('rejects a window ending in the future', () => {
      sim.now = Number(nowSeconds());
      expect(() =>
        sim.call('verifyAttestation', attWith(makeClaim({ windowEnd: nowSeconds() + DAY }))),
      ).toThrow('Window in the future');
    });

    it('rejects a window ending before the 30-day freshness window', () => {
      sim.now = Number(nowSeconds());
      expect(() =>
        sim.call('verifyAttestation', attWith(makeClaim({ windowEnd: nowSeconds() - 31n * DAY }))),
      ).toThrow('Window too old');
    });
  });

  describe('claim vault content', () => {
    it('stores holder and windowEnd (as the timestamp) under the claim id', () => {
      const claim = makeClaim();
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      const entry = sim.ledgerView().A_claimsVault.lookup(idOf(claim, signed.commitRand));
      expect(entry.holder).toBe(holderOf(holder));
      expect(entry.timestamp).toBe(claim.windowEnd);
    });
  });

  describe('openClaim', () => {
    const store = (claim = makeClaim()) => {
      const signed = signClaim(claim, notaryKeys, randomBytes(32));
      sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
      return signed;
    };

    it('re-hydrates the claim and reads multiple value slots', () => {
      const signed = store(makeClaim({ values: [111n, 222n, 333n], present: [true, true, true] }));
      const id = idOf(signed.claim, signed.commitRand);
      expect(() =>
        sim.call('openAndRead', ps({ ...signed, holderSecret: holder }), id, 111n, 222n),
      ).not.toThrow();
    });

    it('reads per-slot presence directly (present[i] is native)', () => {
      const signed = store(makeClaim({ values: [111n, 0n, 333n], present: [true, false, true] }));
      const id = idOf(signed.claim, signed.commitRand);
      expect(() =>
        sim.call('openAndReadPresence', ps({ ...signed, holderSecret: holder }), id, true, false),
      ).not.toThrow();
    });

    it('rejects a presence mismatch on a slot', () => {
      const signed = store(makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }));
      const id = idOf(signed.claim, signed.commitRand);
      expect(() =>
        sim.call('openAndReadPresence', ps({ ...signed, holderSecret: holder }), id, true, true),
      ).toThrow('present[1] mismatch');
    });

    it('accepts a claim where the required metric 0 is present', () => {
      const signed = store(makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }));
      const id = idOf(signed.claim, signed.commitRand);
      expect(() =>
        sim.call('openAndRequireMetric0', ps({ ...signed, holderSecret: holder }), id, 111n),
      ).not.toThrow();
    });

    it('rejects a claim where the required metric 0 is absent', () => {
      const signed = store(makeClaim({ values: [0n, 222n, 333n], present: [false, true, true] }));
      const id = idOf(signed.claim, signed.commitRand);
      expect(() =>
        sim.call('openAndRequireMetric0', ps({ ...signed, holderSecret: holder }), id, 0n),
      ).toThrow('metric 0 not present');
    });

    it('rejects a claim where the required metric 0 value mismatches', () => {
      const signed = store(makeClaim({ values: [111n, 0n, 0n], present: [true, false, false] }));
      const id = idOf(signed.claim, signed.commitRand);
      expect(() =>
        sim.call('openAndRequireMetric0', ps({ ...signed, holderSecret: holder }), id, 222n),
      ).toThrow('value[0] mismatch');
    });

    it('rejects an unknown claim', () => {
      const signed = store();
      const wrongId = randomBytes(32);
      expect(() =>
        sim.call('openAndRead', ps({ ...signed, holderSecret: holder }), wrongId, 12345n, 0n),
      ).toThrow('Unknown claim');
    });

    it('rejects a claim not bound to the caller', () => {
      const signed = store();
      const id = idOf(signed.claim, signed.commitRand);
      const otherHolder = randomBytes(32);
      expect(() =>
        sim.call('openAndRead', ps({ ...signed, holderSecret: otherHolder }), id, 12345n, 0n),
      ).toThrow('Claim not bound to caller');
    });

    it('rejects a claim that does not match the id', () => {
      const signed = store(makeClaim({ values: [12345n, 0n, 0n], present: [true, false, false] }));
      const id = idOf(signed.claim, signed.commitRand);
      const tampered = {
        ...signed,
        claim: { ...signed.claim, values: [54321n, 0n, 0n] },
      };
      expect(() =>
        sim.call('openAndRead', ps({ ...tampered, holderSecret: holder }), id, 54321n, 0n),
      ).toThrow('Claim does not match id');
    });

    it('is repeatable (no nullifier consumed)', () => {
      const signed = store(makeClaim({ values: [999n, 0n, 0n], present: [true, false, false] }));
      const id = idOf(signed.claim, signed.commitRand);
      const state = ps({ ...signed, holderSecret: holder });
      sim.call('openAndRead', state, id, 999n, 0n);
      expect(() => sim.call('openAndRead', state, id, 999n, 0n)).not.toThrow();
    });
  });
});
