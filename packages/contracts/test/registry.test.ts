// Registry-management tests: the deploy-time `keysDistinct` check (duplicate
// and empty-slot pinning) and claim verification against a registry with empty
// slots. The init guards (compile-time exposure, runtime double-init) live in
// sealed-init.test.ts.
import { randomBytes } from 'node:crypto';
import {
  CompactTypeField,
  CompactTypeVector,
  jubjubSchnorrVerify,
} from '@midnight-ntwrk/compact-runtime';
import { describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  DEFAULT_HOLDER_SECRET,
  DUMMY_SIGNATURE,
  idOf,
  makeClaim,
  makeNotaryKey,
  signClaim,
} from './helpers/fixtures.js';
import { createPrivateState, type PrivateState } from './helpers/private-state.js';
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

  it('still deploys with empty slots', async () => {
    await MockAttestationSim.create(createPrivateState(holder), [a.pk, b.pk, empty]);
  });

  it('accepts a threshold claim with an empty slot', async () => {
    const sim = await MockAttestationSim.create(createPrivateState(holder), [a.pk, b.pk, empty]);
    const claim = makeClaim();
    const signed = signClaim(claim, [a, b, null], randomBytes(32));
    await sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    expect(sim.ledgerView().A_claimsVault.member(idOf(claim, signed.commitRand))).toBe(true);
  });

  it('does not count a signature forged for the empty slot', async () => {
    const sim = await MockAttestationSim.create(createPrivateState(holder), [a.pk, b.pk, empty]);
    const claim = makeClaim();
    const msg = pureCircuits.message(claim);
    // The dummy is a valid Schnorr signature for the identity point (the
    // empty key), so only `slotValid`'s empty-slot skip keeps it from
    // counting; without that skip this claim would pass.
    expect(
      jubjubSchnorrVerify(
        new CompactTypeVector(msg.length, CompactTypeField),
        msg,
        empty,
        DUMMY_SIGNATURE,
      ),
    ).toBe(true);
    const signed = signClaim(claim, [a, null, null], randomBytes(32));
    await expect(
      sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder })),
    ).rejects.toThrow('Insufficient valid signatures');
  });
});
