// Regression tests for the audit finding that the signed message ignored the
// last byte of `nonce` and `evidenceHash` (#66). `degradeToTransient` kept 248
// bits, so a change to byte 31 did not change the signed message, while the
// on-chain nullifier and vault id use the full bytes: one attestment could be
// submitted many times with a fresh tail byte. `buildMessage` now signs each
// 32-byte field as two 16-byte halves.
import { randomBytes } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import { makeClaim, makeNotaryKey, signClaim } from './helpers/fixtures.js';
import { createPrivateState, type PrivateState } from './helpers/private-state.js';
import { MockAttestationSim } from './helpers/sim.js';

const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;
const registryKeys = notaryKeys.map((k) => k.pk);
const holder = randomBytes(32);

let sim: MockAttestationSim;

const ps = (overrides: Partial<PrivateState> = {}): PrivateState => ({
  ...createPrivateState(holder),
  ...overrides,
});

// A copy of `bytes` with byte `i` inverted.
const flip = (bytes: Uint8Array, i: number): Uint8Array => {
  const copy = Uint8Array.from(bytes);
  copy[i] = (copy[i] ?? 0) ^ 0xff;
  return copy;
};

const signedOnce = () =>
  signClaim(makeClaim(), [notaryKeys[0], notaryKeys[1], null], randomBytes(32));

describe('replay: the signed message binds every byte of nonce/evidenceHash', () => {
  beforeEach(() => {
    sim = new MockAttestationSim(createPrivateState(holder), registryKeys);
  });

  it('control: rejects a nonce mutation the signature covers', () => {
    const signed = signedOnce();
    sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    const tampered = { ...signed.claim, nonce: flip(signed.claim.nonce, 0) };
    expect(() =>
      sim.call('verifyAttestation', ps({ ...signed, claim: tampered, holderSecret: holder })),
    ).toThrow('Insufficient valid signatures');
  });

  it('rejects the same signatures after mutating nonce[31]', () => {
    const signed = signedOnce();
    sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    const replayed = { ...signed.claim, nonce: flip(signed.claim.nonce, 31) };
    expect(() =>
      sim.call('verifyAttestation', ps({ ...signed, claim: replayed, holderSecret: holder })),
    ).toThrow('Insufficient valid signatures');
  });

  it('rejects the same signatures after mutating evidenceHash[31]', () => {
    const signed = signedOnce();
    sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    const replayed = { ...signed.claim, evidenceHash: flip(signed.claim.evidenceHash, 31) };
    expect(() =>
      sim.call('verifyAttestation', ps({ ...signed, claim: replayed, holderSecret: holder })),
    ).toThrow('Insufficient valid signatures');
  });

  it('rejects the same signatures after mutating nonce[31] and evidenceHash[31]', () => {
    const signed = signedOnce();
    sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    const replayed = {
      ...signed.claim,
      nonce: flip(signed.claim.nonce, 31),
      evidenceHash: flip(signed.claim.evidenceHash, 31),
    };
    expect(() =>
      sim.call('verifyAttestation', ps({ ...signed, claim: replayed, holderSecret: holder })),
    ).toThrow('Insufficient valid signatures');
  });

  it('buildMessage distinguishes a change to nonce[31]', () => {
    const claim = makeClaim();
    const flipped = { ...claim, nonce: flip(claim.nonce, 31) };
    expect(pureCircuits.message(flipped)).not.toEqual(pureCircuits.message(claim));
  });

  it('buildMessage distinguishes a change to evidenceHash[31]', () => {
    const claim = makeClaim();
    const flipped = { ...claim, evidenceHash: flip(claim.evidenceHash, 31) };
    expect(pureCircuits.message(flipped)).not.toEqual(pureCircuits.message(claim));
  });
});
