// Reproductions for the audit finding that the signed message ignores the last
// byte of `nonce` and `evidenceHash`. `degradeToTransient` keeps 248 bits, so a
// change to byte 31 does not change the signed message, while the on-chain
// nullifier and vault id use the full bytes. One attestment can therefore be
// submitted many times with a fresh tail byte.
//
// These are `it.fails`: they pass while the defect exists and turn red once the
// wire layout binds all 32 bytes, which is the signal to convert them into
// normal rejection tests.
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

const signedOnce = () =>
  signClaim(makeClaim(), [notaryKeys[0], notaryKeys[1], null], randomBytes(32));

describe('audit repro: the signed message ignores the last byte of nonce/evidenceHash', () => {
  beforeEach(() => {
    sim = new MockAttestationSim(createPrivateState(holder), registryKeys);
  });

  it('control: rejects a nonce mutation the signature covers', () => {
    const signed = signedOnce();
    sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    const tampered = { ...signed.claim, nonce: Uint8Array.from(signed.claim.nonce) };
    tampered.nonce[0] ^= 0xff;
    expect(() =>
      sim.call('verifyAttestation', ps({ ...signed, claim: tampered, holderSecret: holder })),
    ).toThrow('Insufficient valid signatures');
  });

  it.fails('rejects the same signatures after mutating nonce[31]', () => {
    const signed = signedOnce();
    sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    const replayed = { ...signed.claim, nonce: Uint8Array.from(signed.claim.nonce) };
    replayed.nonce[31] ^= 0xff;
    expect(() =>
      sim.call('verifyAttestation', ps({ ...signed, claim: replayed, holderSecret: holder })),
    ).toThrow();
  });

  it.fails('rejects the same signatures after mutating nonce[31] and evidenceHash[31]', () => {
    const signed = signedOnce();
    sim.call('verifyAttestation', ps({ ...signed, holderSecret: holder }));
    const replayed = {
      ...signed.claim,
      nonce: Uint8Array.from(signed.claim.nonce),
      evidenceHash: Uint8Array.from(signed.claim.evidenceHash),
    };
    replayed.nonce[31] ^= 0xff;
    replayed.evidenceHash[31] ^= 0xff;
    expect(() =>
      sim.call('verifyAttestation', ps({ ...signed, claim: replayed, holderSecret: holder })),
    ).toThrow();
  });

  it.fails('buildMessage distinguishes a change to nonce[31]', () => {
    const claim = makeClaim();
    const flipped = { ...claim, nonce: Uint8Array.from(claim.nonce) };
    flipped.nonce[31] ^= 0xff;
    expect(pureCircuits.message(flipped)).not.toEqual(pureCircuits.message(claim));
  });

  it.fails('buildMessage distinguishes a change to evidenceHash[31]', () => {
    const claim = makeClaim();
    const flipped = { ...claim, evidenceHash: Uint8Array.from(claim.evidenceHash) };
    flipped.evidenceHash[31] ^= 0xff;
    expect(pureCircuits.message(flipped)).not.toEqual(pureCircuits.message(claim));
  });
});
