// A threshold zkFetch attestation, collected through the zk-tls client from two
// operators — each with its own test-key witness and an in-process attestor
// signing with a real Jubjub-Schnorr key — is accepted by the contract simulator.
import { randomBytes } from 'node:crypto';
import { descriptorOf } from '@thoth/attestor';
import { type AttestorTransport, buildTrustedSet } from '@thoth/client';
import type { FlatMessage } from '@thoth/core/claim';
import type { ZkFetchDefinition } from '@thoth/zk-tls';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { type ZkFetchOperator, zkFetchClient } from '@thoth/zk-tls/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type TestWitness, testWitness } from '../../zk-tls/test/helpers/witness.js';
import { DUMMY_SIGNATURE, holderCommitment, idOf, makeNotaryKey } from './helpers/fixtures.js';
import { createPrivateState, type SchnorrSignature } from './helpers/private-state.js';
import { type JubjubPoint, signMessage, verifyMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

const OBSERVED_AT = 1_786_000_000;
const witnesses = [
  testWitness(`0x${'11'.repeat(32)}`),
  testWitness(`0x${'22'.repeat(32)}`),
] as const;
const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;

const pairs = [
  [witnesses[0], notaryKeys[0]],
  [witnesses[1], notaryKeys[1]],
] as const;
const attestors = pairs.map(([witness, key], i) =>
  zkFetchAttestor<JubjubPoint, SchnorrSignature>({
    id: `attestor-${i}`,
    keyPair: {
      publicKey: key.pk,
      signer: { sign: (message: FlatMessage) => signMessage(key.sk, message).signature },
    },
    registryIndex: i,
    witnessAddress: witness.address,
  }),
);
const transport: AttestorTransport<ZkFetchDefinition, JubjubPoint, SchnorrSignature> = {
  request: (descriptor, input) => {
    const attestor = attestors.find((a) => a.id === descriptor.id);
    if (!attestor) {
      throw new Error(`unknown attestor ${descriptor.id}`);
    }
    return attestor.attest(input as Parameters<typeof attestor.attest>[0]);
  },
};

describe('zkFetch attestation in the simulator', () => {
  // The client checks the intent window against the wall clock; pin it.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(OBSERVED_AT * 1000);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('accepts a threshold attestation from two independent witnesses', async () => {
    const operator = (witness: TestWitness): ZkFetchOperator => ({
      witnessAddress: witness.address,
      prover: {
        prove: (request) =>
          witness.sign({
            values: { balance: '0' },
            timestampS: OBSERVED_AT,
            parameters: { url: request.url, method: request.method ?? 'GET', body: '' },
            context: request.context,
          }),
      },
    });
    const client = zkFetchClient.init({
      trusted: buildTrustedSet(attestors.map(descriptorOf)),
      transport,
      policy: {
        allowedHosts: ['api.example.com'],
        maxWindowSeconds: 120,
        slots: [{ slot: 0, name: 'balance', parse: 'int' }],
      },
      valueSlots: 3,
      threshold: 2,
      verifier: { verify: verifyMessage },
      operators: { 'attestor-0': operator(witnesses[0]), 'attestor-1': operator(witnesses[1]) },
    });
    const holderSecret = randomBytes(32);
    const { claim, collected } = await client.attest(
      { url: 'https://api.example.com/v1/account' },
      {
        holder: holderCommitment(holderSecret),
        windowStart: BigInt(OBSERVED_AT - 60),
        windowEnd: BigInt(OBSERVED_AT + 60),
      },
    );

    const commitRand = randomBytes(32);
    const contractClaim = { ...claim, present: [...claim.present], values: [...claim.values] };
    const sim = new MockAttestationSim(
      createPrivateState(holderSecret),
      notaryKeys.map((k) => k.pk),
      { policyDigest: claim.policyDigest },
    );
    sim.now = OBSERVED_AT;
    sim.call('verifyAttestation', {
      claim: contractClaim,
      // Positional: slot i verifies against key i; the unanswered slot never verifies.
      signatures: notaryKeys.map(
        (_, slot) =>
          collected.find((c) => c.registryIndex === slot)?.attestation.signature ?? DUMMY_SIGNATURE,
      ),
      commitRand,
      holderSecret,
    });

    expect(claim.present).toEqual([true, false, false]);
    expect(sim.ledgerView().A_claimsVault.member(idOf(contractClaim, commitRand))).toBe(true);
  });
});
