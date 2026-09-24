// A single-witness zkFetch attestation in the common claim layout, collected
// through the zk-tls client from two in-process attestors that sign with real
// Jubjub-Schnorr keys, is accepted by the contract simulator.
import { randomBytes } from 'node:crypto';
import { descriptorOf } from '@thoth/attestor';
import { type AttestorTransport, buildTrustedSet } from '@thoth/client';
import type { FlatMessage } from '@thoth/core/claim';
import type { ZkFetchDefinition } from '@thoth/zk-tls';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { zkFetchClient } from '@thoth/zk-tls/client';
import { describe, expect, it } from 'vitest';
import { testWitness } from '../../zk-tls/test/helpers/witness.js';
import { idOf, makeNotaryKey } from './helpers/fixtures.js';
import { createPrivateState, type SchnorrSignature } from './helpers/private-state.js';
import { type JubjubPoint, signMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

const OBSERVED_AT = 1_786_000_000;
const witness = testWitness(`0x${'11'.repeat(32)}`);
const notaryKeys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()] as const;

const attestors = notaryKeys.slice(0, 2).map((key, i) =>
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
  it('accepts a single-witness attestation signed by N attestors', async () => {
    const client = zkFetchClient.init({
      trusted: buildTrustedSet(attestors.map(descriptorOf)),
      transport,
      policy: {
        allowedHosts: ['api.example.com'],
        maxWindowSeconds: 120,
        slots: [{ slot: 0, name: 'balance', parse: 'int' }],
      },
      valueSlots: 3,
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
    const proof = await client.proveReq(
      { url: 'https://api.example.com/v1/account' },
      {
        holder: randomBytes(32),
        windowStart: BigInt(OBSERVED_AT - 60),
        windowEnd: BigInt(OBSERVED_AT + 60),
      },
    );
    const { claim, collected } = await proof.attest();

    const holderSecret = randomBytes(32);
    const commitRand = randomBytes(32);
    const contractClaim = { ...claim, present: [...claim.present], values: [...claim.values] };
    const sim = new MockAttestationSim(
      createPrivateState(holderSecret),
      notaryKeys.map((k) => k.pk),
    );
    sim.call('verifyAttestation', {
      claim: contractClaim,
      signatures: [
        ...collected.map((c) => c.attestation.signature),
        // Empty third slot — never verifies.
        { announcement: { x: 0n, y: 1n }, response: 0n },
      ],
      commitRand,
      holderSecret,
    });

    expect(claim.present).toEqual([true, false, false]);
    expect(sim.ledgerView().A_claimsVault.member(idOf(contractClaim, commitRand))).toBe(true);
  });
});
