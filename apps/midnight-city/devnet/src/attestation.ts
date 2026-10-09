// One honest 2-of-3 attestation, built the way
// `packages/contracts/test/acceptance.test.ts` builds it: two test-key
// witnesses observe one request, two zkFetch attestors sign the derived claim
// with Jubjub keys, and the client collects the threshold set. Registry slot 2
// is pinned to an operator the app does not query, so its signature is the
// dummy. The window is anchored to the wall clock, not a fixture time, because
// the devnet checks it against real block time. Signing and the message
// encoding run on Thoth's own packages (compact-runtime 0.19); only the holder
// commitment comes from the deployed contract's circuits.
import { randomBytes } from 'node:crypto';
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import { descriptorOf, type KeyPair } from '@thoth/attestor';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { type ZkFetchPolicy, zkFetchPolicyHashOf } from '@thoth/zk-tls';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { type ZkFetchRequest, zkFetchClient } from '@thoth/zk-tls/client';
import {
  APP_ID,
  DUMMY_SIGNATURE,
  makeNotaryKey,
  POLICY_B,
} from '../../../../packages/contracts/test/helpers/fixtures.js';
import { signMessage } from '../../../../packages/contracts/test/helpers/sign.js';
import { testWitness } from '../../../../packages/zk-tls/test/helpers/witness.js';
import type { A_Claim } from '../artifacts/mock_attestation/contract/index.js';

/** What the contract's `verifyAttestation` reads from private state. */
export interface Submission {
  readonly claim: A_Claim;
  readonly signatures: JubjubSchnorrSignature[];
  readonly commitRand: Uint8Array;
  readonly holderSecret: Uint8Array;
}

/** What the contract seals at deploy and the submission that satisfies it. */
export interface Attestation {
  readonly registryKeys: JubjubPoint[];
  readonly policyHashes: Uint8Array[];
  readonly submission: Submission;
}

const VALUE_SLOTS = 3;

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [
    { slot: 0, name: 'stars', parse: 'int' },
    { slot: 1, name: 'forks', parse: 'int', optional: true },
  ],
};
const request: ZkFetchRequest = { url: 'https://api.github.com/repos/x', method: 'GET' };

/** A Jubjub key pair whose signer signs the flat message the registry verifies. */
const jubjubKeyPair = (): KeyPair<JubjubPoint, JubjubSchnorrSignature> => {
  const { sk, pk } = makeNotaryKey();
  return { publicKey: pk, signer: { sign: (message) => signMessage(sk, message).signature } };
};

/**
 * Collect one honest attestation observed `observedAt` seconds since the epoch.
 *
 * @param observedAt - observation time, Unix seconds; the window opens there.
 * @param holderCommitment - the deployed contract's holder-commitment circuit.
 * @returns the deploy-time seals and the submission.
 */
export const collectAttestation = async (
  observedAt: number,
  holderCommitment: (secret: Uint8Array) => Uint8Array,
): Promise<Attestation> => {
  const operators = ['33', '44'].map((byte, i) => {
    const witness = testWitness(`0x${byte.repeat(32)}`);
    const attestor = zkFetchAttestor({
      id: `attestor-${i}`,
      keyPair: jubjubKeyPair(),
      witnessAddress: witness.address,
    });
    return { witness, attestor };
  });
  const attestors = operators.map(({ attestor }) => attestor);
  const registryKeys = [...attestors.map((attestor) => attestor.publicKey), makeNotaryKey().pk];
  const holderSecret = randomBytes(32);

  const client = zkFetchClient.init({
    trusted: buildTrustedSet({
      registrySize: registryKeys.length,
      attestors: attestors.map((attestor, registryIndex) => ({
        attestor: descriptorOf(attestor),
        registryIndex,
      })),
    }),
    verifier: jubjubVerifier,
    transport: {
      request: (descriptor, input) => {
        const attestor = attestors.find((candidate) => candidate.id === descriptor.id);
        if (!attestor) {
          throw new Error(`transport: unknown attestor ${descriptor.id}`);
        }
        return attestor.attest(input as Parameters<typeof attestor.attest>[0]);
      },
    },
    policy,
    appId: APP_ID,
    valueSlots: VALUE_SLOTS,
    provers: Object.fromEntries(
      operators.map(({ witness, attestor }) => [
        attestor.id,
        {
          prove: (proved: ZkFetchRequest) =>
            witness.sign({
              values: { stars: '42' },
              timestampS: observedAt,
              parameters: { url: proved.url, method: proved.method ?? 'GET', body: '' },
              context: proved.context,
            }),
        },
      ]),
    ),
  });
  const { claim, collected } = await client.collect(request, {
    holder: holderCommitment(holderSecret),
    windowStart: BigInt(observedAt),
    windowEnd: BigInt(observedAt + 60),
    expiresAt: Date.now() + 60_000,
    threshold: 2,
    attestorTimeoutMs: 5_000,
  });
  const signatures = registryKeys.map(
    (_, slot) =>
      collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ??
      DUMMY_SIGNATURE,
  );
  return {
    registryKeys,
    policyHashes: [zkFetchPolicyHashOf(policy), POLICY_B],
    submission: {
      claim: { ...claim, present: [...claim.present], values: [...claim.values] },
      signatures,
      commitRand: randomBytes(32),
      holderSecret,
    },
  };
};
