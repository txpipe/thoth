// Cross-seam acceptance: two test-key witnesses observe one request, two
// zkFetch attestors sign the derived claim with real Jubjub keys, the client
// collects the threshold set, and the contract simulator accepts it. Every
// signed binding is then mutated under the same signatures, each on a fresh
// ledger so a rejection can only come from the signature check, never from a
// nullifier the honest submission left behind.
import { randomBytes } from 'node:crypto';
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { KeyPair } from '@thoth/attestor';
import { descriptorOf } from '@thoth/attestor';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import type { Claim } from '@thoth/core/claim';
import { type ZkFetchPolicy, zkFetchPolicyHashOf, zkFetchSubjectHashOf } from '@thoth/zk-tls';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { type ZkFetchRequest, zkFetchClient } from '@thoth/zk-tls/client';
import { beforeAll, describe, expect, it } from 'vitest';
import { testWitness } from '../../zk-tls/test/helpers/witness.js';
import type { A_Claim } from '../artifacts/mock_attestation/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation/contract/index.js';
import {
  APP_ID,
  DUMMY_SIGNATURE,
  flip,
  idOf,
  makeNotaryKey,
  POLICY_B,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationSim } from './helpers/sim.js';

/** A Jubjub key pair whose signer signs the flat message the registry verifies. */
const jubjubKeyPair = (): KeyPair<JubjubPoint, JubjubSchnorrSignature> => {
  const { sk, pk } = makeNotaryKey();
  return { publicKey: pk, signer: { sign: (message) => signMessage(sk, message).signature } };
};

const VALUE_SLOTS = 3;
const OBSERVED_AT = 1_786_122_944;
const WINDOW_END = BigInt(OBSERVED_AT + 60);

// Slot 0 is measured; slot 1 is optional and never disclosed, so it is signed
// unpresent; slot 2 is outside the policy.
const DISCLOSURE_RULES: Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'> = {
  responseMatches: [{ type: 'regex', value: '(?<data>.*)' }],
  responseRedactions: [],
};
const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [
    { slot: 0, name: 'stars', parse: 'int' },
    { slot: 1, name: 'forks', parse: 'int', optional: true },
  ],
  ...DISCLOSURE_RULES,
};
const request: ZkFetchRequest = { url: 'https://api.github.com/repos/x', method: 'GET' };

// Each operator runs a test-key witness and the attestor that trusts it.
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
// Registry slot 2 is pinned to an operator the app does not query.
const registryKeys = [...attestors.map((attestor) => attestor.publicKey), makeNotaryKey().pk];

const holderSecret = randomBytes(32);

type Submission = { claim: A_Claim; signatures: JubjubSchnorrSignature[]; commitRand: Uint8Array };

// Collect the honest threshold set through the zkFetch client and lay its
// signatures out at their registry slots, the dummy filling the unqueried one.
const collectSubmission = async (): Promise<Submission> => {
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
              timestampS: OBSERVED_AT,
              parameters: {
                url: proved.url,
                method: proved.method ?? 'GET',
                body: '',
                ...DISCLOSURE_RULES,
              },
              context: proved.context,
            }),
        },
      ]),
    ),
  });
  const { claim, collected } = await client.collect(request, {
    holder: pureCircuits.holderCommitment(holderSecret),
    windowStart: BigInt(OBSERVED_AT),
    windowEnd: WINDOW_END,
    expiresAt: Date.now() + 60_000,
    threshold: 2,
    attestorTimeoutMs: 5_000,
  });
  const signatures = registryKeys.map(
    (_, slot) =>
      collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ??
      DUMMY_SIGNATURE,
  );
  return { claim: toContractClaim(claim), signatures, commitRand: randomBytes(32) };
};

const toContractClaim = (claim: Claim<number>): A_Claim => ({
  ...claim,
  present: [...claim.present],
  values: [...claim.values],
});

// A fresh ledger that seals the policy the attestors enforced, with its block
// time at the end of the observation window.
const freshLedger = async (): Promise<MockAttestationSim> => {
  const sim = await MockAttestationSim.create(createPrivateState(holderSecret), registryKeys, {
    policyHashes: [zkFetchPolicyHashOf(policy), POLICY_B],
  });
  sim.now = Number(WINDOW_END);
  return sim;
};

const submit = (sim: MockAttestationSim, submission: Submission, secret = holderSecret) =>
  sim.call('verifyAttestation', { ...submission, holderSecret: secret });

describe('cross-seam acceptance', () => {
  let honest: Submission;

  beforeAll(async () => {
    honest = await collectSubmission();
  });

  it('collects a claim carrying every binding the contract checks', () => {
    expect(honest.claim).toMatchObject({
      appId: APP_ID,
      policyHash: zkFetchPolicyHashOf(policy),
      subjectHash: zkFetchSubjectHashOf({ method: 'GET', url: request.url, body: '' }),
      holder: pureCircuits.holderCommitment(holderSecret),
      windowStart: BigInt(OBSERVED_AT),
      windowEnd: WINDOW_END,
      present: [true, false, false],
      values: [42n, 0n, 0n],
    });
    expect(honest.signatures[2]).toBe(DUMMY_SIGNATURE);
  });

  it('accepts the honest claim end to end', async () => {
    const sim = await freshLedger();
    await submit(sim, honest);
    expect(sim.ledgerView().A_claimsVault.member(idOf(honest.claim, honest.commitRand))).toBe(true);
  });

  const otherSecret = randomBytes(32);
  it.each([
    { name: 'a value', mutate: (c: A_Claim) => ({ ...c, values: [43n, 0n, 0n] }) },
    { name: 'the presence mask', mutate: (c: A_Claim) => ({ ...c, present: [true, true, false] }) },
    // POLICY_B is sealed too, so only the signatures can reject it.
    { name: 'the policy', mutate: (c: A_Claim) => ({ ...c, policyHash: POLICY_B }) },
    { name: 'the app id', mutate: (c: A_Claim) => ({ ...c, appId: flip(c.appId, 0) }) },
    {
      name: 'the subject',
      mutate: (c: A_Claim) => ({ ...c, subjectHash: flip(c.subjectHash, 0) }),
    },
    {
      name: 'the window start',
      mutate: (c: A_Claim) => ({ ...c, windowStart: c.windowStart + 1n }),
    },
    { name: 'the window end', mutate: (c: A_Claim) => ({ ...c, windowEnd: c.windowEnd + 1n }) },
    // The new caller knows the secret behind the substituted holder.
    {
      name: 'the holder',
      mutate: (c: A_Claim) => ({ ...c, holder: pureCircuits.holderCommitment(otherSecret) }),
      secret: otherSecret,
    },
  ])('rejects the signatures over a claim with $name mutated', async ({ mutate, secret }) => {
    const sim = await freshLedger();
    await expect(submit(sim, { ...honest, claim: mutate(honest.claim) }, secret)).rejects.toThrow(
      'Insufficient valid signatures',
    );
  });
});
