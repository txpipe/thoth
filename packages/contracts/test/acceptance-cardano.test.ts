// Cross-seam acceptance: two cardano attestors read the same output event and
// sign the derived claim with real Jubjub keys, the client collects the
// threshold set, and the contract simulator accepts it. Every signed binding
// is then mutated under the same signatures, each on a fresh ledger so the
// rejection can only come from the signature check.
import { randomBytes } from 'node:crypto';
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { KeyPair } from '@thoth/attestor';
import { descriptorOf } from '@thoth/attestor';
import {
  type CardanoLocator,
  type CardanoObservation,
  type CardanoPolicy,
  cardanoOutputSaltOf,
  cardanoOutputSubjectHashOf,
  cardanoPolicyHashOf,
} from '@thoth/cardano';
import { cardanoAttestor } from '@thoth/cardano/attestor';
import { type CardanoAttestationInput, cardanoClient } from '@thoth/cardano/client';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import type { Claim } from '@thoth/core/claim';
import { toContractClaim } from '@thoth/core/claim';
import { beforeAll, describe, expect, it } from 'vitest';
import { type B_Claim, pureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import {
  APP_ID,
  bytesIdOf,
  DUMMY_SIGNATURE,
  flip,
  makeNotaryKey,
  splitHalves,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationBytesSim } from './helpers/sim.js';

const TEST_ADDRESS = `addr_test1${'q'.repeat(53)}`;
const TX_HASH = 'cd'.repeat(32);
const BLOCK_HASH = 'ab'.repeat(32);

// Three numeric facts and one byte fact, sized for the V=3, B=2, K=24 mock.
const policy: CardanoPolicy = {
  kind: 'output',
  network: 'preview',
  networkMagic: 2,
  confirmationDepth: 3,
  address: TEST_ADDRESS,
  slots: [
    { slot: 0, name: 'blockTime' },
    { slot: 1, name: 'blockNumber' },
    { slot: 2, name: 'lovelace' },
    { slot: 3, name: 'txHash' },
  ],
};

// A second sealed policy, so a mutated policy hash can only fail the
// signature check, like the zkFetch acceptance test's POLICY_B.
const otherPolicy: CardanoPolicy = { ...policy, confirmationDepth: 1 };

const locator: CardanoLocator = { txHash: TX_HASH, outputIndex: 0 };

/** The event both the client and every attestor read. */
const observation: CardanoObservation = {
  networkMagic: 2,
  tipBlockNumber: 1003,
  block: { hash: BLOCK_HASH, slot: 123_456, blockNumber: 1000, time: 1_700_000_000 },
  output: {
    txHash: TX_HASH,
    outputIndex: 0,
    address: TEST_ADDRESS,
    lovelace: 5_000_000n,
    assets: [],
  },
};

/** A Jubjub key pair whose signer signs the flat message the registry verifies. */
const jubjubKeyPair = (): KeyPair<JubjubPoint, JubjubSchnorrSignature> => {
  const { sk, pk } = makeNotaryKey();
  return { publicKey: pk, signer: { sign: (message) => signMessage(sk, message).signature } };
};

// Each operator runs its own attestor over its own read of the same event.
const attestors = [0, 1].map((index) =>
  cardanoAttestor({
    id: `cardano-attestor-${index}`,
    keyPair: jubjubKeyPair(),
    read: async () => observation,
  }),
);
// Registry slot 2 is pinned to an operator the app does not query.
const registryKeys = [...attestors.map((attestor) => attestor.publicKey), makeNotaryKey().pk];

const holderSecret = randomBytes(32);

type Submission = { claim: B_Claim; signatures: JubjubSchnorrSignature[]; commitRand: Uint8Array };

/** The claim the honest threshold set signed. */
let honestClaim: Claim<number, number>;

const clientWith = () =>
  cardanoClient.init({
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
        return attestor.attest(input as CardanoAttestationInput);
      },
    },
    policy,
    appId: APP_ID,
    valueSlots: 3,
    byteSlots: 1,
    read: async () => observation,
  });

// Collect the honest threshold set through the cardano client and lay its
// signatures out at their registry slots, the dummy filling the unqueried one.
const collectSubmission = async (): Promise<Submission> => {
  const client = clientWith();
  const { claim, collected } = await client.collect(locator, {
    holder: pureCircuits.holderCommitment(holderSecret),
    expiresAt: Date.now() + 60_000,
    threshold: 2,
    attestorTimeoutMs: 5_000,
  });
  honestClaim = claim;
  const signatures = registryKeys.map(
    (_, slot) =>
      collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ??
      DUMMY_SIGNATURE,
  );
  return { claim: toContractClaim(claim), signatures, commitRand: randomBytes(32) };
};

// A fresh ledger that seals the policy the attestors enforced, with its block
// time inside the claim's window.
const freshLedger = async (): Promise<MockAttestationBytesSim> => {
  const sim = await MockAttestationBytesSim.create(
    createPrivateState<B_Claim>(holderSecret),
    registryKeys,
    { policyHashes: [cardanoPolicyHashOf(policy), cardanoPolicyHashOf(otherPolicy)] },
  );
  sim.now = Number(honestClaim.windowStart);
  return sim;
};

const submit = (sim: MockAttestationBytesSim, submission: Submission, secret = holderSecret) =>
  sim.call('verifyAttestation', { ...submission, holderSecret: secret });

describe('cardano cross-seam acceptance', () => {
  let honest: Submission;

  beforeAll(async () => {
    honest = await collectSubmission();
  });

  it('collects a claim carrying every binding the contract checks', () => {
    expect(honest.claim).toMatchObject({
      appId: APP_ID,
      policyHash: cardanoPolicyHashOf(policy),
      subjectHash: cardanoOutputSubjectHashOf({
        networkMagic: 2,
        txHash: TX_HASH,
        outputIndex: 0,
        blockHash: BLOCK_HASH,
      }),
      holder: pureCircuits.holderCommitment(holderSecret),
      windowStart: 1_700_000_000n,
      windowEnd: 1_700_000_000n,
      present: [true, true, true],
      bytePresent: [true, true],
      values: [1_700_000_000n, 1000n, 5_000_000n],
      byteHalves: splitHalves(Uint8Array.from(Buffer.from(TX_HASH, 'hex'))),
    });
    expect(honest.signatures[2]).toBe(DUMMY_SIGNATURE);
  });

  it('has every attestor derive the same event salt', () => {
    expect(Buffer.from(honest.claim.salt).toString('hex')).toBe(
      Buffer.from(cardanoOutputSaltOf(2, TX_HASH, 0)).toString('hex'),
    );
  });

  it('accepts the honest claim end to end', async () => {
    const sim = await freshLedger();
    await submit(sim, honest);
    expect(sim.ledgerView().B_claimsVault.member(bytesIdOf(honest.claim, honest.commitRand))).toBe(
      true,
    );
  });

  const otherSecret = randomBytes(32);

  it.each([
    {
      name: 'a value',
      mutate: (c: B_Claim) => ({ ...c, values: [1_700_000_001n, 1000n, 5_000_000n] }),
    },
    {
      name: 'the presence mask',
      mutate: (c: B_Claim) => ({ ...c, present: [true, false, true] }),
    },
    {
      name: 'the byte presence mask',
      mutate: (c: B_Claim) => ({ ...c, bytePresent: [true, false] }),
    },
    {
      name: 'the byte value',
      mutate: (c: B_Claim) => ({
        ...c,
        byteHalves: [
          flip(c.byteHalves[0] ?? new Uint8Array(16), 0),
          c.byteHalves[1] ?? new Uint8Array(16),
        ],
      }),
    },
    // The other policy is sealed too, so only the signatures can reject it.
    {
      name: 'the policy',
      mutate: (c: B_Claim) => ({ ...c, policyHash: cardanoPolicyHashOf(otherPolicy) }),
    },
    { name: 'the app id', mutate: (c: B_Claim) => ({ ...c, appId: flip(c.appId, 0) }) },
    {
      name: 'the subject',
      mutate: (c: B_Claim) => ({ ...c, subjectHash: flip(c.subjectHash, 0) }),
    },
    {
      name: 'the window start',
      mutate: (c: B_Claim) => ({ ...c, windowStart: c.windowStart + 1n }),
    },
    { name: 'the window end', mutate: (c: B_Claim) => ({ ...c, windowEnd: c.windowEnd + 1n }) },
    { name: 'the salt', mutate: (c: B_Claim) => ({ ...c, salt: flip(c.salt, 0) }) },
    // The new caller knows the secret behind the substituted holder.
    {
      name: 'the holder',
      mutate: (c: B_Claim) => ({ ...c, holder: pureCircuits.holderCommitment(otherSecret) }),
      secret: otherSecret,
    },
  ])('rejects the signatures over a claim with $name mutated', async ({ mutate, secret }) => {
    const sim = await freshLedger();
    await expect(submit(sim, { ...honest, claim: mutate(honest.claim) }, secret)).rejects.toThrow(
      'Insufficient valid signatures',
    );
  });
});
