// Cross-seam acceptance: two test-key witnesses observe one request, two
// zkFetch attestors sign the derived claim with real Jubjub keys, the client
// collects the threshold set, and the contract simulator accepts it. The policy
// carries one byte value slot (an identifier) alongside its numeric slots, so
// the path from a disclosed string to a signed 32-byte value is covered here.
// Every signed binding is then mutated under the same signatures, each on a
// fresh ledger so a rejection can only come from the signature check, never from
// a nullifier the honest submission left behind.
import { randomBytes } from 'node:crypto';
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { KeyPair } from '@thoth/attestor';
import { descriptorOf } from '@thoth/attestor';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { type Claim, toContractClaim } from '@thoth/core/claim';
import {
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchClaimContextDigestOf,
  zkFetchPolicyHashOf,
  zkFetchSubjectHashOf,
} from '@thoth/zk-tls';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { type ZkFetchProver, type ZkFetchRequest, zkFetchClient } from '@thoth/zk-tls/client';
import { beforeAll, describe, expect, it } from 'vitest';
import { DISCLOSURE_RULES } from '../../zk-tls/test/helpers/helper.js';
import { testWitness } from '../../zk-tls/test/helpers/witness.js';
import type { B_Claim } from '../artifacts/mock_attestation_bytes/contract/index.js';
import { pureCircuits } from '../artifacts/mock_attestation_bytes/contract/index.js';
import {
  APP_ID,
  bytesIdOf,
  DUMMY_SIGNATURE,
  flip,
  makeNotaryKey,
  POLICY_B,
  padded32,
  splitHalves,
} from './helpers/fixtures.js';
import { createPrivateState } from './helpers/private-state.js';
import { signMessage } from './helpers/sign.js';
import { MockAttestationBytesSim } from './helpers/sim.js';

/** A Jubjub key pair whose signer signs the flat message the registry verifies. */
const jubjubKeyPair = (): KeyPair<JubjubPoint, JubjubSchnorrSignature> => {
  const { sk, pk } = makeNotaryKey();
  return { publicKey: pk, signer: { sign: (message) => signMessage(sk, message).signature } };
};

const VALUE_SLOTS = 3;
const BYTE_SLOTS = 1;
const OBSERVED_AT = 1_786_122_944;
const WINDOW_END = BigInt(OBSERVED_AT + 60);
const OWNER = 'alice';

// Numeric slots 0..2, then one byte value slot at index 3. Slot 1 is optional
// and never disclosed, so it is signed unpresent; slot 2 is outside the policy.
const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [
    { slot: 0, name: 'stars', parse: 'int' },
    { slot: 1, name: 'forks', parse: 'int', optional: true },
    { slot: 3, name: 'owner', parse: 'bytes' },
  ],
  bodyPolicy: 'ignored',
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

type Submission = { claim: B_Claim; signatures: JubjubSchnorrSignature[]; commitRand: Uint8Array };

/** The evidence each attestor's witness signed for the honest holder, by attestor id. */
const honestEvidence: Record<string, ZkFetchEvidence> = {};
/** The claim the honest threshold set signed. */
let honestClaim: Claim<number, number>;

// The zkFetch client the app runs, pinning both operators at slots 0 and 1.
const clientWith = (provers: Record<string, ZkFetchProver>) =>
  zkFetchClient.init({
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
    byteSlots: BYTE_SLOTS,
    provers,
  });

const collectOptions = (secret: Uint8Array) => ({
  holder: pureCircuits.holderCommitment(secret),
  windowStart: BigInt(OBSERVED_AT),
  windowEnd: WINDOW_END,
  expiresAt: Date.now() + 60_000,
  threshold: 2,
  attestorTimeoutMs: 5_000,
});

// Collect the honest threshold set through the zkFetch client and lay its
// signatures out at their registry slots, the dummy filling the unqueried one.
const collectSubmission = async (): Promise<Submission> => {
  const client = clientWith(
    Object.fromEntries(
      operators.map(({ witness, attestor }) => [
        attestor.id,
        {
          prove: async (proved: ZkFetchRequest) => {
            const evidence = await witness.sign({
              values: { stars: '42', owner: OWNER },
              timestampS: OBSERVED_AT,
              parameters: {
                url: proved.url,
                method: proved.method ?? 'GET',
                body: '',
                ...DISCLOSURE_RULES,
              },
              context: proved.context,
            });
            honestEvidence[attestor.id] = evidence;
            return evidence;
          },
        },
      ]),
    ),
  );
  const { claim, collected } = await client.collect(request, collectOptions(holderSecret));
  honestClaim = claim;
  const signatures = registryKeys.map(
    (_, slot) =>
      collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ??
      DUMMY_SIGNATURE,
  );
  return { claim: toContractClaim(claim), signatures, commitRand: randomBytes(32) };
};

// A fresh ledger that seals the policy the attestors enforced, with its block
// time at the end of the observation window.
const freshLedger = async (): Promise<MockAttestationBytesSim> => {
  const sim = await MockAttestationBytesSim.create(
    createPrivateState<B_Claim>(holderSecret),
    registryKeys,
    { policyHashes: [zkFetchPolicyHashOf(policy), POLICY_B] },
  );
  sim.now = Number(WINDOW_END);
  return sim;
};

const submit = (sim: MockAttestationBytesSim, submission: Submission, secret = holderSecret) =>
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
      bytePresent: [true, true],
      values: [42n, 0n, 0n],
      byteHalves: splitHalves(padded32(OWNER)),
    });
    expect(honest.signatures[2]).toBe(DUMMY_SIGNATURE);
  });

  it('has every attestor sign the claim context digest the witnesses signed as the salt', () => {
    const digest = zkFetchClaimContextDigestOf({
      policy,
      request: { method: 'GET', url: request.url, body: '' },
      holder: pureCircuits.holderCommitment(holderSecret),
      windowStart: BigInt(OBSERVED_AT),
      windowEnd: WINDOW_END,
    });
    expect(Buffer.from(honest.claim.salt).toString('hex')).toBe(digest);
  });

  it('accepts the honest claim end to end', async () => {
    const sim = await freshLedger();
    await submit(sim, honest);
    expect(sim.ledgerView().B_claimsVault.member(bytesIdOf(honest.claim, honest.commitRand))).toBe(
      true,
    );
  });

  const otherSecret = randomBytes(32);

  it('gets no claim for another holder from evidence signed for the honest one', async () => {
    // Whoever sees the honest evidence replays it to the same attestors under their
    // own holder. The attestors themselves refuse it, without the client's help.
    const thiefHolder = pureCircuits.holderCommitment(otherSecret);
    for (const { attestor } of operators) {
      const replayed = {
        policy,
        evidence: honestEvidence[attestor.id] as ZkFetchEvidence,
        claim: { ...honestClaim, holder: thiefHolder },
      };
      await expect(
        attestor.attest(replayed as unknown as Parameters<typeof attestor.attest>[0]),
      ).rejects.toThrow(/claim context digest/);
    }
  });

  it.each([
    { name: 'a value', mutate: (c: B_Claim) => ({ ...c, values: [43n, 0n, 0n] }) },
    {
      name: 'the presence mask',
      mutate: (c: B_Claim) => ({ ...c, present: [true, true, false] }),
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
    // POLICY_B is sealed too, so only the signatures can reject it.
    { name: 'the policy', mutate: (c: B_Claim) => ({ ...c, policyHash: POLICY_B }) },
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
