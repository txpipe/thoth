// Recorded data end to end, the offline half of #123: the Controller's agent's
// real Control claim and Reading, each recorded through two witnesses, go through
// two zkFetch attestors and the client into the Bounty. Each attestor trusts the
// witness that recorded its evidence; the third registry slot is never queried.
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { JubjubPoint, JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import { descriptorOf, type KeyPair } from '@thoth/attestor';
import { buildTrustedSet } from '@thoth/client';
import { jubjubVerifier } from '@thoth/client/jubjub';
import { type ZkFetchEvidence, type ZkFetchPolicy, zkFetchPolicyHashOf } from '@thoth/zk-tls';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { type ZkFetchRequest, zkFetchClient } from '@thoth/zk-tls/client';
import { beforeEach, describe, expect, it } from 'vitest';
import { pureCircuits } from '../artifacts/bounty/contract/index.js';
import {
  type Attestation,
  agentKey,
  BountySim,
  idOf,
  makeNotaryKey,
  signMessage,
  UNSIGNED,
} from './sim.js';

type Recording = { request: ZkFetchRequest; evidences: [ZkFetchEvidence, ZkFetchEvidence] };
const recording = (name: string): Recording =>
  JSON.parse(readFileSync(new URL(`../../fixtures/${name}`, import.meta.url), 'utf8'));

const CONTROL = recording('control-claimable.json');
const READING = recording('reading-mining.json');
/** The Controller's agent both recordings are of. */
const AGENT = 'user-agent-lhb10ef8yjy1wfc';

/** The agent ID after `user-agent-`, five `bytes8` groups in slots 1-5. */
const ID_SLOTS = [1, 2, 3, 4, 5].map((n) => ({
  slot: n,
  name: `id${n}`,
  parse: 'bytes8' as const,
  optional: n > 1,
}));
const CONTROL_POLICY: ZkFetchPolicy = { allowedHosts: ['midnight.city'], slots: ID_SLOTS };
const READING_POLICY: ZkFetchPolicy = {
  allowedHosts: ['midnight.city'],
  slots: [{ slot: 0, name: 'xp', parse: 'int' }, ...ID_SLOTS],
};

const jubjubKeyPair = (): KeyPair<JubjubPoint, JubjubSchnorrSignature> => {
  const { sk, pk } = makeNotaryKey();
  return { publicKey: pk, signer: { sign: (message) => signMessage(sk, message) } };
};

// Attestor i trusts the witness that recorded evidence i, in both recordings.
const attestors = CONTROL.evidences.map((evidence, i) =>
  zkFetchAttestor({
    id: `attestor-${i}`,
    keyPair: jubjubKeyPair(),
    witnessAddress: evidence.attestorAddress,
  }),
);
const registryKeys = [...attestors.map((attestor) => attestor.publicKey), makeNotaryKey().pk];

/** Collect a 2-of-3 attestment of `recorded` under `policy`, laid out at the registry slots. */
const collect = async (
  recorded: Recording,
  policy: ZkFetchPolicy,
  secret: Uint8Array,
): Promise<Attestation> => {
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
    appId: new Uint8Array(32).fill(0xa1),
    valueSlots: 6,
    // Each attestor's prover replays its witness's recorded evidence.
    provers: Object.fromEntries(
      recorded.evidences.map((evidence, i) => [`attestor-${i}`, { prove: async () => evidence }]),
    ),
  });
  const observedAt = recorded.evidences.map((evidence) => BigInt(evidence.claim.timestampS));
  const { claim, collected } = await client.collect(recorded.request, {
    holder: pureCircuits.holderCommitment(secret),
    windowStart: observedAt.reduce((a, b) => (a < b ? a : b)),
    windowEnd: observedAt.reduce((a, b) => (a > b ? a : b)),
    expiresAt: Date.now() + 60_000,
    threshold: 2,
    attestorTimeoutMs: 5_000,
  });
  return {
    claim: { ...claim, present: [...claim.present], values: [...claim.values] },
    signatures: registryKeys.map(
      (_, slot) =>
        collected.find((entry) => entry.registryIndex === slot)?.attestation.signature ?? UNSIGNED,
    ),
    commitRand: randomBytes(32),
  };
};

const secret = randomBytes(32);
const holder = { attestations: [], holderSecret: secret };
let sim: BountySim;

/** Vault an attestation just after its window. */
const vault = async (attestation: Attestation) => {
  sim.now = attestation.claim.windowEnd + 1n;
  await sim.call('verifyAttestation', { ...holder, attestations: [attestation] });
};

beforeEach(async () => {
  // The Bounty opens just after the recorded Reading, which is then a Start reading.
  const opensAt = BigInt(READING.evidences[1].claim.timestampS) + 60n;
  sim = await BountySim.deploy({
    keys: registryKeys,
    controlPolicy: zkFetchPolicyHashOf(CONTROL_POLICY),
    readingPolicy: zkFetchPolicyHashOf(READING_POLICY),
    threshold: 10_000n,
    opensAt,
    deadline: opensAt + 7_200n,
    payoutEnd: opensAt + 7_200n + 604_800n,
    sponsor: { bytes: new Uint8Array(32).fill(0x5a) },
    freshnessWindow: 3_600n,
    maxWindow: 300n,
  });
});

describe('recorded City data', () => {
  it("registers the Controller's agent from its recorded Control claim and Start reading", async () => {
    const control = await collect(CONTROL, CONTROL_POLICY, secret);
    const start = await collect(READING, READING_POLICY, secret);
    await vault(control);
    await vault(start);
    await sim.call(
      'register',
      { ...holder, attestations: [control, start] },
      idOf(control),
      idOf(start),
      { bytes: new Uint8Array(32).fill(0x11) },
    );
    // 1,073 Mining XP is what both witnesses saw when the Reading was recorded.
    expect(sim.ledger().registrations.lookup(agentKey(AGENT)).startXp).toBe(1_073n);
  });

  it('refuses the recorded Reading as a Control claim', async () => {
    const reading = await collect(READING, READING_POLICY, secret);
    await vault(reading);
    sim.now = reading.claim.windowEnd + 2n;
    await expect(
      sim.call(
        'register',
        { ...holder, attestations: [reading, reading] },
        idOf(reading),
        idOf(reading),
        { bytes: new Uint8Array(32).fill(0x11) },
      ),
    ).rejects.toThrow('Not a Control claim');
  });
});
