// Test-key witnesses: local secp256k1 keys stand in for Reclaim witnesses and
// sign provider claim data. Checks the zkFetch attestor accepts evidence signed
// by the witness key it pins — offline and deterministically — and rejects
// evidence from any other witness.
import type { FlatMessage } from '@thoth/core/claim';
import {
  deriveClaimFromEvidence,
  parsedEvidenceView,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
} from '@thoth/zk-tls';
import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { describe, expect, it } from 'vitest';
import { type Observation, type TestWitness, testWitness } from './helpers/witness.js';

const alice = testWitness(`0x${'11'.repeat(32)}`);
const bob = testWitness(`0x${'22'.repeat(32)}`);

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.example.com'],
  slots: [
    { slot: 0, name: 'balance', parse: 'int' },
    { slot: 1, name: 'score', parse: 'float', optional: true },
  ],
};

const observe = (
  witness: TestWitness,
  overrides: Partial<Observation> = {},
): Promise<ZkFetchEvidence> =>
  witness.sign({
    values: { balance: '0', score: '7.6' },
    timestampS: 1_786_000_000,
    parameters: { url: 'https://api.example.com/v1/account', method: 'GET', body: '' },
    context: { intent: 'ab'.repeat(32) },
    ...overrides,
  });

const attestor = zkFetchAttestor({
  id: 'attestor-0',
  keyPair: {
    publicKey: 'pk-0',
    signer: { sign: (message: FlatMessage): string => `sig:${message.join(',')}` },
  },
  registryIndex: 0,
  witnessKey: `0x${'11'.repeat(32)}`,
});

const attest = (evidence: ZkFetchEvidence) => {
  const claim = deriveClaimFromEvidence({
    verified: parsedEvidenceView(evidence),
    policy,
    valueSlots: 3,
  });
  return attestor.attest({ policy, evidence, claim } as unknown as Parameters<
    typeof attestor.attest
  >[0]);
};

describe('test-key witness', () => {
  it('derives the Ethereum address of its key', () => {
    // The well-known address of secp256k1 key 0x11…11.
    expect(alice.address).toBe('0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a');
    expect(bob.address).not.toBe(alice.address);
  });

  it('produces evidence carrying the chosen values, timestamp, parameters and context', async () => {
    const evidence = await observe(alice, { timestampS: 1_786_000_123 });
    expect(evidence.attestorAddress).toBe(alice.address);
    expect(evidence.claim.timestampS).toBe(1_786_000_123);
    expect(JSON.parse(evidence.claim.parameters)).toMatchObject({
      url: 'https://api.example.com/v1/account',
      method: 'GET',
    });
    const context = JSON.parse(evidence.claim.context);
    expect(context.intent).toBe('ab'.repeat(32));
    expect(context.extractedParameters).toEqual({ balance: '0', score: '7.6' });
  });

  it('is deterministic across runs', async () => {
    // RFC 6979 signing: the same observation always yields this signature.
    expect((await observe(alice)).signatureHex).toBe(
      '0xc8f99f97782ae3983f0236964238b2dc2f84944f9da2d4fc20e25ead54cd188652fe9ef0d2201e4c73c90e64e72e5f4c1737978c59b95e46c7a5f0fec7385e3a1b',
    );
  });

  it('is accepted and signed by the attestor whose witness it is', async () => {
    const attestation = await attest(await observe(alice));
    expect(attestation.claim.timestamp).toBe(1_786_000_000n);
    // A present zero stays present.
    expect(attestation.claim.present).toEqual([true, true, false]);
    expect(attestation.claim.values).toEqual([0n, 8n, 0n]);
    expect(attestation.signature).toMatch(/^sig:/);
  });

  it('is rejected when signed by another witness', async () => {
    await expect(attest(await observe(bob))).rejects.toThrow(/not this attestor's witness/);
  });

  it('is rejected when the claim identifier does not match its signed content', async () => {
    const evidence = await observe(alice);
    const forged = {
      ...evidence,
      claim: { ...evidence.claim, identifier: `0x${'ab'.repeat(32)}` },
    };
    await expect(attest(forged)).rejects.toThrow(/identifier/);
  });

  it('is rejected when it claims another witness address', async () => {
    const forged = { ...(await observe(bob)), attestorAddress: alice.address };
    await expect(attest(forged)).rejects.toThrow(/Invalid claim signature/);
  });
});
