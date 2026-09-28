// Reproductions for zk-tls audit findings that are not in the contract layer.
// These tests assert the intended behavior. They fail while the defects exist
// and go green once they are fixed.

import { descriptorOf } from '@thoth/attestor';
import type { AttestorTransport } from '@thoth/client';
import { buildTrustedSet } from '@thoth/client';
import type { FlatMessage } from '@thoth/core/claim';
import {
  deriveClaimFromEvidence,
  parseDisclosedValue,
  parsedEvidenceView,
  type ZkFetchDefinition,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
} from '@thoth/zk-tls';
import { verifyZkFetchProof, zkFetchAttestor } from '@thoth/zk-tls/attestor';
import { zkFetchClient } from '@thoth/zk-tls/client';
import { describe, expect, it } from 'vitest';
import { type Observation, testWitness } from './helpers/witness.js';

const alice = testWitness(`0x${'11'.repeat(32)}`);

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.example.com'],
  slots: [{ slot: 0, name: 'balance', parse: 'int' }],
};

const observe = (overrides: Partial<Observation> = {}): Promise<ZkFetchEvidence> =>
  alice.sign({
    values: { balance: '0' },
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

const attestWith = (
  evidence: ZkFetchEvidence,
  timestamp: bigint,
  overrides: Partial<ZkFetchPolicy> = {},
) => {
  const activePolicy = { ...policy, ...overrides };
  const claim = deriveClaimFromEvidence({
    verified: parsedEvidenceView(evidence),
    policy: activePolicy,
    valueSlots: 3,
    timestamp,
  });
  return attestor.attest({ policy: activePolicy, evidence, claim } as unknown as Parameters<
    typeof attestor.attest
  >[0]);
};

describe('audit repro: the attestor accepts stale witness observations', () => {
  it('rejects an observation from a year ago', async () => {
    const oldTimestampS = Math.floor(Date.now() / 1000) - 365 * 24 * 3600;
    const evidence = await observe({ timestampS: oldTimestampS });
    await expect(attestWith(evidence, BigInt(oldTimestampS))).rejects.toThrow();
  });

  it('does not let a request widen the observation tolerance', async () => {
    const evidence = await observe();
    await expect(
      attestWith(evidence, 1_786_000_000n - 3_600n, { maxSkewS: 999_999 }),
    ).rejects.toThrow();
  });
});

describe('audit repro: maxResponseBytes is bypassed when responseText is absent', () => {
  it('control: the size bound cannot apply to absent responseText', async () => {
    const evidence = await observe();
    expect(evidence.responseText).toBeUndefined();
    await attestWith(evidence, 1_786_000_000n, { maxResponseBytes: 1 });
  });

  it('rejects evidence that omits the field the bound reads', async () => {
    const evidence = await observe();
    await expect(attestWith(evidence, 1_786_000_000n, { maxResponseBytes: 1 })).rejects.toThrow();
  });
});

describe('audit repro: float parsing accepts prefix junk and loses precision', () => {
  it('rejects a float with trailing junk', () => {
    expect(parseDisclosedValue('12abc', 'float')).toBeNull();
  });

  it('rejects a grouped number', () => {
    expect(parseDisclosedValue('1,000', 'float')).toBeNull();
  });

  it('preserves an integer above 2^53', () => {
    expect(parseDisclosedValue('9007199254740993', 'float')).toBe(9_007_199_254_740_993n);
  });
});

describe('audit repro: verifyZkFetchProof mutates the evidence it verifies', () => {
  it('leaves a non-canonical context unchanged', async () => {
    const evidence = await observe();
    const pretty = JSON.stringify(JSON.parse(evidence.claim.context), null, 2);
    expect(pretty).not.toBe(evidence.claim.context);
    const mutated = {
      ...evidence,
      claim: { ...evidence.claim, context: pretty },
    };
    await verifyZkFetchProof(mutated);
    expect(mutated.claim.context).toBe(pretty);
  });
});

// Encodes option (b) of the decision issue: if the client is meant to verify
// signatures, this test is the desired behavior. If the decision is to
// document the absence instead, delete this test with the issue.
describe('audit repro: the client accepts a signature it never verifies', () => {
  it('rejects a forged attestor signature', async () => {
    const trusted = buildTrustedSet([descriptorOf(attestor)]);
    const forgingTransport: AttestorTransport<ZkFetchDefinition, string, string> = {
      async request(_attestor, input) {
        const attestation = await attestor.attest(input as Parameters<typeof attestor.attest>[0]);
        return { ...attestation, signature: 'forged' };
      },
    };
    const client = zkFetchClient.init({
      trusted,
      transport: forgingTransport,
      policy,
      valueSlots: 3,
      provers: { 'attestor-0': { prove: () => observe() } },
    });
    const proof = await client.proveReq({
      url: 'https://api.example.com/v1/account',
      method: 'GET',
    });
    await expect(proof.attest()).rejects.toThrow();
  });
});
