// Reproductions for zk-tls audit findings that are not in the contract layer.
// These tests assert the intended behavior. They fail while the defects exist
// and go green once they are fixed.
import type { FlatMessage } from '@thoth/core/claim';
import {
  deriveClaimFromEvidence,
  parseDisclosedValue,
  parsedEvidenceView,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
} from '@thoth/zk-tls';
import { verifyZkFetchProof, zkFetchAttestor } from '@thoth/zk-tls/attestor';
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
