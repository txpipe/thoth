// The attestor's per-instance input limits: oversized input is rejected while
// it is parsed, before the proof check or the signature runs.
import type { KeyPair } from '@txpipe/thoth-attestor';
import type { FlatMessage } from '@txpipe/thoth-core/claim';
import {
  ZK_FETCH_DEFAULT_LIMITS,
  type ZkFetchLimits,
  type ZkFetchPolicy,
  zkFetchClaimSchema,
  zkFetchPolicyHashOf,
  zkFetchSchemasWithin,
} from '@txpipe/thoth-zk-tls';
import { zkFetchAttestor } from '@txpipe/thoth-zk-tls/attestor';
import { describe, expect, it, vi } from 'vitest';
import { DISCLOSURE_RULES, FIXTURE } from './helpers/helper.js';

const fixture = FIXTURE;

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.github.com'],
  slots: [{ slot: 0, name: 'data', parse: 'float', optional: true }],
  bodyPolicy: 'ignored',
  ...DISCLOSURE_RULES,
};

const claim = {
  version: 1,
  appId: new Uint8Array(32).fill(0xa1),
  holder: new Uint8Array(32).fill(0xc1),
  salt: new Uint8Array(32).fill(0xcd),
  policyHash: new Uint8Array(32),
  windowStart: 1_786_122_944,
  windowEnd: 1_786_122_944,
  subjectHash: new Uint8Array(32),
  present: [false],
  values: [0],
};

/** An attestor whose proof check and signer record whether they ran. */
const watchedAttestor = (limits?: Partial<ZkFetchLimits>) => {
  const sign = vi.fn((message: FlatMessage) => `sig:${message.length}`);
  const keyPair: KeyPair<string, string, FlatMessage> = { publicKey: 'pk', signer: { sign } };
  const attestor = zkFetchAttestor({
    id: 'attestor-0',
    keyPair,
    witnessAddress: fixture.attestorAddress as string,
    ...(limits === undefined ? {} : { limits }),
  });
  const verify = vi.spyOn(attestor.definition, 'verify');
  return { attestor, verify, sign };
};

/** Attest an input with one part replaced, and assert it fails before verifying or signing. */
const expectRejectedUnverified = async (
  input: { policy?: unknown; evidence?: unknown; claim?: unknown },
  error: RegExp,
  limits?: Partial<ZkFetchLimits>,
) => {
  const { attestor, verify, sign } = watchedAttestor(limits);
  await expect(
    attestor.attest({
      policy: (input.policy ?? policy) as ZkFetchPolicy,
      evidence: (input.evidence ?? fixture) as never,
      claim: (input.claim ?? claim) as never,
    }),
  ).rejects.toThrow(error);
  expect(verify).not.toHaveBeenCalled();
  expect(sign).not.toHaveBeenCalled();
};

const repeat = <T>(count: number, item: T): T[] => Array.from({ length: count }, () => item);

describe('zkFetch attestor default input limits', () => {
  it('rejects more numeric slots than the limit before verifying or signing', async () => {
    const count = ZK_FETCH_DEFAULT_LIMITS.valueSlots + 1;
    await expectRejectedUnverified(
      { claim: { ...claim, values: repeat(count, 0), present: repeat(count, false) } },
      new RegExp(`"values"[\\s\\S]*<=${ZK_FETCH_DEFAULT_LIMITS.valueSlots} items`),
    );
  });

  it('rejects more byte slots than the limit before verifying or signing', async () => {
    const count = ZK_FETCH_DEFAULT_LIMITS.byteSlots + 1;
    await expectRejectedUnverified(
      {
        claim: {
          ...claim,
          byteValues: repeat(count, new Uint8Array(32)),
          present: repeat(count + 1, false),
        },
      },
      new RegExp(`"byteValues"[\\s\\S]*<=${ZK_FETCH_DEFAULT_LIMITS.byteSlots} items`),
    );
  });

  it('counts the array the claim schema parses, so a getter cannot swap in a longer one', () => {
    const huge = repeat(1_000_000, 0);
    let reads = 0;
    const input = {
      ...claim,
      present: repeat(1, false),
      get values() {
        reads += 1;
        return reads === 1 ? [0] : huge;
      },
    };
    const parsed = zkFetchSchemasWithin(ZK_FETCH_DEFAULT_LIMITS).claim.parse(input);
    expect(reads).toBe(1);
    expect(parsed.values).toHaveLength(1);
  });

  it('counts a Proxy array once, and rejects it when that count is over the limit', () => {
    const count = ZK_FETCH_DEFAULT_LIMITS.valueSlots + 1;
    const values = new Proxy(repeat(count, 0), {});
    expect(() =>
      zkFetchSchemasWithin(ZK_FETCH_DEFAULT_LIMITS).claim.parse({
        ...claim,
        values,
        present: repeat(count, false),
      }),
    ).toThrow(/"values"[\s\S]*Too big/);
  });

  it('parses a claim at every slot limit', () => {
    const values = ZK_FETCH_DEFAULT_LIMITS.valueSlots;
    const bytes = ZK_FETCH_DEFAULT_LIMITS.byteSlots;
    const parsed = zkFetchSchemasWithin(ZK_FETCH_DEFAULT_LIMITS).claim.parse({
      ...claim,
      values: repeat(values, 0),
      byteValues: repeat(bytes, new Uint8Array(32)),
      present: repeat(values + bytes, false),
    });
    expect(parsed.values).toHaveLength(values);
    expect(parsed.byteValues).toHaveLength(bytes);
  });

  it.each([
    [
      'allowedHosts',
      { allowedHosts: repeat(ZK_FETCH_DEFAULT_LIMITS.allowedHosts + 1, 'api.github.com') },
    ],
    [
      'slots',
      {
        slots: Array.from(
          { length: ZK_FETCH_DEFAULT_LIMITS.valueSlots + ZK_FETCH_DEFAULT_LIMITS.byteSlots + 1 },
          (_, slot) => ({ slot, name: 'data', parse: 'int' }),
        ),
      },
    ],
    [
      'responseMatches',
      {
        responseMatches: repeat(ZK_FETCH_DEFAULT_LIMITS.responseMatches + 1, {
          type: 'contains',
          value: 'x',
        }),
      },
    ],
    [
      'responseRedactions',
      {
        responseRedactions: repeat(ZK_FETCH_DEFAULT_LIMITS.responseRedactions + 1, { regex: 'x' }),
      },
    ],
  ])('rejects a policy whose %s exceeds its limit', async (field, override) => {
    await expectRejectedUnverified(
      { policy: { ...policy, ...override } },
      new RegExp(`"${field}"[\\s\\S]*Too big`),
    );
  });

  it.each([
    [
      'allowedHosts',
      { allowedHosts: [`${'a'.repeat(ZK_FETCH_DEFAULT_LIMITS.hostLength - 2)}.io`] },
    ],
    [
      'slots',
      {
        slots: [
          { slot: 0, name: 'd'.repeat(ZK_FETCH_DEFAULT_LIMITS.slotNameLength + 1), parse: 'int' },
        ],
      },
    ],
    [
      'responseMatches',
      {
        responseMatches: [
          { type: 'regex', value: 'x'.repeat(ZK_FETCH_DEFAULT_LIMITS.ruleLength + 1) },
        ],
      },
    ],
    [
      'responseRedactions',
      { responseRedactions: [{ jsonPath: 'x'.repeat(ZK_FETCH_DEFAULT_LIMITS.ruleLength + 1) }] },
    ],
  ])('rejects a policy string in %s over its limit', async (field, override) => {
    await expectRejectedUnverified(
      { policy: { ...policy, ...override } },
      new RegExp(`"${field}"[\\s\\S]*Too big`),
    );
  });

  const oversized = (limit: number) => 'x'.repeat(limit + 1);

  it.each([
    [
      'parameters',
      {
        claim: {
          ...fixture.claim,
          parameters: oversized(ZK_FETCH_DEFAULT_LIMITS.parametersLength),
        },
      },
    ],
    [
      'context',
      { claim: { ...fixture.claim, context: oversized(ZK_FETCH_DEFAULT_LIMITS.contextLength) } },
    ],
    [
      'provider',
      { claim: { ...fixture.claim, provider: oversized(ZK_FETCH_DEFAULT_LIMITS.fieldLength) } },
    ],
    [
      'owner',
      { claim: { ...fixture.claim, owner: oversized(ZK_FETCH_DEFAULT_LIMITS.fieldLength) } },
    ],
    [
      'identifier',
      { claim: { ...fixture.claim, identifier: oversized(ZK_FETCH_DEFAULT_LIMITS.fieldLength) } },
    ],
    ['signatureHex', { signatureHex: oversized(ZK_FETCH_DEFAULT_LIMITS.fieldLength) }],
    ['attestorAddress', { attestorAddress: oversized(ZK_FETCH_DEFAULT_LIMITS.fieldLength) }],
    ['responseText', { responseText: oversized(ZK_FETCH_DEFAULT_LIMITS.responseTextLength) }],
  ])('rejects an evidence %s over its limit', async (field, override) => {
    await expectRejectedUnverified(
      { evidence: { ...fixture, ...override } },
      new RegExp(`"${field}"[\\s\\S]*Too big`),
    );
  });
});

describe('zkFetch attestor configured input limits', () => {
  it('rejects input over a lowered limit before verifying or signing', async () => {
    await expectRejectedUnverified(
      { claim: { ...claim, values: repeat(3, 0), present: repeat(3, false) } },
      /"values"[\s\S]*<=2 items/,
      { valueSlots: 2 },
    );
    await expectRejectedUnverified(
      { evidence: { ...fixture, responseText: 'x'.repeat(11) } },
      /"responseText"[\s\S]*Too big/,
      { responseTextLength: 10 },
    );
  });

  it('accepts input over a default limit once the operator raises it', async () => {
    const count = ZK_FETCH_DEFAULT_LIMITS.valueSlots + 1;
    const { attestor, verify } = watchedAttestor({ valueSlots: count });
    // Past the parse, the fixture's policy has one slot, so `verify` rejects
    // the extra slots; reaching it is what this test checks.
    await expect(
      attestor.attest({
        policy,
        evidence: fixture as never,
        claim: { ...claim, values: repeat(count, 0), present: repeat(count, false) } as never,
      }),
    ).rejects.not.toThrow(/Too big/);
    expect(verify).toHaveBeenCalledOnce();
  });

  it('keeps the default for every limit left unset', async () => {
    await expectRejectedUnverified(
      {
        policy: {
          ...policy,
          allowedHosts: repeat(ZK_FETCH_DEFAULT_LIMITS.allowedHosts + 1, 'a.io'),
        },
      },
      /"allowedHosts"[\s\S]*Too big/,
      { valueSlots: 128 },
    );
  });

  it.each([
    [{ valueSlots: 0 }, /'valueSlots' must be a positive integer, got 0/],
    [{ hostLength: 1.5 }, /'hostLength' must be a positive integer, got 1.5/],
    [{ fieldLength: Number.POSITIVE_INFINITY }, /'fieldLength' must be a positive integer/],
    [{ valueSlot: 128 } as Partial<ZkFetchLimits>, /unknown zkFetch limit 'valueSlot'/],
  ])('refuses the limits %o when the attestor is built', (limits, error) => {
    expect(() =>
      zkFetchAttestor({
        id: 'attestor-0',
        keyPair: { publicKey: 'pk', signer: { sign: () => 'sig' } },
        witnessAddress: fixture.attestorAddress as string,
        limits,
      }),
    ).toThrow(error);
  });

  it('leaves the exported schemas uncapped, so a client accepts what any attestor allows', () => {
    const count = ZK_FETCH_DEFAULT_LIMITS.allowedHosts + 1;
    expect(() =>
      zkFetchPolicyHashOf({ ...policy, allowedHosts: repeat(count, 'api.github.com') }),
    ).not.toThrow();
    const values = ZK_FETCH_DEFAULT_LIMITS.valueSlots + 1;
    expect(
      zkFetchClaimSchema.parse({
        ...claim,
        values: repeat(values, 0),
        present: repeat(values, false),
      }).values,
    ).toHaveLength(values);
  });
});
