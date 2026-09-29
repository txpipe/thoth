// Unit tests for the zkFetch kind's shared logic (`@thoth/zk-tls`): value
// parsing, redaction handling, claim derivation, disclosure matching, and
// policy checks.
//
// These exercise the shared surface, not the Reclaim signature machinery —
// that is covered via the attestor by `pipeline.test.ts` (a real witnessed
// fixture) and `witness.test.ts` (local test-key witnesses).

import {
  assertEvidenceMatchesPolicy,
  claimRequestOf,
  deriveClaimFromEvidence,
  type ProviderClaimData,
  parsedEvidenceView,
  type VerifiedEvidence,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchPolicyHashOf,
  zkFetchSubjectHashOf,
} from '@thoth/zk-tls';
import { assertClaimMatchesDisclosures, assertClaimMatchesSubject } from '@thoth/zk-tls/attestor';
import { describe, expect, it } from 'vitest';

/** The app id every claim in this suite is for. */
const APP_ID = new Uint8Array(32).fill(0xa1);

/** The signed request parameters of a claim that only needs a subject. */
const REQUEST = { url: 'https://api.github.com/repos/x', method: 'GET', body: '' };

/** A signed-shape claim whose parameters/context are JSON I control. */
const claimWith = (parameters: unknown, context: unknown): ProviderClaimData => ({
  provider: 'http',
  parameters: JSON.stringify(parameters),
  owner: '0x445541beb656e0f2359cae936fda3c404c409194',
  timestampS: 1_786_122_944,
  context: JSON.stringify(context),
  identifier: '0x1a36ab63aef0496c591235b96b84bac1553ac08752fa8f38e7d088c912c38bb9',
  epoch: 1,
});

/** The disclosed values `parsedEvidenceView` extracts for a crafted claim. */
const disclosedOf = (parameters: unknown, context: unknown): Readonly<Record<string, string>> => {
  const evidence = {
    claim: claimWith(parameters, context),
    signatureHex: `0x${'00'.repeat(64)}`,
    attestorAddress: '0xc340fc267cacbb9e3101adced0c7728f7e63b63d',
  } as ZkFetchEvidence;
  return parsedEvidenceView(evidence).disclosedValues;
};

const verifiedOf = (
  claim: ProviderClaimData,
  disclosedValues: Record<string, string>,
): VerifiedEvidence => ({
  claim,
  attestorAddress: '0xc340fc267cacbb9e3101adced0c7728f7e63b63d',
  disclosedValues,
  identifier: claim.identifier,
  canonicalHash: 'ab'.repeat(32),
});

describe('parse law (through deriveClaimFromEvidence)', () => {
  const derived = (value: string, parse: 'int' | 'float'): { present: boolean; value: bigint } => {
    const claim = deriveClaimFromEvidence({
      verified: verifiedOf(claimWith(REQUEST, {}), { v: value }),
      policy: {
        allowedHosts: ['api.github.com'],
        slots: [{ slot: 0, name: 'v', parse }],
      },
      appId: APP_ID,
      valueSlots: 1,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });
    return { present: claim.present[0] ?? false, value: claim.values[0] ?? 0n };
  };

  it('parses non-negative integers within the Uint<64> wire range', () => {
    expect(derived('0', 'int')).toEqual({ present: true, value: 0n });
    expect(derived('007', 'int')).toEqual({ present: true, value: 7n });
    expect(derived('18446744073709551615', 'int')).toEqual({
      present: true,
      value: (1n << 64n) - 1n,
    });
  });

  it('leaves out-of-range, negative, and non-integer strings unpresent', () => {
    expect(derived('18446744073709551616', 'int').present).toBe(false);
    expect(derived('-1', 'int').present).toBe(false);
    expect(derived('1.5', 'int').present).toBe(false);
    expect(derived('0x10', 'int').present).toBe(false);
    expect(derived('1e3', 'int').present).toBe(false);
  });

  it('rounds floats to the nearest whole value', () => {
    expect(derived('3.7', 'float')).toEqual({ present: true, value: 4n });
    expect(derived('3.2', 'float')).toEqual({ present: true, value: 3n });
    expect(derived('0.0', 'float')).toEqual({ present: true, value: 0n });
    expect(derived('2.5e2', 'float')).toEqual({ present: true, value: 250n });
  });

  it('rejects non-numeric or unbounded floats as unpresent', () => {
    expect(derived('abc', 'float').present).toBe(false);
    expect(derived('NaN', 'float').present).toBe(false);
    expect(derived('Infinity', 'float').present).toBe(false);
    expect(derived('-0.5', 'float').present).toBe(false);
    expect(derived('1e30', 'float').present).toBe(false);
  });
});

describe('disclosedValuesOf via parsedEvidenceView', () => {
  it('returns every extracted value when nothing is redacted', () => {
    expect(
      disclosedOf({}, { extractedParameters: { distance: '12.4', label: 'commute' } }),
    ).toEqual({
      distance: '12.4',
      label: 'commute',
    });
  });

  it('passes extracted values through whatever the signed redactions say', () => {
    // Redaction is a reveal whitelist applied before the witness sees the
    // response, so the witness's extracted values are certifiable as they are.
    const disclosed = disclosedOf(
      {
        responseRedactions: [
          { regex: '(?<token>secret-[0-9]+)' },
          { jsonPath: '$.user.email' },
          { xPath: '//*' },
        ],
      },
      { extractedParameters: { token: 'secret-4815', email: 'a@b.co', label: 'commute' } },
    );
    expect(disclosed).toEqual({ token: 'secret-4815', email: 'a@b.co', label: 'commute' });
  });

  it('treats unknown redaction fields as inert', () => {
    const disclosed = disclosedOf(
      { responseRedactions: [{ xPath: '' }, { regex: '' }, { jsonPath: '' }] },
      { extractedParameters: { a: '1' } },
    );
    expect(disclosed).toEqual({ a: '1' });
  });
});

describe('deriveClaimFromEvidence', () => {
  const policy = (slots: ZkFetchPolicy['slots']): ZkFetchPolicy => ({
    allowedHosts: ['api.github.com'],
    slots,
  });

  it('maps disclosed values into the declared slots', () => {
    const verified = verifiedOf(
      claimWith(REQUEST, { extractedParameters: { distance: '12.4', time: '300' } }),
      { distance: '12.4', time: '300' },
    );
    const claim = deriveClaimFromEvidence({
      verified,
      policy: policy([{ slot: 0, name: 'distance', parse: 'float' }]),
      appId: APP_ID,
      valueSlots: 2,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });
    expect(claim.values).toEqual([12n, 0n]);
    expect(claim.present).toEqual([true, false]);
  });

  it('signs absent or unparseable disclosures as unpresent', () => {
    const verified = verifiedOf(
      claimWith(REQUEST, { extractedParameters: { distance: 'n/a', time: '300' } }),
      { distance: 'n/a', time: '300' },
    );
    const claim = deriveClaimFromEvidence({
      verified,
      policy: policy([{ slot: 0, name: 'time', parse: 'int' }]),
      appId: APP_ID,
      valueSlots: 2,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });
    expect(claim.values).toEqual([300n, 0n]);
    expect(claim.present).toEqual([true, false]);
  });

  it('carries the given appId and the hash of the policy it was derived under', () => {
    const verified = verifiedOf(claimWith(REQUEST, { extractedParameters: { a: '1' } }), {
      a: '1',
    });
    const activePolicy = policy([{ slot: 0, name: 'a', parse: 'int' }]);
    const claim = deriveClaimFromEvidence({
      verified,
      policy: activePolicy,
      appId: APP_ID,
      valueSlots: 1,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });
    expect(claim.appId).toEqual(APP_ID);
    expect(claim.policyHash).toEqual(zkFetchPolicyHashOf(activePolicy));
  });

  it('carries the subject hash of the signed request', () => {
    const request = { url: 'https://api.github.com/repos/x?y=1', method: 'POST', body: '{"a":1}' };
    const verified = verifiedOf(claimWith(request, { extractedParameters: { a: '1' } }), {
      a: '1',
    });
    const claim = deriveClaimFromEvidence({
      verified,
      policy: policy([{ slot: 0, name: 'a', parse: 'int' }]),
      appId: APP_ID,
      valueSlots: 1,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });
    expect(claim.subjectHash).toEqual(zkFetchSubjectHashOf(request));
  });

  it('throws when a policy slot exceeds the claim value count', () => {
    const verified = verifiedOf(claimWith(REQUEST, { extractedParameters: { a: '1' } }), {
      a: '1',
    });
    expect(() =>
      deriveClaimFromEvidence({
        verified,
        policy: policy([{ slot: 1, name: 'a', parse: 'int' }]),
        appId: APP_ID,
        valueSlots: 1,
        windowStart: 1_786_122_944n,
        windowEnd: 1_786_122_944n,
      }),
    ).toThrow(/out of the claim's 1 value slots/);
  });
});

describe('claimRequestOf', () => {
  it('reads the method, url and body the witness signed', () => {
    expect(claimRequestOf(claimWith({ ...REQUEST, body: 'b', headers: { a: '1' } }, {}))).toEqual({
      ...REQUEST,
      body: 'b',
    });
  });

  it('treats a missing body as empty', () => {
    const { body: _, ...noBody } = REQUEST;
    expect(zkFetchSubjectHashOf(claimRequestOf(claimWith(noBody, {})))).toEqual(
      zkFetchSubjectHashOf(REQUEST),
    );
  });

  it('rejects parameters without a method or url', () => {
    expect(() => claimRequestOf(claimWith({ url: REQUEST.url }, {}))).toThrow(/method/);
    expect(() => claimRequestOf(claimWith({ method: 'GET' }, {}))).toThrow(/url/);
    expect(() => claimRequestOf(claimWith({ ...REQUEST, body: 1 }, {}))).toThrow(/body/);
  });
});

describe('assertClaimMatchesSubject', () => {
  const verified = verifiedOf(claimWith(REQUEST, {}), {});

  it('accepts a claim about the signed request', () => {
    assertClaimMatchesSubject({
      claim: { subjectHash: zkFetchSubjectHashOf(REQUEST) } as never,
      verified,
    });
  });

  it('rejects a claim about another request', () => {
    const other = { ...REQUEST, url: 'https://api.github.com/repos/y' };
    expect(() =>
      assertClaimMatchesSubject({
        claim: { subjectHash: zkFetchSubjectHashOf(other) } as never,
        verified,
      }),
    ).toThrow(/subjectHash does not match/);
  });
});

describe('assertClaimMatchesDisclosures', () => {
  const policy = (slots: ZkFetchPolicy['slots']): ZkFetchPolicy => ({
    allowedHosts: ['api.github.com'],
    slots,
  });

  it('accepts a claim that reflects the disclosures', () => {
    assertClaimMatchesDisclosures({
      claim: { values: [12n, 0n], present: [true, false] } as never,
      disclosures: { distance: '12.4' },
      policy: policy([{ slot: 0, name: 'distance', parse: 'float' }]),
    });
  });

  it('rejects a claim that disagrees with the disclosures', () => {
    expect(() =>
      assertClaimMatchesDisclosures({
        claim: { values: [13n, 0n], present: [true, false] } as never,
        disclosures: { distance: '12.4' },
        policy: policy([{ slot: 0, name: 'distance', parse: 'float' }]),
      }),
    ).toThrow(/does not match the disclosed value/);
  });

  it('rejects a claim that certifies an absent disclosure as present', () => {
    expect(() =>
      assertClaimMatchesDisclosures({
        claim: { values: [0n, 0n], present: [true, false] } as never,
        disclosures: {},
        policy: policy([{ slot: 0, name: 'distance', parse: 'float' }]),
      }),
    ).toThrow(/does not match the disclosed value/);
  });
});

describe('assertEvidenceMatchesPolicy', () => {
  const policy: ZkFetchPolicy = {
    allowedHosts: ['api.github.com'],
    slots: [{ slot: 0, name: 'distance', parse: 'float' }],
  };

  const verified = (url: string): VerifiedEvidence =>
    verifiedOf(claimWith({ url }, { extractedParameters: { distance: '12.4' } }), {
      distance: '12.4',
    });

  it('accepts an https claim against an allowlisted host', () => {
    expect(assertEvidenceMatchesPolicy(verified('https://api.github.com/repos/x'), policy)).toBe(
      'api.github.com',
    );
  });

  it('rejects a non-https claim', () => {
    expect(() => assertEvidenceMatchesPolicy(verified('http://api.github.com/x'), policy)).toThrow(
      /must be https/,
    );
  });

  it('rejects an unknown host', () => {
    expect(() =>
      assertEvidenceMatchesPolicy(verified('https://evil.example.com/x'), policy),
    ).toThrow(/not in allowlist/);
  });

  it('allows subdomains of an allowlisted suffix and ignores case', () => {
    const suffixes = { allowedHosts: ['GitHub.COM'] } as ZkFetchPolicy;
    expect(
      assertEvidenceMatchesPolicy(verified('https://uploads.api.github.com/x'), {
        ...policy,
        ...suffixes,
      }),
    ).toBe('uploads.api.github.com');
  });

  it('does not confuse a suffix with a distinct hostname', () => {
    expect(() => assertEvidenceMatchesPolicy(verified('https://notgithub.com/x'), policy)).toThrow(
      /not in allowlist/,
    );
  });

  it('refuses a required slot whose disclosure is missing or unparseable', () => {
    const missing = verifiedOf(
      claimWith({ url: 'https://api.github.com/x' }, { extractedParameters: {} }),
      {},
    );
    expect(() => assertEvidenceMatchesPolicy(missing, policy)).toThrow(
      /not disclose a parseable value/,
    );
    const unparseable = verifiedOf(
      claimWith({ url: 'https://api.github.com/x' }, { extractedParameters: { distance: 'abc' } }),
      { distance: 'abc' },
    );
    expect(() => assertEvidenceMatchesPolicy(unparseable, policy)).toThrow(
      /not disclose a parseable value/,
    );
  });

  it('allows an optional slot to be absent', () => {
    const optional = {
      ...policy,
      slots: [{ slot: 0, name: 'distance', parse: 'float', optional: true }],
    };
    const missing = verifiedOf(
      claimWith({ url: 'https://api.github.com/x' }, { extractedParameters: {} }),
      {},
    );
    expect(assertEvidenceMatchesPolicy(missing, optional)).toBe('api.github.com');
  });

  it('enforces the response size bound', () => {
    const large = verifiedOf(
      claimWith({ url: 'https://api.github.com/x' }, { extractedParameters: { distance: '1' } }),
      { distance: '1' },
    );
    const withSize = { ...policy, maxResponseBytes: 4 };
    large.responseText = 'x'.repeat(100);
    expect(() => assertEvidenceMatchesPolicy(large, withSize)).toThrow(/exceeds maxResponseBytes/);
  });
});
