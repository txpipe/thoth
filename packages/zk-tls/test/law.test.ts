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
  parseDisclosedValue,
  parsedEvidenceView,
  type VerifiedEvidence,
  ZK_FETCH_CLAIM_CONTEXT_KEY,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  type ZkFetchSlot,
  zkFetchBodyHashOf,
  zkFetchClaimContextDigestOf,
  zkFetchPolicyHashOf,
  zkFetchPolicySchema,
  zkFetchSubjectHashOf,
} from '@thoth/zk-tls';
import {
  assertClaimMatchesContext,
  assertClaimMatchesDisclosures,
  assertClaimMatchesSubject,
} from '@thoth/zk-tls/attestor';
import { describe, expect, it } from 'vitest';
import { DISCLOSURE_RULES } from './helpers/helper.js';

/** The app id every claim in this suite is for. */
const APP_ID = new Uint8Array(32).fill(0xa1);

/** The signed request parameters of a claim that only needs a subject. */
const REQUEST = { url: 'https://api.github.com/repos/x', method: 'GET', body: '' };

/** The claim context digest every crafted claim's context carries. */
const SIGNED_DIGEST = 'cd'.repeat(32);

/**
 * A signed-shape claim whose parameters/context are JSON I control. The context
 * also carries {@link SIGNED_DIGEST}.
 */
const claimWith = (parameters: unknown, context: object): ProviderClaimData => ({
  provider: 'http',
  parameters: JSON.stringify(parameters),
  owner: '0x445541beb656e0f2359cae936fda3c404c409194',
  timestampS: 1_786_122_944,
  context: JSON.stringify({ [ZK_FETCH_CLAIM_CONTEXT_KEY]: SIGNED_DIGEST, ...context }),
  identifier: '0x1a36ab63aef0496c591235b96b84bac1553ac08752fa8f38e7d088c912c38bb9',
  epoch: 1,
});

/** The disclosed values `parsedEvidenceView` extracts for a crafted claim. */
const disclosedOf = (parameters: unknown, context: object): Readonly<Record<string, string>> => {
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
});

describe('zkFetchPolicySchema disclosure rules', () => {
  const policyWith = (rules: Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'>) => ({
    allowedHosts: ['api.github.com'],
    slots: [{ slot: 0, name: 'distance', parse: 'float' }],
    bodyPolicy: 'ignored',
    ...rules,
  });
  const match = { type: 'regex', value: '(?<distance>[\\d.]+)' } as const;

  it('refuses {{param}} templates in every rule text', () => {
    const templated = [
      policyWith({
        responseMatches: [{ type: 'regex', value: '"{{field}}":(?<distance>[\\d.]+)' }],
        responseRedactions: [],
      }),
      policyWith({ responseMatches: [match], responseRedactions: [{ regex: '{{field}}' }] }),
      policyWith({ responseMatches: [match], responseRedactions: [{ jsonPath: '{{field}}' }] }),
      policyWith({ responseMatches: [match], responseRedactions: [{ xPath: '{{field}}' }] }),
    ];
    for (const policy of templated) {
      expect(() => zkFetchPolicySchema.parse(policy)).toThrow(/templates/);
    }
  });

  it('refuses a rule field the policy cannot declare', () => {
    const policy = {
      ...policyWith(DISCLOSURE_RULES),
      responseMatches: [{ type: 'contains', value: 'error', invert: true }],
    } as never;
    expect(() => zkFetchPolicySchema.parse(policy)).toThrow(/[Uu]nrecognized key/);
  });
});

describe('zkFetchPolicySchema slots', () => {
  it('refuses two entries for one claim slot, so no policy hash is unattestable', () => {
    const policy = {
      allowedHosts: ['api.github.com'],
      slots: [
        { slot: 0, name: 'a', parse: 'int' },
        { slot: 0, name: 'b', parse: 'int' },
      ],
      bodyPolicy: 'ignored',
      ...DISCLOSURE_RULES,
    } as const;
    expect(() => zkFetchPolicySchema.parse(policy)).toThrow(
      /claim slot 0 is declared more than once/,
    );
    expect(() => zkFetchPolicyHashOf(policy as never)).toThrow(/declared more than once/);
  });
});

describe('zkFetchPolicySchema claimVersion', () => {
  const policyWith = (claimVersion: bigint) => ({
    allowedHosts: ['api.github.com'],
    slots: [{ slot: 0, name: 'distance', parse: 'float' }],
    bodyPolicy: 'ignored',
    ...DISCLOSURE_RULES,
    claimVersion,
  });

  it.each([0n, 1n, 255n])('accepts claimVersion %s', (claimVersion) => {
    expect(() => zkFetchPolicySchema.parse(policyWith(claimVersion))).not.toThrow();
  });

  it.each([-1n, 256n])('refuses claimVersion %s outside the claim Uint<8>', (claimVersion) => {
    const parsed = zkFetchPolicySchema.safeParse(policyWith(claimVersion));
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.map((issue) => issue.path)).toEqual([['claimVersion']]);
    }
  });
});

describe('parse law (through deriveClaimFromEvidence)', () => {
  const derived = (value: string, parse: 'int' | 'float'): { present: boolean; value: bigint } => {
    const claim = deriveClaimFromEvidence({
      verified: verifiedOf(claimWith(REQUEST, {}), { v: value }),
      policy: {
        allowedHosts: ['api.github.com'],
        slots: [{ slot: 0, name: 'v', parse }],
        bodyPolicy: 'ignored',
        ...DISCLOSURE_RULES,
      },
      appId: APP_ID,
      holder: new Uint8Array(32).fill(0xc1),
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

  it.each(['12abc', '1,000', ' 12', '12 ', '12\n', '0x10', '+12', '.5', '1.'])(
    'rejects a float outside the decimal grammar: %s',
    (value) => {
      expect(derived(value, 'float')).toEqual({ present: false, value: 0n });
    },
  );

  it('preserves float integers above the double precision limit', () => {
    expect(derived('9007199254740993', 'float')).toEqual({
      present: true,
      value: 9007199254740993n,
    });
  });

  it.each([
    ['9007199254740993.0', 9007199254740993n],
    ['9.007199254740993e15', 9007199254740993n],
    ['0.49999999999999999999', 0n],
    ['9007199254740993.5', 9007199254740994n],
    ['18446744073709551615.4', 18446744073709551615n],
    ['000.005e2', 1n],
    ['5e-1', 1n],
    ['5e-2', 0n],
    ['1e-999999999999999999999', 0n],
    ['0e999999999999999999999', 0n],
  ])('rounds decimal %s exactly', (value, expected) => {
    expect(derived(value, 'float')).toEqual({ present: true, value: expected });
  });

  it('rejects non-numeric or unbounded floats as unpresent', () => {
    expect(derived('abc', 'float').present).toBe(false);
    expect(derived('NaN', 'float').present).toBe(false);
    expect(derived('Infinity', 'float').present).toBe(false);
    expect(derived('-0.5', 'float').present).toBe(false);
    expect(derived('1e30', 'float').present).toBe(false);
    expect(derived('1e999999999999999999999', 'float').present).toBe(false);
    expect(derived('18446744073709551615.5', 'float').present).toBe(false);
    expect(derived('18446744073709551616', 'float').present).toBe(false);
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
    bodyPolicy: 'ignored',
    ...DISCLOSURE_RULES,
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
      holder: new Uint8Array(32).fill(0xc1),
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
      holder: new Uint8Array(32).fill(0xc1),
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
      holder: new Uint8Array(32).fill(0xc1),
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
      policy: {
        ...policy([{ slot: 0, name: 'a', parse: 'int' }]),
        bodyPolicy: 'non-empty',
      },
      appId: APP_ID,
      holder: new Uint8Array(32).fill(0xc1),
      valueSlots: 1,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });
    expect(claim.subjectHash).toEqual(zkFetchSubjectHashOf(request));
  });

  it('takes the salt from the claim context digest the witness signed', () => {
    const verified = verifiedOf(claimWith(REQUEST, {}), {});
    const claim = deriveClaimFromEvidence({
      verified,
      policy: policy([{ slot: 0, name: 'a', parse: 'int', optional: true }]),
      appId: APP_ID,
      holder: new Uint8Array(32).fill(0xc1),
      valueSlots: 1,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });
    expect(Buffer.from(claim.salt).toString('hex')).toBe(SIGNED_DIGEST);
  });

  it.each([
    ['no digest', {}],
    ['a digest that is not 32 bytes of hex', { [ZK_FETCH_CLAIM_CONTEXT_KEY]: 'cd' }],
  ])('throws when the signed context carries %s', (_, context) => {
    const claim = { ...claimWith(REQUEST, {}), context: JSON.stringify(context) };
    expect(() =>
      deriveClaimFromEvidence({
        verified: verifiedOf(claim, {}),
        policy: policy([{ slot: 0, name: 'a', parse: 'int', optional: true }]),
        appId: APP_ID,
        holder: new Uint8Array(32).fill(0xc1),
        valueSlots: 1,
        windowStart: 1_786_122_944n,
        windowEnd: 1_786_122_944n,
      }),
    ).toThrow(/claim context digest/);
  });

  it.each(['__proto__', 'constructor'])(
    'signs a %s slot unpresent when nothing named it is disclosed',
    (name) => {
      const claim = deriveClaimFromEvidence({
        verified: verifiedOf(claimWith(REQUEST, {}), {}),
        policy: policy([{ slot: 1, name, parse: 'bytes', optional: true }]),
        appId: APP_ID,
        holder: new Uint8Array(32).fill(0xc1),
        valueSlots: 1,
        byteSlots: 1,
        windowStart: 1_786_122_944n,
        windowEnd: 1_786_122_944n,
      });
      expect(claim.present).toEqual([false, false]);
      expect(claim.byteValues).toEqual([new Uint8Array(32)]);
    },
  );

  it('reads a disclosed value whose group is named __proto__', () => {
    const disclosed = disclosedOf(
      REQUEST,
      JSON.parse('{"extractedParameters":{"__proto__":"ab"}}'),
    );
    const claim = deriveClaimFromEvidence({
      verified: verifiedOf(claimWith(REQUEST, {}), disclosed),
      policy: policy([{ slot: 1, name: '__proto__', parse: 'bytes' }]),
      appId: APP_ID,
      holder: new Uint8Array(32).fill(0xc1),
      valueSlots: 1,
      byteSlots: 1,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });
    expect(claim.present).toEqual([false, true]);
    expect(claim.byteValues).toEqual([parseDisclosedValue('ab', 'bytes')]);
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
        holder: new Uint8Array(32).fill(0xc1),
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

describe('assertClaimMatchesContext', () => {
  const policy: ZkFetchPolicy = {
    allowedHosts: ['api.github.com'],
    slots: [{ slot: 0, name: 'distance', parse: 'float' }],
    bodyPolicy: 'ignored',
    ...DISCLOSURE_RULES,
  };
  const window = { holder: new Uint8Array(32).fill(7), windowStart: 10n, windowEnd: 20n };
  const digestUnder = (signedPolicy: ZkFetchPolicy, request: typeof REQUEST = REQUEST) =>
    zkFetchClaimContextDigestOf({ policy: signedPolicy, request, ...window });
  const claim = { ...window, salt: Buffer.from(digestUnder(policy), 'hex') } as never;
  const verifiedWith = (context: object) => verifiedOf(claimWith(REQUEST, context), {});

  it('accepts evidence that signed the claim context digest', () => {
    const verified = verifiedWith({ [ZK_FETCH_CLAIM_CONTEXT_KEY]: digestUnder(policy) });
    assertClaimMatchesContext({ claim, verified, policy });
  });

  it('rejects a digest signed under another policy', () => {
    const other = { ...policy, allowedHosts: ['example.com'] };
    const verified = verifiedWith({ [ZK_FETCH_CLAIM_CONTEXT_KEY]: digestUnder(other) });
    expect(() => assertClaimMatchesContext({ claim, verified, policy })).toThrow(
      /does not carry this claim's claim context digest/,
    );
  });

  it('rejects a digest signed over another path or body than the signed request', () => {
    for (const other of [
      { ...REQUEST, url: 'https://api.github.com/repos/y' },
      { ...REQUEST, body: 'other' },
    ]) {
      const verified = verifiedWith({ [ZK_FETCH_CLAIM_CONTEXT_KEY]: digestUnder(policy, other) });
      expect(() => assertClaimMatchesContext({ claim, verified, policy })).toThrow(
        /does not carry this claim's claim context digest/,
      );
    }
  });

  it('rejects a null, array or non-JSON context', () => {
    for (const context of [null, []]) {
      const verified = verifiedOf(
        { ...claimWith(REQUEST, {}), context: JSON.stringify(context) },
        {},
      );
      expect(() => assertClaimMatchesContext({ claim, verified, policy })).toThrow(
        /carries no claim context digest/,
      );
    }
    const verified = verifiedOf({ ...claimWith(REQUEST, {}), context: 'not json' }, {});
    expect(() => assertClaimMatchesContext({ claim, verified, policy })).toThrow(/not valid JSON/);
  });
});

describe('assertClaimMatchesDisclosures', () => {
  const policy = (slots: ZkFetchPolicy['slots']): ZkFetchPolicy => ({
    allowedHosts: ['api.github.com'],
    slots,
    bodyPolicy: 'ignored',
    ...DISCLOSURE_RULES,
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

  it('rejects a __proto__ slot certified present when nothing named it is disclosed', () => {
    expect(() =>
      assertClaimMatchesDisclosures({
        claim: {
          values: [0n],
          present: [false, true],
          byteValues: [parseDisclosedValue('[object Object]', 'bytes')],
        } as never,
        disclosures: {},
        policy: policy([{ slot: 1, name: '__proto__', parse: 'bytes' }]),
      }),
    ).toThrow(/does not match the disclosed value/);
  });

  it('checks a hex byte slot against its decoded disclosure', () => {
    const slots: ZkFetchPolicy['slots'] = [{ slot: 1, name: 'id', parse: 'hex' }];
    assertClaimMatchesDisclosures({
      claim: {
        values: [0n],
        present: [false, true],
        byteValues: [parseDisclosedValue('abcd', 'hex')],
      } as never,
      disclosures: { id: '0xABCD' },
      policy: policy(slots),
    });
    expect(() =>
      assertClaimMatchesDisclosures({
        claim: {
          values: [0n],
          present: [false, true],
          byteValues: [new Uint8Array(32)],
        } as never,
        disclosures: { id: 'abcd' },
        policy: policy(slots),
      }),
    ).toThrow(/does not match the disclosed value/);
  });
});

describe('assertEvidenceMatchesPolicy', () => {
  const policy: ZkFetchPolicy = {
    allowedHosts: ['api.github.com'],
    slots: [{ slot: 0, name: 'distance', parse: 'float' }],
    bodyPolicy: 'ignored',
    ...DISCLOSURE_RULES,
  };

  const verified = (url: string, method = 'GET', body = ''): VerifiedEvidence =>
    verifiedOf(
      claimWith(
        { url, method, body, ...DISCLOSURE_RULES },
        { extractedParameters: { distance: '12.4' } },
      ),
      {
        distance: '12.4',
      },
    );

  it('drops the removed unsigned response-size policy', () => {
    const parsed = zkFetchPolicySchema.parse({ ...policy, maxResponseBytes: 4 });
    expect(parsed).not.toHaveProperty('maxResponseBytes');
    expect(zkFetchPolicyHashOf(parsed)).toEqual(zkFetchPolicyHashOf(policy));
    for (const responseText of [undefined, '', 'x'.repeat(100)]) {
      const evidence = { ...verified('https://api.github.com/x'), responseText };
      expect(assertEvidenceMatchesPolicy(evidence, parsed)).toBe('api.github.com');
    }
  });

  it('rejects a required __proto__ slot when nothing named it is disclosed', () => {
    const protoPolicy: ZkFetchPolicy = {
      ...policy,
      slots: [{ slot: 0, name: '__proto__', parse: 'bytes' }],
    };
    expect(() =>
      assertEvidenceMatchesPolicy(verified('https://api.github.com/x'), protoPolicy),
    ).toThrow(/did not disclose a parseable value/);
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
    const suffixes: Pick<ZkFetchPolicy, 'allowedHosts'> = { allowedHosts: ['GitHub.COM'] };
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
      claimWith(
        { url: 'https://api.github.com/x', method: 'GET', body: '', ...DISCLOSURE_RULES },
        { extractedParameters: {} },
      ),
      {},
    );
    expect(() => assertEvidenceMatchesPolicy(missing, policy)).toThrow(
      /not disclose a parseable value/,
    );
    const unparseable = verifiedOf(
      claimWith(
        { url: 'https://api.github.com/x', method: 'GET', body: '', ...DISCLOSURE_RULES },
        { extractedParameters: { distance: 'abc' } },
      ),
      { distance: 'abc' },
    );
    expect(() => assertEvidenceMatchesPolicy(unparseable, policy)).toThrow(
      /not disclose a parseable value/,
    );
  });

  it('accepts signed rules whose keys are sorted against a policy keyed otherwise', () => {
    const keyedOtherwise: ZkFetchPolicy = {
      ...policy,
      responseMatches: [
        { value: '(?<distance>[\\d.]+)', type: 'regex' },
        { value: 'moving_time', type: 'contains' },
      ],
      responseRedactions: [{ regex: 'a', jsonPath: '' }, { jsonPath: '$.b' }],
    };
    // Reclaim signs the parameters with sorted keys.
    const signed = {
      url: 'https://api.github.com/x',
      method: 'GET',
      body: '',
      responseMatches: [
        { type: 'contains', value: 'moving_time' },
        { type: 'regex', value: '(?<distance>[\\d.]+)' },
      ],
      responseRedactions: [{ jsonPath: '', regex: 'a' }, { jsonPath: '$.b' }],
    };
    const evidence = verifiedOf(claimWith(signed, { extractedParameters: { distance: '12.4' } }), {
      distance: '12.4',
    });
    expect(assertEvidenceMatchesPolicy(evidence, keyedOtherwise)).toBe('api.github.com');
  });

  it('allows an optional slot to be absent', () => {
    const optional: ZkFetchPolicy = {
      ...policy,
      slots: [{ slot: 0, name: 'distance', parse: 'float', optional: true }],
    };
    const missing = verifiedOf(
      claimWith(
        { url: 'https://api.github.com/x', method: 'GET', body: '', ...DISCLOSURE_RULES },
        { extractedParameters: {} },
      ),
      {},
    );
    expect(assertEvidenceMatchesPolicy(missing, optional)).toBe('api.github.com');
  });

  describe('body policy', () => {
    it('applies the chosen mode to every method', () => {
      const ignored: ZkFetchPolicy = { ...policy, bodyPolicy: 'ignored' };
      expect(assertEvidenceMatchesPolicy(verified('https://api.github.com/x'), ignored)).toBe(
        'api.github.com',
      );
      expect(
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x', 'POST'), ignored),
      ).toBe('api.github.com');
      expect(() =>
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x', 'POST', '{}'), ignored),
      ).toThrow(/body/);

      const nonEmpty: ZkFetchPolicy = { ...policy, bodyPolicy: 'non-empty' };
      expect(
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x', 'GET', '{}'), nonEmpty),
      ).toBe('api.github.com');
      expect(() =>
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x', 'GET'), nonEmpty),
      ).toThrow(/body/);
      expect(
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x', 'POST', '{}'), nonEmpty),
      ).toBe('api.github.com');
    });

    it('pins the exact signed body', () => {
      const pinned: ZkFetchPolicy = {
        ...policy,
        bodyPolicy: { sha256: zkFetchBodyHashOf('{}') },
      };
      expect(
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x', 'POST', '{}'), pinned),
      ).toBe('api.github.com');
      expect(() =>
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x', 'POST'), pinned),
      ).toThrow(/body/);
      expect(() =>
        assertEvidenceMatchesPolicy(
          verified('https://api.github.com/x', 'POST', '{"x":1}'),
          pinned,
        ),
      ).toThrow(/body/);
    });

    it('treats a Buffer pin as the same bytes', () => {
      const pinned: ZkFetchPolicy = {
        ...policy,
        bodyPolicy: { sha256: Buffer.from(zkFetchBodyHashOf('{}')) },
      };
      expect(
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x', 'POST', '{}'), pinned),
      ).toBe('api.github.com');
    });

    it('refuses a signed body with a redaction marker under every mode', () => {
      const starred = verified('https://api.github.com/x', 'POST', '{"q":*********}');
      const pinned = { sha256: zkFetchBodyHashOf('{"q":123456789}') };
      for (const bodyPolicy of ['non-empty', 'ignored', pinned] as const) {
        expect(() => assertEvidenceMatchesPolicy(starred, { ...policy, bodyPolicy })).toThrow(
          /cannot contain \*/,
        );
      }
    });

    it('refuses the empty body as a pin', () => {
      expect(() =>
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x'), {
          ...policy,
          bodyPolicy: { sha256: zkFetchBodyHashOf('') },
        }),
      ).toThrow(/ignored/);
    });

    it('refuses a policy without a body policy', () => {
      const missing = { ...policy, bodyPolicy: undefined } as unknown as ZkFetchPolicy;
      expect(() =>
        assertEvidenceMatchesPolicy(verified('https://api.github.com/x'), missing),
      ).toThrow(/bodyPolicy/);
    });
  });
});

describe('byte value parse rules', () => {
  const policy = (slots: ZkFetchPolicy['slots']): ZkFetchPolicy => ({
    allowedHosts: ['api.github.com'],
    slots,
    bodyPolicy: 'ignored',
    ...DISCLOSURE_RULES,
  });

  const padded = (value: string): Uint8Array => {
    const out = new Uint8Array(32);
    out.set(new TextEncoder().encode(value));
    return out;
  };

  const pad32 = (bytes: Uint8Array): Uint8Array => {
    const out = new Uint8Array(32);
    out.set(bytes);
    return out;
  };

  const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

  const PARAMS = { ...REQUEST, extractedParameters: { id: 'abc' } };

  const derive = (slots: ZkFetchPolicy['slots'], id: string) =>
    deriveClaimFromEvidence({
      verified: verifiedOf(claimWith(PARAMS, {}), { id }),
      policy: policy(slots),
      appId: APP_ID,
      holder: new Uint8Array(32).fill(0xc1),
      valueSlots: 1,
      byteSlots: 1,
      windowStart: 1_786_122_944n,
      windowEnd: 1_786_122_944n,
    });

  it('parses a disclosed string into its UTF-8 bytes, zero-padded to 32', () => {
    expect(parseDisclosedValue('abc', 'bytes')).toEqual(padded('abc'));
    expect(parseDisclosedValue('', 'bytes')).toEqual(new Uint8Array(32));
    // The limit counts bytes, not characters.
    const accented = parseDisclosedValue('é', 'bytes');
    expect(accented?.slice(0, 2)).toEqual(new Uint8Array([0xc3, 0xa9]));
    expect(accented?.slice(2)).toEqual(new Uint8Array(30));
  });

  it('rejects a string longer than 32 bytes and accepts exactly 32', () => {
    expect(parseDisclosedValue('a'.repeat(33), 'bytes')).toBeNull();
    expect(parseDisclosedValue('a'.repeat(32), 'bytes')).toHaveLength(32);
  });

  it('derives the byte value and its flag into the byte region', () => {
    const claim = derive([{ slot: 1, name: 'id', parse: 'bytes' }], 'abc');
    expect(claim.present).toEqual([false, true]);
    expect(claim.values).toEqual([0n]);
    expect(claim.byteValues[0]).toEqual(padded('abc'));
  });

  it('leaves an over-long disclosure unpresent, like an unparseable number', () => {
    const claim = derive([{ slot: 1, name: 'id', parse: 'bytes', optional: true }], 'a'.repeat(33));
    expect(claim.present).toEqual([false, false]);
    expect(claim.byteValues[0]).toEqual(new Uint8Array(32));
  });

  it('rejects a rule that targets the wrong region', () => {
    expect(() => derive([{ slot: 0, name: 'id', parse: 'bytes' }], 'abc')).toThrow(
      /targets a numeric slot/,
    );
    expect(() => derive([{ slot: 0, name: 'id', parse: 'hex' }], 'abcd')).toThrow(
      /targets a numeric slot/,
    );
    expect(() => derive([{ slot: 1, name: 'id', parse: 'int' }], 'abc')).toThrow(
      /targets a byte slot/,
    );
  });

  it('is pinned by the policy hash', () => {
    const intPolicy = policy([{ slot: 0, name: 'id', parse: 'int' }]);
    const bytesPolicy = policy([{ slot: 0, name: 'id', parse: 'bytes' }]);
    const pinnedPolicy = policy([{ slot: 0, name: 'id', parse: 'bytes', length: 32 }]);
    expect(hex(zkFetchPolicyHashOf(bytesPolicy))).not.toEqual(hex(zkFetchPolicyHashOf(intPolicy)));
    expect(hex(zkFetchPolicyHashOf(pinnedPolicy))).not.toEqual(
      hex(zkFetchPolicyHashOf(bytesPolicy)),
    );
  });

  it('collapses trailing NULs and unpaired surrogates (the mapping is not injective)', () => {
    expect(parseDisclosedValue('a\u0000', 'bytes')).toEqual(parseDisclosedValue('a', 'bytes'));
    const lone = parseDisclosedValue('\uD800', 'bytes');
    // TextEncoder replaces an unpaired surrogate with U+FFFD (EF BF BD).
    expect(lone?.slice(0, 3)).toEqual(new Uint8Array([0xef, 0xbf, 0xbd]));
    expect(lone?.slice(3)).toEqual(new Uint8Array(29));
    expect(lone).toEqual(parseDisclosedValue('\uFFFD', 'bytes'));
  });

  it('decodes hex case-insensitively with an optional 0x prefix', () => {
    const expected = Uint8Array.from([0xab, 0xcd]);
    for (const form of ['abcd', 'ABCD', 'AbCd', '0xabcd', '0XABCD', '0xAbCd']) {
      expect(parseDisclosedValue(form, 'hex')?.slice(0, 2)).toEqual(expected);
      expect(parseDisclosedValue(form, 'hex')?.slice(2)).toEqual(new Uint8Array(30));
    }
  });

  it('rejects hex separators, whitespace, and other non-data characters', () => {
    const forms = ['', '0x', 'abc', 'ab:cd', 'ab-cd', 'ab cd', 'ab,cd', 'ab.cd', 'abcd\n', 'abcz'];
    for (const form of forms) {
      expect(parseDisclosedValue(form, 'hex')).toBeNull();
    }
  });

  it('decodes base64 across padding and alphabet variants', () => {
    for (const bytes of [Uint8Array.from([0xfb]), Uint8Array.from([0xfb, 0xef, 0xbe])]) {
      const std = Buffer.from(bytes).toString('base64');
      const url = Buffer.from(bytes).toString('base64url');
      expect(std).not.toBe(url); // the alphabets differ, so the mapping is exercised
      for (const form of [std, url, std.replace(/=+$/, '')]) {
        expect(parseDisclosedValue(form, 'base64')).toEqual(pad32(bytes));
      }
    }
  });

  it('rejects wrapped, partially padded, or non-canonical base64', () => {
    const forms = ['', 'YQ=', 'YQ\n', 'Y Q==', 'YQ== ', 'A', 'AB==', '====', 'YQ!='];
    for (const form of forms) {
      expect(parseDisclosedValue(form, 'base64')).toBeNull();
    }
  });

  it('pins the exact decoded length when the slot declares one', () => {
    const exact = derive([{ slot: 1, name: 'id', parse: 'hex', length: 2 }], 'abcd');
    expect(exact.present).toEqual([false, true]);
    expect(exact.byteValues[0]?.slice(0, 2)).toEqual(Uint8Array.from([0xab, 0xcd]));
    const short = derive(
      [{ slot: 1, name: 'id', parse: 'hex', length: 1, optional: true }],
      'abcd',
    );
    expect(short.present).toEqual([false, false]);
    expect(short.byteValues[0]).toEqual(new Uint8Array(32));
  });

  it('pins the exact UTF-8 length of a bytes slot', () => {
    const exact = derive([{ slot: 1, name: 'id', parse: 'bytes', length: 3 }], 'abc');
    expect(exact.present).toEqual([false, true]);
    const short = derive(
      [{ slot: 1, name: 'id', parse: 'bytes', length: 4, optional: true }],
      'abc',
    );
    expect(short.present).toEqual([false, false]);
  });

  it('rejects a length pin on a numeric rule or outside 1..32', () => {
    const policyWith = (slot: ZkFetchSlot): ZkFetchPolicy =>
      zkFetchPolicySchema.parse({
        allowedHosts: ['api.github.com'],
        slots: [slot],
        bodyPolicy: 'ignored',
        ...DISCLOSURE_RULES,
      });
    expect(() => policyWith({ slot: 0, name: 'id', parse: 'int', length: 4 })).toThrow(/length/);
    expect(() => policyWith({ slot: 1, name: 'id', parse: 'hex', length: 0 })).toThrow();
    expect(() => policyWith({ slot: 1, name: 'id', parse: 'hex', length: 33 })).toThrow();
    expect(policyWith({ slot: 1, name: 'id', parse: 'hex', length: 32 }).slots[0]?.length).toBe(32);
  });
});
