// The tlsn@1 law offline, under a zkFetch-shaped policy: the attestor reads only the
// redacted response, every check rejects its own mutation, and the policy schema takes
// the zkFetch policies tlsn@1 can honour.

import type { Claim } from '@txpipe/thoth-core/claim';
import { claimToMessage } from '@txpipe/thoth-core/claim';
import { describe, expect, it } from 'vitest';
import { tlsnAttestor } from '../src/attestor/index.js';
import { redactedResponseText } from '../src/http.js';
import {
  deriveTlsnClaim,
  observePresentation,
  type TlsnPolicy,
  tlsnClaimContextDigestOf,
  tlsnPolicyHashOf,
  tlsnPolicySchema,
  tlsnSubjectHashOf,
  verifiedPresentationSchema,
} from '../src/index.js';
import { requestReveals, responseReveals } from '../src/redact.js';
import {
  APP_ID,
  evidenceOf,
  fakeKey,
  fakeVerifier,
  HOLDER,
  NOTARY_KEY,
  POLICY,
  PRIVATE_EMAIL,
  RESPONSE_BODY,
  rangeOf,
  request,
  response,
  SECRET,
  URL_,
  verifiedJson,
  WINDOW,
} from './helpers.js';

const contextFor = (
  options: { policy?: TlsnPolicy; holder?: Uint8Array; url?: string; body?: string } = {},
) =>
  tlsnClaimContextDigestOf({
    policy: options.policy ?? POLICY,
    request: { method: 'GET', url: options.url ?? URL_, body: options.body ?? '' },
    holder: options.holder ?? HOLDER,
    ...WINDOW,
  });

const attestor = tlsnAttestor({
  id: 'tlsn-1',
  keyPair: fakeKey('tlsn-1'),
  notaryKey: NOTARY_KEY,
  verifier: fakeVerifier,
});

/** The honest input for a verifier output: the claim the client would derive and propose. */
const inputFor = (verified: ReturnType<typeof verifiedJson>, policy: TlsnPolicy = POLICY) => {
  const observation = observePresentation(verifiedPresentationSchema.parse(verified), policy);
  const claim = deriveTlsnClaim({
    observation,
    policy,
    appId: APP_ID,
    holder: HOLDER,
    valueSlots: 2,
    byteSlots: 1,
    ...WINDOW,
  });
  return { policy, evidence: evidenceOf(verified), claim };
};

const honest = () => inputFor(verifiedJson({ claimContext: contextFor() }));

/** Replace the evidence of the honest input; the proposal stays the honest one. */
const withEvidence = (options: Parameters<typeof verifiedJson>[0]) => ({
  ...honest(),
  evidence: evidenceOf(verifiedJson(options)),
});

describe('tlsn@1 attestor', () => {
  it('signs the claim it reads from the redacted response', async () => {
    const attestation = await attestor.attest(honest());
    expect(attestation.claim.values).toEqual([1234n, 18446744073709551615n]);
    expect(attestation.claim.present).toEqual([true, true, true]);
    expect(
      Buffer.from(attestation.claim.byteValues[0] as Uint8Array)
        .subarray(0, 7)
        .toString(),
    ).toBe('octocat');
    expect(attestation.claim.salt).toEqual(contextFor());
    expect(attestation.claim.subjectHash).toEqual(tlsnSubjectHashOf({ method: 'GET', url: URL_ }));
    expect(attestation.message).toEqual(claimToMessage(attestation.claim));
    expect(attestation.signature).toBe(`sig:${attestation.message.length}`);
  });

  it('never sees the response bytes no redaction selects, nor the secret header', () => {
    const verified = verifiedPresentationSchema.parse(verifiedJson({ claimContext: contextFor() }));
    const text = redactedResponseText(verified.received);
    expect(text).toContain('"stars":1234');
    expect(text).toContain('"login":"octocat"');
    expect(text).not.toContain(PRIVATE_EMAIL);
    expect(text).not.toContain('session=abc');
    expect(Buffer.from(verified.sent.data).toString('latin1')).not.toContain('s3cret');
  });

  it('refuses a presentation from another notary', async () => {
    const input = inputFor(
      verifiedJson({
        claimContext: contextFor(),
        notaryKey: { alg: 'k256', key: `02${'aa'.repeat(32)}` },
      }),
    );
    await expect(attestor.attest(input)).rejects.toThrow(/another notary/);
  });

  it('allows a subdomain of an allowed host, and refuses any other server', async () => {
    await expect(
      attestor.attest(withEvidence({ claimContext: contextFor(), serverName: 'evil.com' })),
    ).rejects.toThrow(/allowlist/);
    await expect(
      attestor.attest(withEvidence({ claimContext: contextFor(), serverName: 'example.com.evil' })),
    ).rejects.toThrow(/allowlist/);
  });

  it('refuses a Host header that is not the attested server', async () => {
    const sent = request({ host: 'other.example.com' });
    await expect(
      attestor.attest(withEvidence({ claimContext: contextFor(), sent })),
    ).rejects.toThrow(/Host/);
  });

  it('refuses a request that does not open with Host then Connection: close', async () => {
    const sent = request({
      head: `GET /repos/x?y=1 HTTP/1.1\r\nConnection: close\r\nHost: ${'api.example.com'}`,
    });
    await expect(
      attestor.attest(withEvidence({ claimContext: contextFor(), sent })),
    ).rejects.toThrow(/first request header/);
    const keepAlive = request({
      head: 'GET /repos/x?y=1 HTTP/1.1\r\nHost: api.example.com\r\nConnection: keep-alive',
    });
    await expect(
      attestor.attest(withEvidence({ claimContext: contextFor(), sent: keepAlive })),
    ).rejects.toThrow(/Connection: close/);
  });

  it('refuses a hidden request line or Host value', async () => {
    const sent = request();
    const hideTarget = [
      [0, rangeOf(sent, '/repos')[0]],
      [rangeOf(sent, '/repos')[1], sent.length],
    ] as const;
    await expect(
      attestor.attest(withEvidence({ claimContext: contextFor(), revealSent: hideTarget })),
    ).rejects.toThrow(/request line/);
    const host = rangeOf(sent, 'api.example.com');
    await expect(
      attestor.attest(
        withEvidence({
          claimContext: contextFor(),
          revealSent: [
            [0, host[0]],
            [host[1], sent.length],
          ],
        }),
      ),
    ).rejects.toThrow(/hides its host/);
  });

  it('refuses a response whose status is hidden or not 2xx', async () => {
    const received = response();
    const all = responseReveals(Buffer.from(received), POLICY.responseRedactions);
    await expect(
      attestor.attest(
        withEvidence({
          claimContext: contextFor(),
          revealReceived: all.filter(([start]) => start > 0),
        }),
      ),
    ).rejects.toThrow(/status line/);
    const notFound = response(RESPONSE_BODY, '404 Not Found');
    await expect(
      attestor.attest(
        withEvidence({
          claimContext: contextFor(),
          received: notFound,
          revealReceived: [[0, notFound.length]],
        }),
      ),
    ).rejects.toThrow(/not 2xx/);
  });

  it('refuses a response whose matched field is not revealed', async () => {
    const received = response();
    const reveals = responseReveals(Buffer.from(received), [{ jsonPath: '$.stars' }]);
    await expect(
      attestor.attest(withEvidence({ claimContext: contextFor(), revealReceived: reveals })),
    ).rejects.toThrow(/does not match/);
  });

  it('refuses an observation outside the window', async () => {
    await expect(
      attestor.attest(
        withEvidence({ claimContext: contextFor(), time: Number(WINDOW.windowEnd) + 1 }),
      ),
    ).rejects.toThrow(/outside the claim window/);
  });

  it('refuses a presentation signed for another holder', async () => {
    const other = contextFor({ holder: new Uint8Array(32).fill(1) });
    await expect(attestor.attest(withEvidence({ claimContext: other }))).rejects.toThrow(
      /claim context digest/,
    );
  });

  it('refuses an attestation without exactly one claim context extension', async () => {
    await expect(
      attestor.attest(withEvidence({ claimContext: contextFor(), extensions: [] })),
    ).rejects.toThrow(/exactly one extension/);
  });

  it('refuses a proposal whose value or salt differs from what it reads', async () => {
    const input = honest();
    const claim: Claim<number, number> = { ...input.claim, values: [1235n, 18446744073709551615n] };
    await expect(attestor.attest({ ...input, claim })).rejects.toThrow(/does not say/);
    await expect(
      attestor.attest({ ...input, claim: { ...input.claim, salt: new Uint8Array(32) } }),
    ).rejects.toThrow(/salt/);
  });

  it('refuses a missing required value, and signs an optional one unpresent', async () => {
    const received = response('{"stars":1234,"big":1,"owner":{"name":"x"}}');
    const policy: TlsnPolicy = {
      ...POLICY,
      responseMatches: POLICY.responseMatches.slice(0, 2),
      responseRedactions: [{ jsonPath: '$.stars' }, { jsonPath: '$.big' }],
      slots: [...POLICY.slots.slice(0, 2), { slot: 2, name: 'stars', parse: 'bytes' }],
    };
    // A required byte slot whose value is too long is not certifiable.
    const required: TlsnPolicy = {
      ...policy,
      slots: [...POLICY.slots.slice(0, 2), { slot: 2, name: 'stars', parse: 'bytes', length: 3 }],
    };
    await expect(
      attestor.attest({
        ...honest(),
        policy: required,
        evidence: evidenceOf(
          verifiedJson({ claimContext: contextFor({ policy: required }), received, policy }),
        ),
      }),
    ).rejects.toThrow(/certifiable value/);
    const optional: TlsnPolicy = {
      ...policy,
      slots: [
        ...POLICY.slots.slice(0, 2),
        { slot: 2, name: 'stars', parse: 'bytes', length: 3, optional: true },
      ],
    };
    const attestation = await attestor.attest(
      inputFor(
        verifiedJson({ claimContext: contextFor({ policy: optional }), received, policy }),
        optional,
      ),
    );
    expect(attestation.claim.present).toEqual([true, true, false]);
  });

  it('enforces the body policy on the revealed body', async () => {
    const body = '{"q":1}';
    const sent = `POST /repos/x?y=1 HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
    await expect(
      attestor.attest(
        withEvidence({ claimContext: contextFor(), sent, revealSent: [[0, sent.length]] }),
      ),
    ).rejects.toThrow(/must be empty/);
  });

  it('reads a chunked response through its framing', async () => {
    const body = RESPONSE_BODY;
    const received = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n${(20).toString(16)}\r\n${body.slice(0, 20)}\r\n${(body.length - 20).toString(16)}\r\n${body.slice(20)}\r\n0\r\n\r\n`;
    const attestation = await attestor.attest(
      inputFor(verifiedJson({ claimContext: contextFor(), received })),
    );
    expect(attestation.claim.values[0]).toBe(1234n);
  });
});

describe('tlsn@1 redaction', () => {
  it('reveals the request except the secret header value', () => {
    const sent = request();
    const [start, end] = rangeOf(sent, SECRET);
    expect(requestReveals(Buffer.from(sent), new Set(['authorization']))).toEqual([
      [0, start],
      [end, sent.length],
    ]);
    expect(() => requestReveals(Buffer.from(sent), new Set(['host']))).toThrow(/cannot be secret/);
  });

  it('reveals the status line, framing, Date and Content-Type, and each jsonPath key and value', () => {
    const received = response();
    const text = (ranges: readonly (readonly [number, number])[]) =>
      ranges.map(([start, end]) => received.slice(start, end));
    expect(text(responseReveals(Buffer.from(received), [{ jsonPath: '$.owner.login' }]))).toEqual([
      'HTTP/1.1 200 OK',
      'Date: Tue, 24 Nov 2026 10:00:00 GMT',
      'Content-Type: application/json',
      '\r\n\r\n',
      '"login":"octocat"',
    ]);
  });

  it('reveals a regex redaction, or the regex match inside a jsonPath selection', () => {
    const received = response();
    const last = (redaction: { jsonPath?: string; regex?: string }) =>
      responseReveals(Buffer.from(received), [redaction])
        .map(([start, end]) => received.slice(start, end))
        .at(-1);
    expect(last({ regex: '"stars":\\d+' })).toBe('"stars":1234');
    expect(last({ jsonPath: '$.owner', regex: '"login":"[^"]+"' })).toBe('"login":"octocat"');
  });

  it('refuses a redaction that selects nothing', () => {
    expect(() => responseReveals(Buffer.from(response()), [{ jsonPath: '$.nope' }])).toThrow(
      /selects nothing/,
    );
  });
});

describe('tlsn@1 policy', () => {
  it('accepts a zkFetch policy it can honour', () => {
    expect(() => tlsnPolicySchema.parse(POLICY)).not.toThrow();
  });

  it.each([
    ['an xPath redaction', { responseRedactions: [{ xPath: '//div' }] }, /xPath/],
    ['a host with a port', { allowedHosts: ['example.com:8443'] }, /without a port/],
    ['a slot no group names', { slots: [{ slot: 0, name: 'nope', parse: 'int' }] }, /named group/],
    ['a template', { responseMatches: [{ type: 'regex', value: '{{x}}' }] }, /templates/],
    ['an unknown field', { hiddenHeaders: ['authorization'] }, /unrecognized/i],
    ['a regex RE2 refuses', { responseMatches: [{ type: 'regex', value: '(?=x)' }] }, /RE2/],
  ])('refuses %s', (_name, change, message) => {
    expect(() => tlsnPolicySchema.parse({ ...POLICY, ...change })).toThrow(message);
  });

  it('hashes the same policy the same regardless of order and defaults', () => {
    const reordered: TlsnPolicy = {
      ...POLICY,
      allowedHosts: ['EXAMPLE.com'],
      slots: [...POLICY.slots].reverse(),
      responseMatches: [...POLICY.responseMatches].reverse(),
      claimVersion: 1n,
    };
    expect(tlsnPolicyHashOf(reordered)).toEqual(tlsnPolicyHashOf(POLICY));
    expect(tlsnPolicyHashOf({ ...POLICY, bodyPolicy: 'non-empty' })).not.toEqual(
      tlsnPolicyHashOf(POLICY),
    );
    expect(Buffer.from(tlsnPolicyHashOf(POLICY)).toString('hex')).toBe(
      '9ceda01340a2f243a57c844ce7f2ff5c35ad1fba8d75df23844d7f9128fd9a9b',
    );
  });
});
