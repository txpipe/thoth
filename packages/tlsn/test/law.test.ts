// The tlsn@1 law offline: every check rejects its own mutation, and the attestor
// signs the claim it derived from the presentation.

import type { Claim } from '@txpipe/thoth-core/claim';
import { claimToMessage } from '@txpipe/thoth-core/claim';
import { describe, expect, it } from 'vitest';
import { tlsnAttestor } from '../src/attestor/index.js';
import {
  deriveTlsnClaim,
  observePresentation,
  type TlsnPolicy,
  tlsnClaimContextDigestOf,
  tlsnPolicyHashOf,
  tlsnSubjectHashOf,
  tlsnSubjectRequestOf,
  verifiedPresentationSchema,
} from '../src/index.js';
import { parseStrictJson } from '../src/json.js';
import {
  APP_ID,
  evidenceOf,
  fakeKey,
  fakeVerifier,
  HOLDER,
  HOST,
  NOTARY_KEY,
  POLICY,
  RESPONSE_BODY,
  rangeOf,
  request,
  response,
  verifiedJson,
  WINDOW,
} from './helpers.js';

const URL_ = `https://${HOST}/repos/x?y=1`;

const contextFor = (
  options: { policy?: TlsnPolicy; holder?: Uint8Array; windowEnd?: bigint } = {},
) =>
  tlsnClaimContextDigestOf({
    policy: options.policy ?? POLICY,
    request: tlsnSubjectRequestOf({ url: URL_ }),
    holder: options.holder ?? HOLDER,
    windowStart: WINDOW.windowStart,
    windowEnd: options.windowEnd ?? WINDOW.windowEnd,
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

describe('tlsn@1 attestor', () => {
  it('signs the claim it derives from an honest presentation', async () => {
    const input = honest();
    const attestation = await attestor.attest(input);
    expect(attestation.claim.values).toEqual([1234n, 18446744073709551615n]);
    expect(attestation.claim.present).toEqual([true, true, true]);
    expect(
      Buffer.from(attestation.claim.byteValues[0] as Uint8Array)
        .subarray(0, 7)
        .toString(),
    ).toBe('octocat');
    expect(attestation.claim.salt).toEqual(contextFor());
    expect(attestation.claim.subjectHash).toEqual(
      tlsnSubjectHashOf(tlsnSubjectRequestOf({ url: URL_ })),
    );
    expect(attestation.message).toEqual(claimToMessage(attestation.claim));
    expect(attestation.signature).toBe(`sig:${attestation.message.length}`);
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

  it('refuses a server outside the allowlist', async () => {
    const verified = verifiedJson({ claimContext: contextFor(), serverName: 'evil.example.com' });
    const input = { ...honest(), evidence: evidenceOf(verified) };
    await expect(attestor.attest(input)).rejects.toThrow(/allowlist/);
  });

  it('refuses a Host header that is not the attested server', async () => {
    const sent = request({ host: 'other.example.com' });
    const verified = verifiedJson({
      claimContext: contextFor(),
      sent,
      hiddenSent: [rangeOf(sent, 'Bearer s3cret')],
    });
    const input = { ...honest(), evidence: evidenceOf(verified) };
    await expect(attestor.attest(input)).rejects.toThrow(/Host/);
  });

  it('refuses a hidden header value the policy does not allow', async () => {
    const input = honest();
    const policy = { ...POLICY, hiddenHeaders: [] };
    await expect(attestor.attest({ ...input, policy })).rejects.toThrow(/does not allow/);
  });

  it('refuses a hidden request line', async () => {
    const sent = request();
    const verified = verifiedJson({
      claimContext: contextFor(),
      hiddenSent: [rangeOf(sent, '/repos/x')],
    });
    await expect(attestor.attest({ ...honest(), evidence: evidenceOf(verified) })).rejects.toThrow(
      /request line/,
    );
  });

  it('refuses a response with hidden bytes', async () => {
    const received = response();
    const verified = verifiedJson({
      claimContext: contextFor(),
      hiddenReceived: [rangeOf(received, 'octocat')],
    });
    await expect(attestor.attest({ ...honest(), evidence: evidenceOf(verified) })).rejects.toThrow(
      /hidden bytes/,
    );
  });

  it('refuses an observation outside the window', async () => {
    const verified = verifiedJson({
      claimContext: contextFor(),
      time: Number(WINDOW.windowEnd) + 1,
    });
    await expect(attestor.attest({ ...honest(), evidence: evidenceOf(verified) })).rejects.toThrow(
      /outside the claim window/,
    );
  });

  it('refuses a presentation signed for another holder', async () => {
    const other = contextFor({ holder: new Uint8Array(32).fill(1) });
    const input = honest();
    const verified = verifiedJson({ claimContext: other });
    await expect(attestor.attest({ ...input, evidence: evidenceOf(verified) })).rejects.toThrow(
      /claim context digest/,
    );
  });

  it('refuses an attestation without exactly one claim context extension', async () => {
    const verified = verifiedJson({ claimContext: contextFor(), extensions: [] });
    await expect(attestor.attest({ ...honest(), evidence: evidenceOf(verified) })).rejects.toThrow(
      /exactly one extension/,
    );
  });

  it('refuses a proposal whose value differs from the response', async () => {
    const input = honest();
    const claim: Claim<number, number> = { ...input.claim, values: [1235n, 18446744073709551615n] };
    await expect(attestor.attest({ ...input, claim })).rejects.toThrow(/does not say/);
  });

  it('refuses a proposal whose salt differs', async () => {
    const input = honest();
    await expect(
      attestor.attest({ ...input, claim: { ...input.claim, salt: new Uint8Array(32) } }),
    ).rejects.toThrow(/salt/);
  });

  it('refuses a response missing a required field, and signs an optional one unpresent', async () => {
    const received = response('{"stars":1234,"big":1}');
    const verified = verifiedJson({ claimContext: contextFor(), received });
    await expect(attestor.attest({ ...honest(), evidence: evidenceOf(verified) })).rejects.toThrow(
      /no certifiable value/,
    );

    const policy: TlsnPolicy = {
      ...POLICY,
      slots: POLICY.slots.map((slot) => (slot.slot === 2 ? { ...slot, optional: true } : slot)),
    };
    const optional = verifiedJson({ claimContext: contextFor({ policy }), received });
    const attestation = await attestor.attest(inputFor(optional, policy));
    expect(attestation.claim.present).toEqual([true, true, false]);
  });

  it('refuses a status other than the policy one', async () => {
    const verified = verifiedJson({
      claimContext: contextFor(),
      received: response(RESPONSE_BODY, '404 Not Found'),
    });
    await expect(attestor.attest({ ...honest(), evidence: evidenceOf(verified) })).rejects.toThrow(
      /status/,
    );
  });

  it('reads a chunked response', async () => {
    const body = RESPONSE_BODY;
    const received = `HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n${(10).toString(16)}\r\n${body.slice(0, 10)}\r\n${(body.length - 10).toString(16)}\r\n${body.slice(10)}\r\n0\r\n\r\n`;
    const attestation = await attestor.attest(
      inputFor(verifiedJson({ claimContext: contextFor(), received })),
    );
    expect(attestation.claim.values[0]).toBe(1234n);
  });
});

describe('strict JSON', () => {
  it('refuses duplicate keys, which parsers resolve differently', () => {
    expect(() => parseStrictJson('{"stars":1,"stars":2}')).toThrow(/duplicate key/);
  });

  it('keeps number source text', () => {
    expect(parseStrictJson('{"n":18446744073709551615}')).toEqual({
      type: 'object',
      members: new Map([['n', { type: 'number', raw: '18446744073709551615' }]]),
    });
  });
});

describe('tlsn@1 policy hash', () => {
  it('is pinned for one fixed policy, and ignores order and defaults', () => {
    expect(Buffer.from(tlsnPolicyHashOf(POLICY)).toString('hex')).toBe(
      '15e6e7e10d7aae237d3f99de76eeeed15a2bc016062fc54ecfe816e93c8aeed3',
    );
    const reordered: TlsnPolicy = {
      ...POLICY,
      allowedHosts: [HOST.toUpperCase()],
      hiddenHeaders: ['Authorization', 'authorization'],
      status: 200,
      slots: [...POLICY.slots].reverse(),
    };
    expect(tlsnPolicyHashOf(reordered)).toEqual(tlsnPolicyHashOf(POLICY));
    expect(tlsnPolicyHashOf({ ...POLICY, status: 201 })).not.toEqual(tlsnPolicyHashOf(POLICY));
  });
});
