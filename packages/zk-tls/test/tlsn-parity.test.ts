// Parity between zkFetch and the tlsn@1 prototype: on the same response and the same
// disclosure rules, tlsn@1 reveals exactly the bytes Reclaim's prover reveals, and reads
// exactly the values Reclaim's witness extracts. This runs Reclaim's own code, so it
// lives in the AGPL package rather than in the Apache-2.0 tlsn package.
import {
  CURRENT_ATTESTOR_VERSION,
  logger,
  PROVIDER_CTX,
  providers,
} from '@reclaimprotocol/attestor-core';
import {
  disclosedValuesOf,
  redactedResponseText,
  requestReveals,
  responseReveals,
} from '@txpipe/thoth-tlsn/disclosure';
import { describe, expect, it } from 'vitest';

const HOST = 'api.example.com';
const URL_ = `https://${HOST}/repos/x?y=1`;
const REQUEST = `GET /repos/x?y=1 HTTP/1.1\r\nHost: ${HOST}\r\nConnection: close\r\nAccept-Encoding: identity\r\nAuthorization: Bearer s3cret\r\n\r\n`;

const BODY = JSON.stringify({
  stars: 1234,
  owner: { login: 'octocat', email: 'private@example.com', bio: 'café ☕' },
  items: [{ id: 'a' }, { id: 'b', note: 'second' }],
});

const plain = (body: string, contentType = 'application/json'): Buffer =>
  Buffer.from(
    `HTTP/1.1 200 OK\r\nDate: Tue, 24 Nov 2026 10:00:00 GMT\r\nContent-Type: ${contentType}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nSet-Cookie: session=abc\r\n\r\n${body}`,
  );

const chunked = (body: string, at: readonly number[]): Buffer => {
  const bytes = Buffer.from(body);
  const cuts = [0, ...at, bytes.length];
  const chunks = cuts.slice(1).map((end, index) => bytes.subarray(cuts[index], end));
  return Buffer.concat([
    Buffer.from(
      'HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n',
    ),
    ...chunks.flatMap((chunk) => [
      Buffer.from(`${chunk.length.toString(16)}\r\n`),
      chunk,
      Buffer.from('\r\n'),
    ]),
    Buffer.from('0\r\n\r\n'),
  ]);
};

type Rules = {
  responseMatches: { type: 'regex' | 'contains'; value: string }[];
  responseRedactions: { jsonPath?: string; regex?: string }[];
};

const CASES: { name: string; response: Buffer; rules: Rules }[] = [
  {
    name: 'jsonPath properties',
    response: plain(BODY),
    rules: {
      responseMatches: [
        { type: 'regex', value: '"stars":(?<stars>\\d+)' },
        { type: 'regex', value: '"login":"(?<login>[^"]+)"' },
      ],
      responseRedactions: [{ jsonPath: '$.stars' }, { jsonPath: '$.owner.login' }],
    },
  },
  {
    name: 'an array element and a contains guard',
    response: plain(BODY),
    rules: {
      responseMatches: [
        { type: 'regex', value: '"note":"(?<note>[^"]+)"' },
        { type: 'contains', value: '"id":"b"' },
      ],
      responseRedactions: [{ jsonPath: '$.items[1]' }],
    },
  },
  {
    name: 'a regex redaction',
    response: plain(BODY),
    rules: {
      responseMatches: [{ type: 'regex', value: '"stars":(?<stars>\\d+)' }],
      responseRedactions: [{ regex: '"stars":\\d+' }],
    },
  },
  {
    name: 'a regex inside a jsonPath selection, past multibyte text',
    response: plain(BODY, 'application/json; charset=utf-8'),
    rules: {
      responseMatches: [{ type: 'regex', value: '"bio":"(?<bio>[^"]+)"' }],
      responseRedactions: [{ jsonPath: '$.owner', regex: '"bio":"[^"]+"' }],
    },
  },
  {
    name: 'a chunked body with a selection across a chunk boundary',
    response: chunked(BODY, [5, 40, 60]),
    rules: {
      responseMatches: [
        { type: 'regex', value: '"stars":(?<stars>\\d+)' },
        { type: 'regex', value: '"login":"(?<login>[^"]+)"' },
      ],
      responseRedactions: [{ jsonPath: '$.stars' }, { jsonPath: '$.owner.login' }],
    },
  },
  {
    name: 'no redactions',
    response: plain(BODY),
    rules: {
      responseMatches: [{ type: 'regex', value: '"email":"(?<email>[^"]+)"' }],
      responseRedactions: [],
    },
  },
];

const params = (rules: Rules) => ({
  url: URL_,
  method: 'GET' as const,
  responseMatches: rules.responseMatches,
  responseRedactions: rules.responseRedactions,
});

/** The ranges Reclaim's prover reveals: the complement of the ranges it redacts. */
const reclaimReveals = (response: Uint8Array, rules: Rules): [number, number][] => {
  const redactions = providers.http.getResponseRedactions?.({
    response,
    params: params(rules),
    logger,
    ctx: PROVIDER_CTX,
  }) as { fromIndex: number; toIndex: number }[];
  const hidden = new Uint8Array(response.length);
  for (const { fromIndex, toIndex } of redactions) hidden.fill(1, fromIndex, toIndex);
  const reveals: [number, number][] = [];
  for (let index = 0; index < response.length; index += 1) {
    if (hidden[index] === 1) continue;
    const last = reveals.at(-1);
    if (last !== undefined && last[1] === index) last[1] = index + 1;
    else reveals.push([index, index + 1]);
  }
  return reveals;
};

/** The response with every unrevealed byte replaced by Reclaim's `*` marker. */
const redact = (response: Uint8Array, reveals: readonly (readonly [number, number])[]) => {
  const redacted = new Uint8Array(response.length).fill('*'.charCodeAt(0));
  for (const [start, end] of reveals) redacted.set(response.subarray(start, end), start);
  return redacted;
};

describe('tlsn@1 disclosure parity with zkFetch', () => {
  it.each(CASES)('reveals and reads what zkFetch does: $name', ({ response, rules }) => {
    const bytes = new Uint8Array(response);
    const reveals = responseReveals(bytes, rules.responseRedactions);
    expect(reveals).toEqual(reclaimReveals(bytes, rules));

    const sent = new Uint8Array(Buffer.from(REQUEST));
    const sentReveals = requestReveals(sent, new Set(['authorization']));
    const { extractedParameters } = providers.http.assertValidProviderReceipt({
      clientVersion: CURRENT_ATTESTOR_VERSION,
      receipt: [
        { sender: 'client', message: redact(sent, sentReveals) },
        { sender: 'server', message: redact(bytes, reveals) },
      ],
      params: params(rules),
      logger,
      ctx: PROVIDER_CTX,
    }) as { extractedParameters: Record<string, string> };
    const tlsn = disclosedValuesOf(redactedResponseText({ data: bytes, revealed: reveals }), [
      ...rules.responseMatches,
    ]);
    expect({ ...tlsn }).toEqual(extractedParameters);
    expect(Object.keys(extractedParameters).length).toBeGreaterThan(0);
  });
});
