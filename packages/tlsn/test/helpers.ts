// Offline fixtures: a fake presentation verifier that returns what `thoth-tlsn verify`
// would print for a transcript the test writes, revealed the way the real prover reveals
// it, and fake attestor keys.

import type { KeyPair } from '@txpipe/thoth-attestor';
import type { FlatMessage } from '@txpipe/thoth-core/claim';
import { holderCommitmentOf } from '@txpipe/thoth-core/claim-context';
import type {
  TlsnEvidence,
  TlsnNotaryKey,
  TlsnPolicy,
  TlsnPresentationVerifier,
} from '../src/index.js';
import { TLSN_CLAIM_CONTEXT_EXTENSION } from '../src/index.js';
import { requestReveals, responseReveals } from '../src/redact.js';

export const NOTARY_KEY: TlsnNotaryKey = {
  alg: 'k256',
  key: '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f',
};

export const HOST = 'api.example.com';
export const URL_ = `https://${HOST}/repos/x?y=1`;
export const APP_ID = new Uint8Array(32).fill(7);
export const HOLDER = holderCommitmentOf(new Uint8Array(32).fill(9));
export const TIME = 1_800_000_000;
export const WINDOW = { windowStart: BigInt(TIME - 60), windowEnd: BigInt(TIME + 60) };
export const PRIVATE_EMAIL = 'private@example.com';
export const SECRET = 'Bearer s3cret';

/** The policy a zkFetch dApp would write for this source. */
export const POLICY: TlsnPolicy = {
  allowedHosts: ['example.com'],
  slots: [
    { slot: 0, name: 'stars', parse: 'int' },
    { slot: 1, name: 'big', parse: 'int' },
    { slot: 2, name: 'login', parse: 'bytes' },
  ],
  responseMatches: [
    { type: 'regex', value: '"stars":(?<stars>\\d+)' },
    { type: 'regex', value: '"big":(?<big>\\d+)' },
    { type: 'regex', value: '"login":"(?<login>[^"]+)"' },
  ],
  responseRedactions: [
    { jsonPath: '$.stars' },
    { jsonPath: '$.big' },
    { jsonPath: '$.owner.login' },
  ],
  bodyPolicy: 'ignored',
};

export const RESPONSE_BODY = JSON.stringify({
  stars: 1234,
  big: '__BIG__',
  owner: { login: 'octocat', email: PRIVATE_EMAIL },
}).replace('"__BIG__"', '18446744073709551615');

export const response = (body = RESPONSE_BODY, status = '200 OK'): string =>
  `HTTP/1.1 ${status}\r\nDate: Tue, 24 Nov 2026 10:00:00 GMT\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nSet-Cookie: session=abc\r\n\r\n${body}`;

export const request = (options: { host?: string; target?: string; head?: string } = {}): string =>
  options.head !== undefined
    ? `${options.head}\r\n\r\n`
    : `GET ${options.target ?? '/repos/x?y=1'} HTTP/1.1\r\nHost: ${options.host ?? HOST}\r\nConnection: close\r\nAccept-Encoding: identity\r\nAuthorization: ${SECRET}\r\n\r\n`;

/** The `[start, end)` range of `needle` in `haystack`. */
export const rangeOf = (haystack: string, needle: string): [number, number] => {
  const start = Buffer.from(haystack).indexOf(needle);
  if (start < 0) throw new Error(`${needle} not found`);
  return [start, start + Buffer.byteLength(needle)];
};

/** One transcript direction as the verifier prints it: hidden bytes are zero. */
const direction = (text: string, revealed: readonly (readonly [number, number])[]) => {
  const data = Buffer.from(text);
  const mask = new Uint8Array(data.length);
  for (const [start, end] of revealed) mask.fill(1, start, end);
  for (let index = 0; index < data.length; index += 1) {
    if (mask[index] !== 1) data[index] = 0;
  }
  return {
    length: data.length,
    data: data.toString('hex'),
    revealed: revealed.map(([s, e]) => [s, e]),
  };
};

/**
 * What `thoth-tlsn verify` prints for a transcript, revealed by default the way
 * the prover reveals it under {@link POLICY}.
 */
export const verifiedJson = (options: {
  claimContext: Uint8Array;
  sent?: string;
  received?: string;
  revealSent?: readonly (readonly [number, number])[];
  revealReceived?: readonly (readonly [number, number])[];
  policy?: TlsnPolicy;
  serverName?: string;
  time?: number;
  notaryKey?: TlsnNotaryKey;
  extensions?: { id: string; value: string }[];
}) => {
  const sent = options.sent ?? request();
  const received = options.received ?? response();
  return {
    notaryKey: options.notaryKey ?? NOTARY_KEY,
    serverName: options.serverName ?? HOST,
    time: options.time ?? TIME,
    sent: direction(
      sent,
      options.revealSent ?? requestReveals(Buffer.from(sent), new Set(['authorization'])),
    ),
    received: direction(
      received,
      options.revealReceived ??
        responseReveals(Buffer.from(received), (options.policy ?? POLICY).responseRedactions),
    ),
    extensions: options.extensions ?? [
      {
        id: Buffer.from(TLSN_CLAIM_CONTEXT_EXTENSION).toString('hex'),
        value: Buffer.from(options.claimContext).toString('hex'),
      },
    ],
  };
};

/** Evidence whose "presentation" is the verifier output itself, hex-encoded. */
export const evidenceOf = (verified: object): TlsnEvidence => ({
  presentation: Buffer.from(JSON.stringify(verified)).toString('hex'),
});

/** A presentation verifier that decodes {@link evidenceOf}'s fake presentations. */
export const fakeVerifier: TlsnPresentationVerifier = {
  verify: async (presentation) => JSON.parse(Buffer.from(presentation, 'hex').toString('utf-8')),
};

export type FakePublicKey = { id: string };
export type FakeSignature = string;

export const fakeSignatureVerifier = {
  verify: (_key: FakePublicKey, message: FlatMessage, signature: FakeSignature) =>
    signature === `sig:${message.length}`,
};

export const fakeKey = (id: string): KeyPair<FakePublicKey, FakeSignature, FlatMessage> => ({
  publicKey: { id },
  signer: { sign: (message: FlatMessage): FakeSignature => `sig:${message.length}` },
});
