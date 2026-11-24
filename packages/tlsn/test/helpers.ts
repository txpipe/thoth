// Offline fixtures: a fake presentation verifier that returns what `thoth-tlsn verify`
// would print for a transcript the test writes, and fake attestor keys.

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

export const NOTARY_KEY: TlsnNotaryKey = {
  alg: 'k256',
  key: '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f',
};

export const HOST = 'api.example.com';
export const APP_ID = new Uint8Array(32).fill(7);
export const HOLDER = holderCommitmentOf(new Uint8Array(32).fill(9));
export const TIME = 1_800_000_000;
export const WINDOW = { windowStart: BigInt(TIME - 60), windowEnd: BigInt(TIME + 60) };

export const POLICY: TlsnPolicy = {
  allowedHosts: [HOST],
  hiddenHeaders: ['authorization'],
  slots: [
    { slot: 0, path: ['stars'], parse: 'int' },
    { slot: 1, path: ['big'], parse: 'int' },
    { slot: 2, path: ['owner', 'login'], parse: 'bytes' },
  ],
  bodyPolicy: 'empty',
};

export const RESPONSE_BODY =
  '{"stars":1234,"big":18446744073709551615,"owner":{"login":"octocat"}}';

export const response = (body = RESPONSE_BODY, status = '200 OK'): string =>
  `HTTP/1.1 ${status}\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`;

export const SECRET = 'Bearer s3cret';

export const request = (options: { host?: string; target?: string } = {}): string =>
  `GET ${options.target ?? '/repos/x?y=1'} HTTP/1.1\r\nhost: ${options.host ?? HOST}\r\naccept-encoding: identity\r\nconnection: close\r\nauthorization: ${SECRET}\r\n\r\n`;

/** The `[start, end)` range of `needle` in `haystack`. */
export const rangeOf = (haystack: string, needle: string): [number, number] => {
  const start = Buffer.from(haystack).indexOf(needle);
  if (start < 0) throw new Error(`${needle} not found`);
  return [start, start + Buffer.byteLength(needle)];
};

/** One transcript direction as the verifier prints it, with `hidden` ranges zeroed. */
const direction = (text: string, hidden: readonly [number, number][]) => {
  const data = Buffer.from(text);
  const mask = new Uint8Array(data.length).fill(1);
  for (const [start, end] of hidden) {
    data.fill(0, start, end);
    mask.fill(0, start, end);
  }
  const revealed: [number, number][] = [];
  for (let index = 0; index < mask.length; index += 1) {
    if (mask[index] !== 1) continue;
    const last = revealed.at(-1);
    if (last !== undefined && last[1] === index) last[1] = index + 1;
    else revealed.push([index, index + 1]);
  }
  return { length: data.length, data: data.toString('hex'), revealed };
};

/** What `thoth-tlsn verify` prints, for a transcript the test writes. */
export const verifiedJson = (options: {
  claimContext: Uint8Array;
  sent?: string;
  received?: string;
  hiddenSent?: readonly [number, number][];
  hiddenReceived?: readonly [number, number][];
  serverName?: string;
  time?: number;
  notaryKey?: TlsnNotaryKey;
  extensions?: { id: string; value: string }[];
}) => {
  const sent = options.sent ?? request();
  return {
    notaryKey: options.notaryKey ?? NOTARY_KEY,
    serverName: options.serverName ?? HOST,
    time: options.time ?? TIME,
    sent: direction(sent, options.hiddenSent ?? [rangeOf(sent, SECRET)]),
    received: direction(options.received ?? response(), options.hiddenReceived ?? []),
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
