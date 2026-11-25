// The evidence source behind the client: one HTTPS fetch through MPC-TLS with an
// attestor's notary, revealing only what the zkFetch prover would reveal.

import {
  type TlsnEvidence,
  type TlsnResponseMatch,
  type TlsnResponseRedaction,
  tlsnEvidenceSchema,
} from '../index.js';
import { startNativeSession, TlsnNativeError } from '../native.js';
import { TlsnProverError } from '../prover-error.js';
import { RedactionError, requestReveals, responseReveals } from '../redact.js';

export { TlsnNativeError, TlsnProverError };

/** The key under which the client puts the claim context digest in a request's `context`. */
export const TLSN_CLAIM_CONTEXT_KEY = 'thothClaimContext';

/**
 * What to fetch and which of its fields the evidence reveals, in the zkFetch
 * request's shape.
 *
 * Public headers, the body and the request line are visible to whoever
 * verifies the evidence; secret header values are not.
 */
export interface TlsnRequest {
  /** The HTTPS URL to fetch, on port 443. */
  url: string;
  /** Defaults to `GET`. */
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH';
  /** Revealed to the attestors. */
  body?: string;
  /** Headers revealed to the attestors. */
  publicHeaders?: Readonly<Record<string, string>>;
  /** Headers whose values are hidden from the attestors, such as authorization. */
  secretHeaders?: Readonly<Record<string, string>>;
  /** Response patterns the attestors apply. The client always sets the policy's. */
  responseMatches?: readonly TlsnResponseMatch[];
  /** Slices of the response the prover reveals. The client always sets the policy's. */
  responseRedactions?: readonly TlsnResponseRedaction[];
  /**
   * What the notary signs. tlsn@1 signs only the claim context digest, which the
   * client sets under {@link TLSN_CLAIM_CONTEXT_KEY}; any other key is refused.
   */
  context?: Readonly<Record<string, unknown>>;
}

/** The evidence source behind the client: where the fetch happens. */
export interface TlsnProver {
  /**
   * Fetch `request` and return the presentation it attests.
   *
   * @throws {@link TlsnProverError} if the notary or the source cannot be
   *   reached, or the response fails the request's redaction rules. Only this
   *   error gives `collect` a reason other than `evidence`.
   * @throws if the request is malformed or proving fails otherwise.
   */
  prove(request: TlsnRequest): Promise<TlsnEvidence>;
}

/** The configuration of a prover that runs the `thoth-tlsn` binary against one notary. */
export interface TlsnProverConfig {
  /** Path to the `thoth-tlsn` binary. */
  binary: string;
  /** The notary's `host:port`; point it at the notary the attestor pins. */
  notary: string;
  /** Connect to this `host:port` instead of the URL's host, for test servers. */
  connect?: string;
  /** A DER root certificate to trust in place of the Mozilla roots, for test servers. */
  rootCert?: string;
  /** Bytes the prover may send. MPC cost grows with it. */
  maxSent?: number;
  /** Bytes the prover may receive. MPC cost grows with it. */
  maxRecv?: number;
  /** Defaults to 5 minutes. */
  timeoutMs?: number;
}

/** Refuse a header that could smuggle a second line into the request. */
const checkHeaders = (headers: Readonly<Record<string, string>> = {}): [string, string][] =>
  Object.entries(headers).map(([name, value]) => {
    if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) {
      throw new Error(`header ${name} contains a line break`);
    }
    if (['host', 'connection'].includes(name.toLowerCase())) {
      throw new Error(`the prover sets the ${name} header itself`);
    }
    return [name, value];
  });

/** The claim context digest a request carries for the notary to sign. */
const claimContextOf = (request: TlsnRequest): string => {
  const context = request.context ?? {};
  const keys = Object.keys(context);
  if (keys.some((key) => key !== TLSN_CLAIM_CONTEXT_KEY)) {
    throw new Error('tlsn@1 signs no context besides the claim context digest');
  }
  const digest = context[TLSN_CLAIM_CONTEXT_KEY];
  if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error('the request carries no claim context digest');
  }
  return digest;
};

const transcriptOf = (line: unknown): { sent: Uint8Array; received: Uint8Array } => {
  const transcript = (line as { transcript?: { sent?: unknown; received?: unknown } }).transcript;
  if (typeof transcript?.sent !== 'string' || typeof transcript.received !== 'string') {
    throw new Error('thoth-tlsn prove printed no transcript');
  }
  return {
    sent: new Uint8Array(Buffer.from(transcript.sent, 'hex')),
    received: new Uint8Array(Buffer.from(transcript.received, 'hex')),
  };
};

/**
 * A {@link TlsnProver} that runs `thoth-tlsn prove` against one notary.
 *
 * The binary fetches the request through MPC-TLS and hands back the
 * plaintext; this side chooses what to reveal, as the zkFetch prover does, and
 * the binary commits exactly that before the notary signs. The plaintext never
 * leaves this machine.
 *
 * @example
 * ```ts
 * import { tlsnProver } from '@txpipe/thoth-tlsn/prover';
 *
 * const prover = tlsnProver({ binary: 'thoth-tlsn', notary: 'notary-1.example:7047' });
 * ```
 */
export const tlsnProver = (config: TlsnProverConfig): TlsnProver => ({
  prove: async (request) => {
    const url = new URL(request.url);
    if (url.protocol !== 'https:' || url.port !== '') {
      throw new Error('tlsn@1 requests are HTTPS on port 443');
    }
    const claimContext = claimContextOf(request);
    const publicHeaders = checkHeaders(request.publicHeaders);
    const secretHeaders = checkHeaders(request.secretHeaders);
    const secretNames = new Set(secretHeaders.map(([name]) => name.toLowerCase()));

    const session = startNativeSession({
      binary: config.binary,
      args: [
        'prove',
        '--notary',
        config.notary,
        '--url',
        url.href,
        '--method',
        request.method ?? 'GET',
        '--claim-context',
        claimContext,
        ...publicHeaders.flatMap(([name, value]) => ['--header', `${name}: ${value}`]),
        ...(request.body === undefined ? [] : ['--body', request.body]),
        ...(config.connect === undefined ? [] : ['--connect', config.connect]),
        ...(config.rootCert === undefined ? [] : ['--root-cert', config.rootCert]),
        ...(config.maxSent === undefined ? [] : ['--max-sent', String(config.maxSent)]),
        ...(config.maxRecv === undefined ? [] : ['--max-recv', String(config.maxRecv)]),
      ],
      timeoutMs: config.timeoutMs ?? 300_000,
    });
    try {
      // Secret header values go through stdin: arguments are visible to other local users.
      session.send({ secretHeaders: Object.fromEntries(secretHeaders) });
      let transcript: { sent: Uint8Array; received: Uint8Array };
      try {
        transcript = transcriptOf(await session.next());
      } catch (error) {
        // Nothing came back from the fetch: the notary or the source was unreachable.
        throw new TlsnProverError('transport', { cause: error });
      }
      let reveal: { sent: [number, number][]; received: [number, number][] };
      try {
        reveal = {
          sent: requestReveals(transcript.sent, secretNames) as [number, number][],
          received: responseReveals(transcript.received, request.responseRedactions ?? []) as [
            number,
            number,
          ][],
        };
      } catch (error) {
        throw error instanceof RedactionError
          ? new TlsnProverError('no-match', { cause: error })
          : error;
      }
      session.send({ reveal });
      const output = await session.next();
      await session.finish();
      return tlsnEvidenceSchema.parse(output);
    } finally {
      session.kill();
    }
  },
});
