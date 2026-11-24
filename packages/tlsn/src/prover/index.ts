// The evidence source behind the client: the thoth-tlsn binary's `prove` subcommand,
// run against one attestor's notary.

import { type TlsnEvidence, tlsnEvidenceSchema } from '../index.js';
import { runNative, TlsnNativeError } from '../native.js';

export { TlsnNativeError };

/** What to fetch, and which header values stay hidden from the attestors. */
export interface TlsnRequest {
  /** The HTTPS URL to fetch, on port 443. */
  url: string;
  /** Defaults to `GET`. */
  method?: string;
  /** Revealed to the attestors. */
  body?: string;
  /** Headers revealed to the attestors. */
  publicHeaders?: Readonly<Record<string, string>>;
  /** Headers whose values stay hidden; the policy's `hiddenHeaders` must name them. */
  secretHeaders?: Readonly<Record<string, string>>;
}

/** Produces a presentation for one request, bound to one claim context digest. */
export interface TlsnProver {
  /**
   * Fetch `request` with a notary and return the presentation.
   *
   * @param claimContext — the 32-byte digest the notary signs.
   * @throws if the notary or the server cannot be reached, or proving fails.
   */
  prove(request: TlsnRequest, claimContext: Uint8Array): Promise<TlsnEvidence>;
}

/** Refuse a header that could smuggle a second line into the request. */
const checkHeaders = (headers: Readonly<Record<string, string>> = {}): [string, string][] =>
  Object.entries(headers).map(([name, value]) => {
    if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) {
      throw new Error(`header ${name} contains a line break`);
    }
    return [name, value];
  });

/**
 * A {@link TlsnProver} that runs `thoth-tlsn prove` against one notary.
 *
 * @example
 * ```ts
 * const prover = nativeProver({ binary: 'thoth-tlsn', notary: 'notary-1.example:7047' });
 * ```
 */
export const nativeProver = (options: {
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
}): TlsnProver => ({
  prove: async (request, claimContext) => {
    if (claimContext.length !== 32) {
      throw new Error('the claim context digest must be 32 bytes');
    }
    const args = [
      'prove',
      '--notary',
      options.notary,
      '--url',
      request.url,
      '--method',
      request.method ?? 'GET',
      '--claim-context',
      Buffer.from(claimContext).toString('hex'),
      ...checkHeaders(request.publicHeaders).flatMap(([name, value]) => [
        '--header',
        `${name}: ${value}`,
      ]),
      // Secret headers go through stdin: arguments are visible to other local users.
      ...(request.secretHeaders === undefined ? [] : ['--secret-headers-stdin']),
      ...(request.body === undefined ? [] : ['--body', request.body]),
      ...(options.connect === undefined ? [] : ['--connect', options.connect]),
      ...(options.rootCert === undefined ? [] : ['--root-cert', options.rootCert]),
      ...(options.maxSent === undefined ? [] : ['--max-sent', String(options.maxSent)]),
      ...(options.maxRecv === undefined ? [] : ['--max-recv', String(options.maxRecv)]),
    ];
    checkHeaders(request.secretHeaders);
    const output = await runNative({
      binary: options.binary,
      args,
      ...(request.secretHeaders === undefined
        ? {}
        : { stdin: JSON.stringify(request.secretHeaders) }),
      timeoutMs: options.timeoutMs ?? 300_000,
    });
    return tlsnEvidenceSchema.parse(output);
  },
});
