// The zkFetch kind's live evidence source, run against a caller-chosen witness.
// It imports the Reclaim client libraries lazily, so loading it has no side effects.
import type {
  IAttestorClientInitParams,
  PrepareZKProofsBaseOpts,
  ProofGenerationStep,
} from '@reclaimprotocol/attestor-core';
import type { ZkFetchProver, ZkFetchRequest } from '../client/index.js';
import { bytesToHex } from '../hex.js';
import type { ZkFetchEvidence } from '../index.js';
import { ZkFetchProverError } from '../prover-error.js';

/** The lazily-imported Reclaim client module. */
type AttestorCore = typeof import('@reclaimprotocol/attestor-core');

/** Configuration for {@link zkFetchProver}. */
export interface ZkFetchProverConfig {
  /**
   * WebSocket URL of the Reclaim witness that opens the TLS connection and
   * signs the claim. Point it at the witness the attestor trusts.
   */
  witnessUrl: string | URL;
  /**
   * Auth for a witness running with `AUTHENTICATION_PUBLIC_KEY` set. A
   * provider function is called per `prove`, so a short-lived signed request
   * stays fresh.
   */
  authRequest?: IAttestorClientInitParams['authRequest'];
  /** ZK engine for redaction proofs. Defaults to `stwo`, whose assets ship in the package. */
  zkEngine?: PrepareZKProofsBaseOpts['zkEngine'];
  /** ZK operators in place of the engine's default factory; browser builds inject their own. */
  zkOperators?: PrepareZKProofsBaseOpts['zkOperators'];
}

let corePromise: Promise<AttestorCore> | undefined;

/**
 * Import the Reclaim client libraries once, install the WebCrypto TLS backend,
 * which `@reclaimprotocol/tls` leaves empty by default, and wait for `re2`.
 *
 * @throws if the native `re2` module does not load.
 */
const loadCore = (): Promise<AttestorCore> => {
  corePromise ??= (async () => {
    const [attestorCore, tls, webcrypto] = await Promise.all([
      import('@reclaimprotocol/attestor-core'),
      import('@reclaimprotocol/tls'),
      import('@reclaimprotocol/tls/webcrypto'),
    ]);
    tls.setCryptoImplementation(webcrypto.webcryptoCrypto);
    // attestor-core starts loading `re2` on import and runs regexes with RegExp until it has.
    // The witnesses run RE2, so wait for the same module, and never prove without it.
    await import('re2').catch((error: unknown) => {
      throw new Error('@thoth/zk-tls needs the native re2 module, which did not load', {
        cause: error,
      });
    });
    return attestorCore;
  })();
  return corePromise;
};

/** Reclaim error codes for a witness, proxy, or source the prover could not reach. */
const TRANSPORT_CODES: ReadonlySet<string> = new Set([
  'ERROR_NETWORK_ERROR',
  'ERROR_TIMEOUT',
  'ERROR_CERTIFICATE_FETCH_FAILED',
  'ERROR_PROXY_ERROR',
]);

/**
 * The messages `@reclaimprotocol/tls` and Reclaim's tunnel build locally when
 * the TLS handshake with the source fails: a certificate it cannot verify, a
 * fatal alert, or a connection the source closed. They carry no code.
 */
const TLS_FAILURES: readonly RegExp[] = [
  /^Fatal alert: /,
  /^Certificate is not for host /,
  /^Certificate .+ is outside validity$/,
  /^Missing issuer for certificate /,
  /^Issuer Cert .+ is not within validity period$/,
  /^Verification of .+ failed by issuer /,
  /^TLS connection closed$/,
];

/**
 * Whether a local error says the response failed the request's disclosure
 * rules. Reclaim's client applies them before it sends the claim to the
 * witness: the redactions first, then `responseMatches`. It builds each
 * message locally from the rule, so only the exact message for one of this
 * request's rules counts.
 */
const isNoMatch = (message: string, request: ZkFetchRequest): boolean =>
  // A `responseMatches` failure, for a regex or a contains rule.
  message.startsWith('Invalid receipt. ') ||
  (request.responseRedactions ?? []).some(
    ({ regex, jsonPath, xPath }) =>
      (Boolean(regex) && message.startsWith(`regexp ${regex} does not match found element `)) ||
      (Boolean(jsonPath) && message === 'jsonPath not found') ||
      (Boolean(xPath) && message === `Failed to find XPath: "${xPath}"`),
  );

/**
 * Classify an error `createClaimOnAttestor` threw, given the request and the
 * last step it reported; return the error unchanged when no reason fits.
 */
const classifyThrown = (
  core: AttestorCore,
  error: unknown,
  request: ZkFetchRequest,
  step: ProofGenerationStep['name'] | undefined,
): unknown => {
  if (error instanceof core.AttestorError) {
    // While connecting, the witness opens the TCP connection to the source,
    // relays the handshake and fetches certificates. Its RPC handler answers a
    // socket error there (connection refused, DNS failure, reset) as
    // `ERROR_INTERNAL`, so that code in this step is taken as the source being
    // unreachable. The witness also checks the app's auth request in this step,
    // and a malformed signature there surfaces as `ERROR_INTERNAL` too: that
    // rare app misconfiguration is reported as `transport`.
    if (
      TRANSPORT_CODES.has(error.code) ||
      (error.code === 'ERROR_INTERNAL' && step === 'connecting')
    ) {
      return new ZkFetchProverError('transport', { cause: error });
    }
    return error;
  }
  if (!(error instanceof Error)) {
    return error;
  }
  if (isNoMatch(error.message, request)) {
    return new ZkFetchProverError('no-match', { cause: error });
  }
  if (step === 'connecting' && TLS_FAILURES.some((failure) => failure.test(error.message))) {
    return new ZkFetchProverError('transport', { cause: error });
  }
  return error;
};

/**
 * Build the zkFetch kind's live prover.
 *
 * It runs the Reclaim zkFetch protocol over WebSocket and returns the
 * canonical {@link ZkFetchEvidence} the attestor verifies. `responseText` is
 * the transcript as the client saw it, not witness-signed content.
 *
 * @example
 * ```ts
 * import { zkFetchProver } from '@thoth/zk-tls/prover';
 *
 * const prover = zkFetchProver({ witnessUrl: 'ws://localhost:8001/ws' });
 * const evidence = await prover.prove({
 *   url: 'https://api.github.com/repos/txpipe/dolos',
 *   responseMatches: [{ type: 'regex', value: '"stargazers_count":\\s*(?<stars>\\d+)' }],
 *   responseRedactions: [{ regex: '"stargazers_count":\\s*\\d+' }],
 * });
 * ```
 */
export const zkFetchProver = (config: ZkFetchProverConfig): ZkFetchProver => {
  const ownerBytes = crypto.getRandomValues(new Uint8Array(32));
  const ownerPrivateKey = `0x${bytesToHex(ownerBytes)}`;
  return {
    /**
     * Fetch `request` through the configured witness.
     *
     * @throws {@link ZkFetchProverError} if the witness or the source cannot be
     *   reached, or the response fails the request's redactions or `responseMatches`.
     * @throws if the native `re2` module does not load, the prover fails otherwise,
     *   the witness refuses the claim, or it returns no signed claim.
     */
    prove: async (request: ZkFetchRequest): Promise<ZkFetchEvidence> => {
      const core = await loadCore();
      let step: ProofGenerationStep['name'] | undefined;
      const result = await core
        .createClaimOnAttestor({
          name: 'http',
          params: {
            url: request.url,
            method: request.method ?? 'GET',
            headers: request.publicHeaders === undefined ? undefined : { ...request.publicHeaders },
            responseMatches:
              request.responseMatches === undefined
                ? [{ type: 'regex', value: '(?<data>.*)' }]
                : request.responseMatches.map((match) => ({ ...match })),
            responseRedactions: [...(request.responseRedactions ?? [])],
            body: request.body ?? '',
            paramValues: {},
          },
          secretParams: {
            cookieStr: '',
            headers: request.secretHeaders === undefined ? {} : { ...request.secretHeaders },
            paramValues: {},
          },
          context: request.context,
          ownerPrivateKey,
          client: { url: config.witnessUrl, authRequest: config.authRequest },
          zkEngine: config.zkEngine ?? 'stwo',
          zkOperators: config.zkOperators,
          onStep: ({ name }) => {
            step = name;
          },
        })
        .catch((error: unknown) => {
          throw classifyThrown(core, error, request, step);
        });
      if (result.error !== undefined) {
        // A witness returns a claim it refuses, with `ERROR_INVALID_CLAIM` whatever
        // the cause. The client checked the disclosure rules before sending it, so
        // a refusal is not a `no-match`; it stays unclassified.
        throw new Error(`zkFetch witness error: ${result.error.message}`);
      }
      const { claim, signatures } = result;
      if (claim === undefined || signatures === undefined) {
        throw new Error('zkFetch witness returned no signed claim');
      }
      return {
        claim,
        signatureHex: `0x${bytesToHex(signatures.claimSignature)}`,
        attestorAddress: signatures.attestorAddress.toLowerCase(),
        responseText: (
          JSON.parse(claim.context) as { extractedParameters?: Record<string, string> }
        ).extractedParameters?.data,
      };
    },
  };
};
