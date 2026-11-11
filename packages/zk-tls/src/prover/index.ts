// The zkFetch kind's live evidence source, run against a caller-chosen witness.
// It imports the Reclaim client libraries lazily, so loading it has no side effects.
import type {
  IAttestorClientInitParams,
  PrepareZKProofsBaseOpts,
  ProofGenerationStep,
} from '@reclaimprotocol/attestor-core';
import type { ZkFetchProver, ZkFetchRequest } from '../client/index.js';
import { ZkFetchProverError } from '../client/index.js';
import { bytesToHex } from '../hex.js';
import type { ZkFetchEvidence } from '../index.js';

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
 * Import the Reclaim client libraries once and install the WebCrypto TLS backend,
 * which `@reclaimprotocol/tls` leaves empty by default.
 */
const loadCore = (): Promise<AttestorCore> => {
  corePromise ??= (async () => {
    const [attestorCore, tls, webcrypto] = await Promise.all([
      import('@reclaimprotocol/attestor-core'),
      import('@reclaimprotocol/tls'),
      import('@reclaimprotocol/tls/webcrypto'),
    ]);
    tls.setCryptoImplementation(webcrypto.webcryptoCrypto);
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
 * The reason a Reclaim error code stands for, if any. A witness reports every
 * claim it refuses, its failed `responseMatches` included, as
 * `ERROR_INVALID_CLAIM` with nothing finer than remote text, which is not read.
 */
const reasonOfCode = (code: string): ZkFetchProverError['reason'] | undefined => {
  if (TRANSPORT_CODES.has(code)) {
    return 'transport';
  }
  return code === 'ERROR_INVALID_CLAIM' ? 'no-match' : undefined;
};

/**
 * Classify an error `createClaimOnAttestor` threw, given the last step it
 * reported; return the error unchanged when no reason fits.
 */
const classifyThrown = (
  core: AttestorCore,
  error: unknown,
  step: ProofGenerationStep['name'] | undefined,
): unknown => {
  if (error instanceof core.AttestorError) {
    const reason = reasonOfCode(error.code);
    return reason === undefined ? error : new ZkFetchProverError(reason, { cause: error });
  }
  if (!(error instanceof Error)) {
    return error;
  }
  // Reclaim's client runs the witness's receipt check locally first, and a
  // failure there is a plain error with no code. Only its two
  // `responseMatches` failures (regex and contains) start with this prefix,
  // and the text is built locally from the policy's rule, never remote.
  if (error.message.startsWith('Invalid receipt. ')) {
    return new ZkFetchProverError('no-match', { cause: error });
  }
  // In this step Reclaim's client opens the tunnel and runs the TLS handshake,
  // whose certificate and alert failures `@reclaimprotocol/tls` throws with no
  // code. It also builds the HTTP request here, which fails only on a
  // `{{param}}` template in the body, a request every attestor refuses.
  if (step === 'connecting') {
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
     * @throws {@link ZkFetchProverError} if the witness or the source is
     *   unreachable, or the response fails `responseMatches`.
     * @throws if the witness reports another error or returns no signed claim.
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
          throw classifyThrown(core, error, step);
        });
      if (result.error !== undefined) {
        // The witness answers a claim it refuses with an error instead of throwing.
        const refusal = core.AttestorError.fromProto(result.error);
        const reason = reasonOfCode(refusal.code);
        if (reason !== undefined) {
          throw new ZkFetchProverError(reason, { cause: refusal });
        }
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
