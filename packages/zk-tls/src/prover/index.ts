// The zkFetch kind's live evidence source, run against a caller-chosen witness.
// It imports the Reclaim client libraries lazily, so loading it has no side effects.
import type {
  IAttestorClientInitParams,
  PrepareZKProofsBaseOpts,
} from '@reclaimprotocol/attestor-core';
import type { ZkFetchProver, ZkFetchRequest } from '../client/index.js';
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
     * @throws if the witness reports an error or returns no signed claim.
     */
    prove: async (request: ZkFetchRequest): Promise<ZkFetchEvidence> => {
      const core = await loadCore();
      const result = await core.createClaimOnAttestor({
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
      });
      if (result.error !== undefined) {
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
