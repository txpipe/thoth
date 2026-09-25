// The zkFetch kind's concrete evidence source: runs the Reclaim client
// protocol against a caller-chosen witness and returns canonical evidence.
//
// Environment-neutral by construction — no Node built-ins, and the Reclaim
// client stack is imported (and its TLS crypto backend installed) lazily on the
// first `prove`, so importing this module has no side effects and a bundler can
// take the edge however its target needs.
import type {
  IAttestorClientInitParams,
  PrepareZKProofsBaseOpts,
} from '@reclaimprotocol/attestor-core';
import type { ZkFetchProver, ZkFetchRequest } from '../client/index.js';
import type { ZkFetchEvidence } from '../index.js';

/** The lazily-imported Reclaim client module. */
type AttestorCore = typeof import('@reclaimprotocol/attestor-core');

/**
 * Configuration for {@link zkFetchProver}.
 */
export interface ZkFetchProverConfig {
  /**
   * WebSocket URL of the Reclaim witness that performs the TLS connection and
   * signs the claim.
   *
   * Each attestor instance trusts one witness key, so point this at the
   * witness that attestor trusts — one you run yourself, or one whose key the
   * operator pinned.
   */
  witnessUrl: string | URL;
  /**
   * Auth for a witness running with `AUTHENTICATION_PUBLIC_KEY` set. A provider
   * is called per `prove`, so a short-lived signed request stays fresh.
   */
  authRequest?: IAttestorClientInitParams['authRequest'];
  /**
   * ZK engine for redaction proofs. Defaults to `stwo`, whose assets ship in
   * the package (unlike `snarkjs`, which needs a separate download).
   */
  zkEngine?: PrepareZKProofsBaseOpts['zkEngine'];
  /**
   * ZK operators to use instead of the engine's default factory. Browser builds
   * inject their own here — the published `stwo` entry is Node-only; see the
   * README's browser recipe.
   */
  zkOperators?: PrepareZKProofsBaseOpts['zkOperators'];
}

let corePromise: Promise<AttestorCore> | undefined;

/**
 * Import the Reclaim client stack once and install the WebCrypto TLS backend.
 *
 * `@reclaimprotocol/tls` starts with an empty crypto object, so the backend
 * must be installed before any claim runs. WebCrypto exists in Node 20+ and in
 * browsers, which is what keeps this path environment-neutral.
 *
 * @returns the attestor-core module.
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

/** Lowercase hex of raw bytes. */
const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

/**
 * Build the zkFetch kind's live prover.
 *
 * The returned `ZkFetchProver` runs the Reclaim zkFetch protocol over
 * WebSocket: the witness opens the TLS connection to the requested URL, the
 * client drives the transcript and redaction proofs, and the witness returns a
 * signed claim. The result is canonical {@link ZkFetchEvidence} — the one shape
 * `@thoth/zk-tls` attestors verify — with the witness address taken from the
 * tunnel response and the captured response body in `responseText`.
 *
 * @param config — witness URL, witness auth, and ZK tuning.
 * @returns a `ZkFetchProver` for the client's `prover` slot.
 */
export const zkFetchProver = (config: ZkFetchProverConfig): ZkFetchProver => {
  const ownerBytes = crypto.getRandomValues(new Uint8Array(32));
  const ownerPrivateKey = `0x${bytesToHex(ownerBytes)}`;
  return {
    /**
     * Fetch `request` through the configured witness.
     *
     * @param request — what to fetch and which fields to reveal/redact.
     * @returns canonical evidence the witness signed.
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
