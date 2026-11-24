// Test-key witness: a local secp256k1 key that signs provider claim data the
// way a Reclaim witness does, so tests can mint canonical zkFetch evidence
// offline. Signing goes through attestor-core's own `SIGNATURES` and
// `createSignDataForClaim`, so the attestor's check runs unchanged.
import {
  canonicalStringify,
  createSignDataForClaim,
  getIdentifierFromClaimInfo,
  SelectedServiceSignatureType,
  SIGNATURES,
} from '@reclaimprotocol/attestor-core';
import type { ProviderClaimData, ZkFetchEvidence } from '@txpipe/thoth-zk-tls';

const scheme = SIGNATURES[SelectedServiceSignatureType];

/** What a test witness observed; each field lands in the signed claim data. */
export interface Observation {
  /** Disclosed values, signed as the context's `extractedParameters`. */
  values: Readonly<Record<string, string>>;
  /** Observation time, Unix seconds. */
  timestampS: number;
  /** Provider parameters (url, method, body, …). */
  parameters: Readonly<Record<string, unknown>>;
  /** Extra signed context fields (e.g. an intent digest). */
  context?: Readonly<Record<string, unknown>>;
}

/** The requester a test witness records as the claim owner. */
const OWNER = '0x445541beb656e0f2359cae936fda3c404c409194';

/** A witness backed by a local test key; see {@link testWitness}. */
export interface TestWitness {
  /** The witness address the attestor recovers (lowercase `0x` + 40 hex). */
  address: string;
  /** Sign an observation into canonical zkFetch evidence. */
  sign(observation: Observation): Promise<ZkFetchEvidence>;
}

/**
 * A witness backed by a local test key.
 *
 * @param privateKey — `0x`-prefixed 32-byte hex secp256k1 key.
 * @returns the witness address (lowercase `0x` + 40 hex) and a signer that
 *   turns an {@link Observation} into canonical {@link ZkFetchEvidence}.
 */
export const testWitness = (privateKey: string): TestWitness => {
  const address = scheme.getAddress(scheme.getPublicKey(privateKey));
  return {
    address,
    sign: async (observation: Observation): Promise<ZkFetchEvidence> => {
      const info = {
        provider: 'http',
        parameters: canonicalStringify(observation.parameters),
        context: canonicalStringify({
          ...observation.context,
          extractedParameters: observation.values,
        }),
      };
      const claim: ProviderClaimData = {
        ...info,
        owner: OWNER,
        timestampS: observation.timestampS,
        identifier: getIdentifierFromClaimInfo(info),
        epoch: 1,
      };
      const signature = await scheme.sign(
        new TextEncoder().encode(createSignDataForClaim(claim)),
        privateKey,
      );
      return {
        claim,
        signatureHex: `0x${Buffer.from(signature).toString('hex')}`,
        attestorAddress: address,
      };
    },
  };
};
