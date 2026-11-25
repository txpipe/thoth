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
import {
  createTestWitness,
  type TestWitness,
  type TestWitnessObservation,
} from '@txpipe/thoth-test-utils/zk-fetch';

/** What a test witness observed; each field lands in the signed claim data. */
export type Observation = TestWitnessObservation;

/** A witness backed by a local test key; see {@link testWitness}. */
export type { TestWitness };

/**
 * A witness backed by a local test key.
 *
 * @param privateKey — `0x`-prefixed 32-byte hex secp256k1 key.
 * @returns the witness address (lowercase `0x` + 40 hex) and a signer that
 *   turns an {@link Observation} into canonical `ZkFetchEvidence`.
 */
export const testWitness = (privateKey: string): TestWitness =>
  createTestWitness(
    {
      SIGNATURES,
      SelectedServiceSignatureType,
      canonicalStringify,
      createSignDataForClaim,
      getIdentifierFromClaimInfo,
    },
    privateKey,
  );
