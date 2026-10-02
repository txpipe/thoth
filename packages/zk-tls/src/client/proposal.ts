// Claim proposal helpers shared by `proveReq` and `collect`.

import type { Claim } from '@thoth/core/claim';
import { claimSchema } from '@thoth/core/claim';
import type { ZkFetchEvidence, ZkFetchPolicy } from '../index.js';
import {
  assertEvidenceMatchesPolicy,
  claimUrl,
  deriveClaimFromEvidence,
  parsedEvidenceView,
} from '../index.js';
import type { ZkFetchRequest } from './index.js';

/**
 * The URL the signed evidence attests is the one the request asked for.
 *
 * A prover returns canonical evidence for the interaction it witnessed; this
 * keeps that evidence honest against the caller's request before any
 * attestation is collected. Origin (scheme + host + port) is compared, so a
 * redirect or a differing path still passes, while a mismatched host is
 * caught early.
 *
 * @param evidence — canonical evidence from the prover.
 * @param request — what the caller asked the client to prove.
 * @throws if the evidence attests a different origin than requested.
 */
export const assertEvidenceMatchesRequest = (
  evidence: ZkFetchEvidence,
  request: ZkFetchRequest,
): void => {
  const asked = new URL(request.url).origin;
  const attested = new URL(claimUrl(evidence.claim)).origin;
  if (asked !== attested) {
    throw new Error(`prover returned evidence for ${attested}, not the requested ${asked}`);
  }
};

/**
 * Build the claim proposal the client sends to every attestor.
 *
 * Runs the policy check and derives the canonical claim. The client
 * deliberately does **not** re-verify the Reclaim ECDSA signature, and each
 * pinned attestor verifies the evidence before signing.
 * Because the claim is deterministic in the evidence, the
 * proposal is byte-identical to what each attestor will sign, so the client
 * can precompute the expected message and vet each returned attestation
 * against it (`resolveAttestation`'s `expectedMessage`).
 *
 * @typeParam V — the claim's value-slot count (the dApp contract's `#V`).
 * @param options — the evidence, the shared policy, the app id, the slot
 *   count, and the observation window every witness's evidence falls in.
 * @returns the claim to propose (and to submit, once collected).
 * @throws if the evidence is invalid, fails the policy, or does not fit the
 *   dApp's claim length.
 */
export const buildClaimProposal = async <V extends number>(options: {
  /** The evidence to attest (as produced by the prover). */
  evidence: ZkFetchEvidence;
  /** The shared policy every attestor in the set enforces. */
  policy: ZkFetchPolicy;
  /** The app the claim is for. */
  appId: Uint8Array;
  /** Per-claim holder commitment, supplied by the caller. */
  holder: Uint8Array;
  /** The claim's value-slot count (the target contract's `#V`). */
  valueSlots: V;
  /** Start of the window to sign: the earliest observation across the witnesses. */
  windowStart: bigint;
  /** End of the window to sign: the latest observation across the witnesses. */
  windowEnd: bigint;
}): Promise<Claim<V>> => {
  const { evidence, policy, appId, holder, valueSlots, windowStart, windowEnd } = options;
  const verified = parsedEvidenceView(evidence);
  assertEvidenceMatchesPolicy(verified, policy);
  const derived = deriveClaimFromEvidence({
    verified,
    policy,
    appId,
    holder,
    valueSlots,
    windowStart,
    windowEnd,
  });
  return claimSchema(valueSlots).parse(derived);
};
