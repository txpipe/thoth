import type { proto } from '@reclaimprotocol/attestor-core';
import {
  assertValidClaimSignatures,
  getIdentifierFromClaimInfo,
} from '@reclaimprotocol/attestor-core';
import type { Attestor, KeyPair } from '@thoth/attestor';
import { buildAttestor, defineAttestor } from '@thoth/attestor';
import type { AttestationInput } from '@thoth/core';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import { hexToBytes } from '../hex.js';
import {
  assertEvidenceMatchesPolicy,
  assertPolicySlotsInRange,
  claimRequestOf,
  deriveClaimFromEvidence,
  parseDisclosedValue,
  parsedEvidenceView,
  type VerifiedEvidence,
  ZK_FETCH_LAW,
  type ZkFetchDefinition,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchClaimSchema,
  zkFetchEvidenceSchema,
  zkFetchPolicySchema,
  zkFetchSubjectHashOf,
} from '../index.js';

/**
 * Verify a zkFetch proof and extract the values it disclosed.
 *
 * Re-verifies the Reclaim witness's ECDSA signature over the claim (65-byte
 * hex), then returns the parsed evidence view with the values it may certify
 * in {@link VerifiedEvidence.disclosedValues}.
 *
 * The signature covers an identifier the witness recomputes from
 * provider/parameters/context, not the `claim.identifier` field itself, so the
 * field is checked against that recomputation here.
 *
 * Only the attestor (host) side needs the signature work: the client builds
 * its expected claim by derivation and relies on its pinned attestors having
 * verified (plus the on-chain N-of-M threshold).
 *
 * Verification leaves the caller's evidence unchanged, including its context encoding.
 *
 * @param evidence — canonicalized proof artifacts.
 * @returns the cryptographically verified evidence.
 * @throws if the signature is invalid, malformed, the claim identifier does
 *   not match its signed content, or the claim is uninterpretable.
 */
export const verifyZkFetchProof = async (evidence: ZkFetchEvidence): Promise<VerifiedEvidence> => {
  const claimSignature = hexToBytes(evidence.signatureHex);
  if (claimSignature.length !== 65) {
    throw new Error(`zkFetch claim signature must be 65 bytes, got ${claimSignature.length}`);
  }
  await assertValidClaimSignatures({
    // Reclaim canonicalizes context in place while computing the signed identifier.
    // All claim fields are scalars, so a shallow copy isolates that mutation.
    claim: { ...evidence.claim },
    signatures: {
      claimSignature,
      attestorAddress: evidence.attestorAddress,
    } as proto.ClaimTunnelResponse['signatures'],
  });

  const { provider, parameters, context } = evidence.claim;
  // `getIdentifierFromClaimInfo` re-canonicalizes `context` in place; pass a
  // copy so re-verification never mutates the evidence it was handed.
  const recomputed = getIdentifierFromClaimInfo({ provider, parameters, context });
  if (evidence.claim.identifier !== recomputed) {
    throw new Error(
      `claim identifier ${evidence.claim.identifier} does not match its signed content (${recomputed})`,
    );
  }

  return parsedEvidenceView(evidence);
};

/**
 * Check a client-proposed claim against the disclosed values.
 *
 * The client proposes claim values; the attestor only signs what the evidence
 * disclosed. For every policy slot this enforces that the proposal's `present`
 * flag and value match the disclosure exactly (an absent disclosure must be
 * proposed unpresent), so a client cannot have the attestor certify a
 * different reading of the same evidence.
 *
 * @param options — the proposed claim, the disclosed values, and the policy.
 * @throws with a descriptive message on the first mismatch.
 */
export const assertClaimMatchesDisclosures = (options: {
  /** The client-proposed claim. */
  claim: Claim<number>;
  /** The disclosed values (redacted values excluded). */
  disclosures: Readonly<Record<string, string>>;
  /** The policy declaring the slot map. */
  policy: ZkFetchPolicy;
}): void => {
  const { claim, disclosures, policy } = options;
  for (const slot of policy.slots) {
    const raw = disclosures[slot.name];
    const parsed = raw === undefined ? null : parseDisclosedValue(raw, slot.parse);
    const certifiable = parsed !== null;
    const expected = parsed ?? 0n;
    const proposedPresent = claim.present[slot.slot] ?? false;
    const proposedValue = claim.values[slot.slot] ?? 0n;
    if (proposedPresent !== certifiable || proposedValue !== expected) {
      throw new Error(
        `claim slot ${slot.slot} does not match the disclosed value for "${slot.name}"`,
      );
    }
  }
};

/**
 * Check a client-proposed claim's subject against the signed request.
 *
 * The attestor derives the subject hash from the request its witness signed
 * ({@link claimRequestOf}) and requires the proposal to carry it, so a client
 * cannot have the attestor certify a claim about another source (ADR 0001).
 *
 * @param options — the proposed claim and the verified evidence.
 * @throws if the proposed `subjectHash` is not the signed request's, or the
 *   signed parameters carry no request.
 */
export const assertClaimMatchesSubject = (options: {
  /** The client-proposed claim. */
  claim: Claim<number>;
  /** The verified evidence whose signed parameters name the request. */
  verified: VerifiedEvidence;
}): void => {
  const { claim, verified } = options;
  const expected = zkFetchSubjectHashOf(claimRequestOf(verified.claim));
  if (!Buffer.from(claim.subjectHash).equals(expected)) {
    throw new Error('claim subjectHash does not match the request the witness signed');
  }
};

/**
 * Check a client-proposed claim's observation window against the witness.
 *
 * The window is when the attestor observed (ADR 0005), so the attestor
 * requires its own witness's observation time to fall inside the proposed
 * `[windowStart, windowEnd]`, bounds included. The contract bounds the
 * window's length and checks it against block time.
 *
 * @param options — the proposed claim and the verified evidence.
 * @throws if the witness observed outside the proposed window.
 */
export const assertObservationInWindow = (options: {
  /** The client-proposed claim. */
  claim: Claim<number>;
  /** The verified evidence whose signed claim carries the observation time. */
  verified: VerifiedEvidence;
}): void => {
  const { claim, verified } = options;
  const observedAt = BigInt(verified.claim.timestampS);
  if (observedAt < claim.windowStart || observedAt > claim.windowEnd) {
    throw new Error(
      `witness observation ${observedAt} is outside the claim window [${claim.windowStart}, ${claim.windowEnd}]`,
    );
  }
};

/**
 * Create the zkFetch attestor kind's shareable definition.
 *
 * The claim schema requires equal `values` and `present` lengths.
 * `verify` checks policy slot bounds at that requested size before verifying the evidence
 * ({@link verifyZkFetchProof}), checking it against the policy
 * ({@link assertEvidenceMatchesPolicy}), requiring the witness's own
 * observation to fall inside the client-proposed window
 * ({@link assertObservationInWindow}), and enforcing that the proposed claim matches the
 * signed request ({@link assertClaimMatchesSubject}) and the disclosed values
 * ({@link assertClaimMatchesDisclosures}). `message` encodes a
 * claim into its flat field vector via `claimToMessage`.
 *
 * @returns the shareable definition; instantiate it with `@thoth/attestor`'s
 *   `buildAttestor` (see {@link zkFetchAttestor}).
 */
export function createZkFetchDefinition(): ZkFetchDefinition {
  return defineAttestor({
    kind: ZK_FETCH_LAW,
    policy: zkFetchPolicySchema,
    evidence: zkFetchEvidenceSchema,
    claim: zkFetchClaimSchema,
    verify: async (input: AttestationInput<ZkFetchPolicy, ZkFetchEvidence, Claim<number>>) => {
      assertPolicySlotsInRange(input.policy, input.claim.values.length);
      const verified = await verifyZkFetchProof(input.evidence);
      assertEvidenceMatchesPolicy(verified, input.policy);
      assertObservationInWindow({ claim: input.claim, verified });
      assertClaimMatchesSubject({ claim: input.claim, verified });
      assertClaimMatchesDisclosures({
        claim: input.claim,
        disclosures: verified.disclosedValues,
        policy: input.policy,
      });
    },
    message: (claim: Claim<number>): FlatMessage => claimToMessage(claim),
  });
}

/**
 * Build a deployable zkFetch attestor instance.
 *
 * Specialization of `@thoth/attestor`'s `buildAttestor` that knows the kind:
 * it accepts evidence only from the operator's own Reclaim witness, rejects
 * proposals that do not match the disclosures, derives the *authoritative*
 * claim from the verified evidence (request-bound subject hash)
 * sized to the proposed claim's values length, and signs `message(claim)` with
 * the key pair's signer.
 *
 * @typeParam PK — the signature scheme's public key type.
 * @typeParam S — the signature scheme's signature type.
 * @param parts — instance id, key material, registry slot, and witness address.
 * @returns a working `Attestor` for the kind.
 */
export function zkFetchAttestor<PK, S>(parts: {
  /** Stable identifier for this deployable instance. */
  id: string;
  /** The key material: public key plus the matching signing boundary. */
  keyPair: KeyPair<PK, S, FlatMessage>;
  /** Slot index of this attestor's key in the on-chain registry. */
  registryIndex: number;
  /** The operator's own Reclaim witness address (`0x` + 20-byte hex). */
  witnessAddress: string;
}): Attestor<ZkFetchDefinition, PK, S> {
  const { id, keyPair, registryIndex, witnessAddress } = parts;
  const trustedWitnessAddress = witnessAddress.toLowerCase();
  const definition = createZkFetchDefinition();
  const publicKey = keyPair.publicKey;
  return buildAttestor({
    id,
    definition,
    keyPair,
    registryIndex,
    attest: async (definition, signer, input) => {
      const policy = definition.policy.parse(input.policy);
      const evidence = definition.evidence.parse(input.evidence);
      const proposed = definition.claim.parse(input.claim);
      // One full check pass (ECDSA + policy + subject and disclosures cross-check).
      await definition.verify({ policy, evidence, claim: proposed });
      if (evidence.attestorAddress.toLowerCase() !== trustedWitnessAddress) {
        throw new Error(
          `evidence signed by witness ${evidence.attestorAddress}, not this attestor's witness ${trustedWitnessAddress}`,
        );
      }
      // Claim derivation only needs the pure parsed view.
      const verified = parsedEvidenceView(evidence);
      const claim = deriveClaimFromEvidence({
        verified,
        policy,
        appId: proposed.appId,
        holder: proposed.holder,
        valueSlots: proposed.values.length,
        windowStart: proposed.windowStart,
        windowEnd: proposed.windowEnd,
      });
      const message = claimToMessage(claim);
      const signature = await signer.sign(message);
      return { kind: definition.kind, claim, message, publicKey, signature };
    },
  });
}
