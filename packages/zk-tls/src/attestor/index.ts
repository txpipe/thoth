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
import { bytesToHex, hexToBytes } from '../hex.js';
import {
  assertEvidenceMatchesPolicy,
  assertObservationInWindow,
  assertPolicySlotsInRange,
  claimRequestOf,
  deriveClaimFromEvidence,
  isByteRule,
  parsedEvidenceView,
  parseSlotValue,
  signedClaimContextDigestOf,
  type VerifiedEvidence,
  ZK_FETCH_DEFAULT_LIMITS,
  ZK_FETCH_LAW,
  type ZkFetchDefinition,
  type ZkFetchEvidence,
  type ZkFetchLimits,
  type ZkFetchPolicy,
  zkFetchClaimContextDigestOf,
  zkFetchSchemasWithin,
  zkFetchSubjectHashOf,
} from '../index.js';

/**
 * Verify the witness's ECDSA signature over a zkFetch proof and return the
 * parsed view with the values it disclosed.
 *
 * The signature covers an identifier the witness recomputes from provider,
 * parameters and context, so `claim.identifier` is checked against that
 * recomputation too. The evidence is left unchanged.
 *
 * @throws if the signature is invalid or malformed, the identifier does not
 *   match its signed content, or the claim context is not JSON.
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

/** Whether two byte arrays are equal, byte for byte. */
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

/** The all-zero 32-byte value an absent byte slot must carry. */
const ZERO_BYTES_32 = new Uint8Array(32);

/**
 * Require a proposed claim to say exactly what the evidence disclosed: for
 * every policy slot, the `present` flag and the value (numeric or byte, under
 * the slot's rule and `length` pin) match the disclosure. An absent disclosure
 * must be proposed unpresent.
 *
 * @throws on the first mismatch.
 */
export const assertClaimMatchesDisclosures = (options: {
  claim: Claim<number, number>;
  /** The disclosed values, keyed by named regex group. */
  disclosures: Readonly<Record<string, string>>;
  policy: ZkFetchPolicy;
}): void => {
  const { claim, disclosures, policy } = options;
  const valueSlots = claim.values.length;
  for (const slot of policy.slots) {
    const raw = disclosures[slot.name];
    const proposedPresent = claim.present[slot.slot] ?? false;
    if (isByteRule(slot.parse)) {
      const parsed = raw === undefined ? null : parseSlotValue({ ...slot, parse: slot.parse }, raw);
      const proposed = claim.byteValues[slot.slot - valueSlots] ?? ZERO_BYTES_32;
      if (proposedPresent !== (parsed !== null) || !sameBytes(proposed, parsed ?? ZERO_BYTES_32)) {
        throw new Error(
          `claim slot ${slot.slot} does not match the disclosed value for "${slot.name}"`,
        );
      }
    } else {
      const parsed = raw === undefined ? null : parseSlotValue({ ...slot, parse: slot.parse }, raw);
      const proposed = claim.values[slot.slot] ?? 0n;
      if (proposedPresent !== (parsed !== null) || proposed !== (parsed ?? 0n)) {
        throw new Error(
          `claim slot ${slot.slot} does not match the disclosed value for "${slot.name}"`,
        );
      }
    }
  }
};

/**
 * Require a proposed claim's `subjectHash` to be the hash of the request the
 * witness signed, so a client cannot have the attestor certify another source
 * (ADR 0001).
 *
 * @throws if the subject hash differs, or the signed parameters carry no request.
 */
export const assertClaimMatchesSubject = (options: {
  claim: Claim<number, number>;
  verified: VerifiedEvidence;
}): void => {
  const { claim, verified } = options;
  const expected = zkFetchSubjectHashOf(claimRequestOf(verified.claim));
  if (!Buffer.from(claim.subjectHash).equals(expected)) {
    throw new Error('claim subjectHash does not match the request the witness signed');
  }
};

/**
 * Require the context the witness signed to carry the claim context digest of
 * the policy, the signed request's subject, and the proposal's holder and
 * window (ADR 0011). The proposal's salt must be that digest (ADR 0012).
 *
 * @throws if the signed context is not JSON or carries no digest or another one,
 *   the salt differs from it, the signed parameters carry no request or an
 *   unparseable URL, the policy fails `zkFetchPolicySchema`, the holder is not
 *   32 bytes, or a window bound is negative.
 */
export const assertClaimMatchesContext = (options: {
  claim: Claim<number, number>;
  verified: VerifiedEvidence;
  policy: ZkFetchPolicy;
}): void => {
  const { claim, verified, policy } = options;
  const signed = signedClaimContextDigestOf(verified.claim);
  const expected = zkFetchClaimContextDigestOf({
    policy,
    request: claimRequestOf(verified.claim),
    holder: claim.holder,
    windowStart: claim.windowStart,
    windowEnd: claim.windowEnd,
  });
  if (signed !== expected) {
    throw new Error(
      "the witness-signed context does not carry this claim's claim context digest (holder, window, policy or subject differ)",
    );
  }
  if (bytesToHex(claim.salt) !== signed) {
    throw new Error('claim salt is not the claim context digest the witness signed');
  }
};

/**
 * Merge an operator's limits over {@link ZK_FETCH_DEFAULT_LIMITS}. An
 * `undefined` entry keeps its default.
 */
const resolveZkFetchLimits = (limits: Partial<ZkFetchLimits> = {}): ZkFetchLimits => {
  const resolved: { -readonly [K in keyof ZkFetchLimits]: number } = { ...ZK_FETCH_DEFAULT_LIMITS };
  for (const [key, value] of Object.entries(limits)) {
    // Limits often come from a config file, so a misspelled key must not
    // silently leave its default in place.
    if (!Object.hasOwn(ZK_FETCH_DEFAULT_LIMITS, key)) {
      throw new Error(`unknown zkFetch limit '${key}'`);
    }
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new Error(`zkFetch limit '${key}' must be a positive integer, got ${String(value)}`);
    }
    resolved[key as keyof ZkFetchLimits] = value;
  }
  return resolved;
};

/**
 * Create the zkFetch kind's shareable definition: the three schemas, capped by
 * `limits`, a `verify` that runs every check in this module in order, and a
 * `message` that encodes the claim with `claimToMessage`.
 *
 * Instantiate it with {@link zkFetchAttestor}.
 *
 * @param limits - Overrides for {@link ZK_FETCH_DEFAULT_LIMITS}; an unset
 *   limit keeps its default.
 * @throws if a `limits` key is not a {@link ZkFetchLimits} field, or a value
 *   is not a positive integer.
 */
export function createZkFetchDefinition(limits?: Partial<ZkFetchLimits>): ZkFetchDefinition {
  return defineAttestor({
    kind: ZK_FETCH_LAW,
    ...zkFetchSchemasWithin(resolveZkFetchLimits(limits)),
    verify: async (
      input: AttestationInput<ZkFetchPolicy, ZkFetchEvidence, Claim<number, number>>,
    ) => {
      assertPolicySlotsInRange(
        input.policy,
        input.claim.values.length,
        input.claim.byteValues.length,
      );
      const verified = await verifyZkFetchProof(input.evidence);
      assertEvidenceMatchesPolicy(verified, input.policy);
      assertObservationInWindow({ claim: input.claim, verified });
      assertClaimMatchesSubject({ claim: input.claim, verified });
      assertClaimMatchesContext({ claim: input.claim, verified, policy: input.policy });
      assertClaimMatchesDisclosures({
        claim: input.claim,
        disclosures: verified.disclosedValues,
        policy: input.policy,
      });
    },
    message: (claim: Claim<number, number>): FlatMessage => claimToMessage(claim),
  });
}

/**
 * Build a deployable zkFetch attestor.
 *
 * It accepts evidence only from the witness at `witnessAddress`, runs the
 * definition's `verify`, then derives its own claim from the evidence, sized
 * to the proposal's `values` and `byteValues` lengths, and signs that.
 * Input larger than its limits fails while it is parsed, before `verify`.
 *
 * @example
 * ```ts
 * import { zkFetchAttestor } from '@thoth/zk-tls/attestor';
 *
 * const attestor = zkFetchAttestor({
 *   id: 'zkFetch-strava-1',
 *   keyPair, // the attestor's signing key, not the witness's
 *   witnessAddress: '0x…', // the public address of your Reclaim witness
 *   limits: { valueSlots: 128 }, // optional; the rest keep ZK_FETCH_DEFAULT_LIMITS
 * });
 * ```
 *
 * @throws if a `limits` key is not a {@link ZkFetchLimits} field, or a value
 *   is not a positive integer.
 */
export function zkFetchAttestor<PK, S>(parts: {
  id: string;
  keyPair: KeyPair<PK, S, FlatMessage>;
  /** The operator's own Reclaim witness address, `0x` + 40 hex. Compared case-insensitively. */
  witnessAddress: string;
  /**
   * This attestor's input limits, merged over {@link ZK_FETCH_DEFAULT_LIMITS}.
   * They are offchain operator config: they only refuse input, and never
   * change what the attestor signs.
   */
  limits?: Partial<ZkFetchLimits>;
}): Attestor<ZkFetchDefinition, PK, S> {
  const { id, keyPair, witnessAddress, limits } = parts;
  const trustedWitnessAddress = witnessAddress.toLowerCase();
  const definition = createZkFetchDefinition(limits);
  const publicKey = keyPair.publicKey;
  return buildAttestor({
    id,
    definition,
    keyPair,
    attest: async (definition, signer, input) => {
      const policy = definition.policy.parse(input.policy);
      const evidence = definition.evidence.parse(input.evidence);
      // The claim schema parses with `claimSchema()`, whose parsed claim owns its byte
      // arrays, so the caller cannot change the holder between `verify` and the
      // signature.
      const proposed = definition.claim.parse(input.claim);
      await definition.verify({ policy, evidence, claim: proposed });
      if (evidence.attestorAddress.toLowerCase() !== trustedWitnessAddress) {
        throw new Error(
          `evidence signed by witness ${evidence.attestorAddress}, not this attestor's witness ${trustedWitnessAddress}`,
        );
      }
      const verified = parsedEvidenceView(evidence);
      const claim = deriveClaimFromEvidence({
        verified,
        policy,
        appId: proposed.appId,
        holder: proposed.holder,
        valueSlots: proposed.values.length,
        byteSlots: proposed.byteValues.length,
        windowStart: proposed.windowStart,
        windowEnd: proposed.windowEnd,
      });
      const message = claimToMessage(claim);
      const signature = await signer.sign(message);
      return { claim, message, publicKey, signature };
    },
  });
}
