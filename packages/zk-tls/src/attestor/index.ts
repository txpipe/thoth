import type { proto } from '@reclaimprotocol/attestor-core';
import { assertValidClaimSignatures } from '@reclaimprotocol/attestor-core';
import type { Attestor, KeyPair } from '@thoth/attestor';
import { buildAttestor, defineAttestor } from '@thoth/attestor';
import type { AttestationInput } from '@thoth/core';
import type { Claim, FlatMessage } from '@thoth/core/claim';
import { claimToMessage } from '@thoth/core/claim';
import {
  assertEvidenceMatchesIntent,
  assertEvidenceMatchesPolicy,
  deriveClaimFromEvidence,
  intentOf,
  parseDisclosedValue,
  parsedEvidenceView,
  type VerifiedEvidence,
  type ZkFetchDefinition,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchClaimSchema,
  zkFetchEvidenceSchema,
  zkFetchPolicySchema,
} from '../index.js';

const hexToBytes = (hex: string): Uint8Array =>
  new Uint8Array(Buffer.from(hex.replace(/^0x/, ''), 'hex'));

/**
 * Verify a zkFetch proof and extract the values it disclosed.
 *
 * Re-verifies the Reclaim witness's ECDSA signature over the claim (65-byte
 * hex), then returns the parsed evidence view with the values it may certify
 * in {@link VerifiedEvidence.disclosedValues}.
 *
 * Only the attestor (host) side needs the signature work: the client builds
 * its expected claim by derivation and relies on its pinned attestors having
 * verified (plus the on-chain N-of-M threshold).
 *
 * @param evidence — canonicalized proof artifacts.
 * @returns the cryptographically verified evidence.
 * @throws if the signature is invalid, malformed, or the claim is uninterpretable.
 */
export const verifyZkFetchProof = async (evidence: ZkFetchEvidence): Promise<VerifiedEvidence> => {
  const claimSignature = hexToBytes(evidence.signatureHex);
  if (claimSignature.length !== 65) {
    throw new Error(`zkFetch claim signature must be 65 bytes, got ${claimSignature.length}`);
  }
  await assertValidClaimSignatures({
    claim: evidence.claim,
    signatures: {
      claimSignature,
      attestorAddress: evidence.attestorAddress,
    } as proto.ClaimTunnelResponse['signatures'],
  });

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
 * Derive the claim this attestor signs, after running the kind's checks in
 * order and rejecting at the first failure: the Reclaim signature, this
 * instance's witness, the allowed host and required disclosures
 * ({@link assertEvidenceMatchesPolicy}), the intent binding, request binding
 * and window ({@link assertEvidenceMatchesIntent}), and finally that the
 * client's proposed claim equals the claim derived here.
 *
 * The intent is read off the proposed claim; the evidence signature is what
 * makes it trustworthy.
 *
 * @param input — the parsed policy, evidence and proposed claim.
 * @param witnessAddress — the witness this attestor instance trusts.
 * @returns the derived claim (equal to the proposal).
 * @throws with a descriptive message on the first failed check.
 */
const checkAndDerive = async (
  input: AttestationInput<ZkFetchPolicy, ZkFetchEvidence, Claim<number>>,
  witnessAddress: string,
): Promise<Claim<number>> => {
  const { policy, evidence, claim: proposed } = input;
  const verified = await verifyZkFetchProof(evidence);
  if (verified.attestorAddress.toLowerCase() !== witnessAddress.toLowerCase()) {
    throw new Error(`witness ${verified.attestorAddress} is not trusted by this attestor`);
  }
  assertEvidenceMatchesPolicy(verified, policy);
  const intent = intentOf(proposed);
  assertEvidenceMatchesIntent(verified, intent, policy.maxWindowSeconds);
  assertClaimMatchesDisclosures({
    claim: proposed,
    disclosures: verified.disclosedValues,
    policy,
  });
  const derived = deriveClaimFromEvidence({
    verified,
    policy,
    intent,
    valueSlots: proposed.values.length,
  });
  const expected = claimToMessage(derived);
  const actual = claimToMessage(proposed);
  if (expected.length !== actual.length || expected.some((field, i) => field !== actual[i])) {
    throw new Error('proposed claim does not match the claim derived from the evidence');
  }
  return derived;
};

/**
 * Create a zkFetch attestor definition bound to one trusted witness.
 *
 * `verify` implements the kind's check (see {@link zkFetchAttestor} for the
 * order). `message` encodes a claim into its flat field vector via
 * `claimToMessage`.
 *
 * @param witnessAddress — the witness this definition trusts.
 * @returns the definition; instantiate it with `@thoth/attestor`'s
 *   `buildAttestor` (see {@link zkFetchAttestor}).
 */
export function createZkFetchDefinition(witnessAddress: string): ZkFetchDefinition {
  if (!/^0x[0-9a-fA-F]{40}$/.test(witnessAddress)) {
    throw new Error('witnessAddress must be a 0x-prefixed 40-hex address');
  }
  return defineAttestor({
    kind: 'zk-fetch@1',
    policy: zkFetchPolicySchema,
    evidence: zkFetchEvidenceSchema,
    claim: zkFetchClaimSchema,
    verify: async (input: AttestationInput<ZkFetchPolicy, ZkFetchEvidence, Claim<number>>) => {
      await checkAndDerive(input, witnessAddress);
    },
    message: (claim: Claim<number>): FlatMessage => claimToMessage(claim),
  });
}

/**
 * Build a deployable zkFetch attestor instance.
 *
 * Specialization of `@thoth/attestor`'s `buildAttestor` that knows the kind.
 * For each request it checks, in order, rejecting at the first failure:
 *
 * 1. the Reclaim signature is valid;
 * 2. the signer is this instance's configured witness;
 * 3. the attested host is allowed, and the required disclosures are present
 *    and parseable;
 * 4. the signed context carries the intent digest;
 * 5. the signed request matches the request binding;
 * 6. the window is not inverted and the witness observed inside it;
 * 7. the proposed claim equals the claim the attestor derives itself.
 *
 * It then signs `message(claim)` of its own derived claim with the key pair's
 * signer.
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
  /** Reclaim witness address this instance trusts. */
  witnessAddress: string;
}): Attestor<ZkFetchDefinition, PK, S> {
  const { id, keyPair, registryIndex, witnessAddress } = parts;
  const definition = createZkFetchDefinition(witnessAddress);
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
      const claim = await checkAndDerive({ policy, evidence, claim: proposed }, witnessAddress);
      const message = claimToMessage(claim);
      const signature = await signer.sign(message);
      return { kind: definition.kind, claim, message, publicKey, signature };
    },
  });
}
