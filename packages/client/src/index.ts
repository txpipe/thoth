import type {
  Attestation,
  AttestationInput,
  AttestorDefinition,
  AttestorDescriptor,
  MessageOf,
} from '@thoth/core';
import type { FlatMessage } from '@thoth/core/claim';
import type { z } from 'zod';
import {
  AttestationMismatchError,
  AttestorNotInTrustedSetError,
  InvalidTrustedSetError,
} from './errors.js';

/**
 * The client's pinned set of attestors.
 *
 * An unordered collection: the array carries no order — each member's
 * `registryIndex` is its on-chain registry slot, never its position in this
 * list.
 *
 * @typeParam D — the attestor definition type for every member.
 * @typeParam PK — the public-key type.
 */
export interface TrustedSet<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
> {
  /** The attestors the client may query. */
  attestors: readonly AttestorDescriptor<D, PK>[];
}

/**
 * Assemble a checked {@link TrustedSet} from its descriptors.
 *
 * Ensure a trusted set is  * well-formed by construction: it rejects an
 * empty set, two members sharing an `id`, two members claiming the same
 * registry slot, and any `registryIndex` outside the set's own slot range.
 * Uniqueness is what keeps downstream placement deterministic; see {@link AttestorDescriptor.registryIndex}.
 *
 * @param attestors — the descriptors to assemble.
 * @returns the validated trusted set.
 * @throws {@link InvalidTrustedSetError} if a construction invariant fails.
 */
export function buildTrustedSet<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
>(attestors: readonly AttestorDescriptor<D, PK>[]): TrustedSet<D, PK> {
  if (attestors.length === 0) {
    throw new InvalidTrustedSetError('', 'empty');
  }
  const ids = new Set<string>();
  const slots = new Set<number>();
  for (const attestor of attestors) {
    if (ids.has(attestor.id)) {
      throw new InvalidTrustedSetError(attestor.id, 'duplicate-id');
    }
    if (attestor.registryIndex < 0 || attestor.registryIndex >= attestors.length) {
      throw new InvalidTrustedSetError(attestor.id, 'registry-index');
    }
    if (slots.has(attestor.registryIndex)) {
      throw new InvalidTrustedSetError(attestor.id, 'duplicate-slot');
    }
    ids.add(attestor.id);
    slots.add(attestor.registryIndex);
  }
  return { attestors };
}

/**
 * Find the descriptor for a named attestor in the trusted set.
 *
 * The seam's name→descriptor resolution, so a kind SDK can support
 * string-named endpoints (`proof.attest("txpipeEndpoint", …)`) without
 * re-checking membership at every call site.
 *
 * @param trusted — the trusted set to search.
 * @param id — the attestor instance id (non-cryptographic).
 * @returns the descriptor whose `id` matches.
 * @throws {@link AttestorNotInTrustedSetError} if no member has that `id`.
 */
export function attestorOf<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
>(trusted: TrustedSet<D, PK>, id: string): AttestorDescriptor<D, PK> {
  const found = trusted.attestors.find((attestor) => attestor.id === id);
  if (found === undefined) {
    throw new AttestorNotInTrustedSetError(id);
  }
  return found;
}

/**
 * How the client reaches a remote attestor.
 *
 * The remote mirror of the host-side `Attestor.attest(input)`: both consume the
 * same raw {@link AttestationInput} shape and produce the same
 * {@link Attestation} artifact, agreeing purely through `@thoth/core` types.
 * This package provides only the seam — a kind SDK or the application supplies
 * a concrete transport (HTTP, in-process, mock).
 *
 * @typeParam D — the attestor definition type.
 * @typeParam PK — the public-key type.
 * @typeParam S — the signature scheme type.
 */
export interface AttestorTransport<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
> {
  /**
   * Request an attestation from a specific attestor.
   *
   * @param attestor — the attestor to reach.
   * @param input — the raw (unparsed) policy/evidence/claim values; forwarded
   *   as-is, the attestor is the law.
   * @returns the signed attestation, or throws if the attestor cannot be
   *   reached or rejects the request.
   */
  request(
    attestor: AttestorDescriptor<D, PK>,
    input: AttestationInput<z.input<D['policy']>, z.input<D['evidence']>, z.input<D['claim']>>,
  ): Promise<Attestation<z.output<D['claim']>, PK, S, MessageOf<D>>>;
}

/**
 * One collected attestation paired with the registry slot it answered from.
 *
 * @typeParam C — the certified claim.
 * @typeParam PK — the attesting public key.
 * @typeParam S — the signature scheme type.
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 */
export interface CollectedAttestation<C, PK, S, Msg = FlatMessage> {
  /** The registry slot the attestation was collected from. */
  readonly registryIndex: number;
  /** The attested artifact collected from that slot. */
  readonly attestation: Attestation<C, PK, S, Msg>;
}

/**
 * Signature verification supplied by the application's signature scheme.
 * @typeParam PK - Public key type.
 * @typeParam S - Signature type.
 * @typeParam Msg - Signed message type.
 */
export interface AttestationVerifier<PK, S, Msg = FlatMessage> {
  /**
   * Check a signature against the pinned key and message.
   * @param publicKey - The trusted public key.
   * @param message - The message to authenticate.
   * @param signature - The returned signature.
   * @returns true for a valid signature; false or throw to reject.
   */
  verify(publicKey: PK, message: Msg, signature: S): boolean | Promise<boolean>;
}

/**
 * Validate one attestation against its descriptor and tag it with its slot.
 *
 * Checks the pinned key, registry slot, expected claim, claim-to-message
 * binding, and signature. When provided, `expectedMessage` must also match.
 * Verifier errors reject the signature. The caller supplies the parsed expected claim.
 *
 * @param options — the trusted set, the attestor that was asked, the returned
 *   attestation, verifier, expected parsed claim, and optional expected message.
 * @returns a promise of the slot-tagged {@link CollectedAttestation}.
 * @throws {@link AttestationMismatchError} if a check fails; the `reason`
 *   discriminates which one.
 */
export async function resolveAttestation<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
>(options: {
  /** The trusted set; its size bounds the valid registry slots. */
  readonly trusted: TrustedSet<D, PK>;
  /** The attestor that was asked. */
  readonly attestor: AttestorDescriptor<D, PK>;
  /** The attestation returned for that attestor. */
  readonly attestation: Attestation<z.output<D['claim']>, PK, S, MessageOf<D>>;
  /** The scheme that verifies the returned signature. */
  readonly verifier: AttestationVerifier<PK, S, MessageOf<D>>;
  /** The parsed claim the caller asked the attestor to certify. */
  readonly expectedClaim: z.output<D['claim']>;
  /** The message the attestor was expected to sign; checked when provided. */
  readonly expectedMessage?: MessageOf<D>;
}): Promise<CollectedAttestation<z.output<D['claim']>, PK, S, MessageOf<D>>> {
  const { trusted, attestor, attestation, expectedMessage, verifier } = options;

  if (!structuredEquals(attestation.publicKey, attestor.publicKey)) {
    throw new AttestationMismatchError(attestor.id, 'public-key');
  }
  if (expectedMessage !== undefined && !structuredEquals(attestation.message, expectedMessage)) {
    throw new AttestationMismatchError(attestor.id, 'message');
  }
  if (attestor.registryIndex < 0 || attestor.registryIndex >= trusted.attestors.length) {
    throw new AttestationMismatchError(attestor.id, 'registry-index');
  }

  if (!structuredEquals(attestation.claim, options.expectedClaim)) {
    throw new AttestationMismatchError(attestor.id, 'claim');
  }
  if (!structuredEquals(attestation.message, attestor.definition.message(options.expectedClaim))) {
    throw new AttestationMismatchError(attestor.id, 'message');
  }
  let validSignature = false;
  try {
    validSignature = await verifier.verify(
      attestor.publicKey,
      attestation.message,
      attestation.signature,
    );
  } catch {
    // Malformed signatures must fail vetting just like cryptographic mismatches.
  }
  if (!validSignature) {
    throw new AttestationMismatchError(attestor.id, 'signature');
  }
  return { registryIndex: attestor.registryIndex, attestation };
}

/**
 * Deep structural equality over the plain data used in attestations: primitives
 * (including `bigint`), `Uint8Array`, arrays, and plain objects.
 */
const structuredEquals = (a: unknown, b: unknown): boolean => {
  if (a === b) {
    return true;
  }
  if (typeof a !== typeof b) {
    return false;
  }
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) {
    return a === b;
  }
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    return (
      a instanceof Uint8Array &&
      b instanceof Uint8Array &&
      a.length === b.length &&
      a.every((byte, i) => byte === b[i])
    );
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((value, i) => structuredEquals(value, b[i]))
    );
  }
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  return (
    aKeys.length === bKeys.length &&
    aKeys.every((key) =>
      structuredEquals((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]),
    )
  );
};
