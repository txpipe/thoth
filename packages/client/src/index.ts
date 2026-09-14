import type {
  Attestation,
  AttestationInput,
  AttestorDefinition,
  AttestorDescriptor,
  MessageOf,
} from '@thoth/core';
import type { FlatMessage } from '@thoth/core/claim';
import type { z } from 'zod';
import { AttestationMismatchError, AttestorNotInTrustedSetError } from './errors.js';

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
  ): Promise<Attestation<D['kind'], z.output<D['claim']>, PK, S, MessageOf<D>>>;
}

/**
 * One collected attestation paired with the registry slot it answered from.
 *
 * @typeParam K — the attestor kind.
 * @typeParam C — the certified claim.
 * @typeParam PK — the attesting public key.
 * @typeParam S — the signature scheme type.
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 */
export interface CollectedAttestation<K, C, PK, S, Msg = FlatMessage> {
  /** The registry slot the attestation was collected from. */
  readonly registryIndex: number;
  /** The attested artifact collected from that slot. */
  readonly attestation: Attestation<K, C, PK, S, Msg>;
}

/**
 * Validate one attestation against its descriptor and tag it with its slot.
 *
 * The client's per-attestation validity primitive: it checks that the
 * attestation comes from the pinned key (`'public-key'`), that its
 * `registryIndex` names a real slot in the trusted set (`'registry-index'`),
 * and — when given `expectedMessage` — that the attestor signed the message
 * the caller asked for (`'message'`).
 *
 * @param options — the trusted set, the attestor that was asked, the returned
 *   attestation, and optionally the expected signed message.
 * @returns the slot-tagged {@link CollectedAttestation}.
 * @throws {@link AttestationMismatchError} if a check fails; the `reason`
 *   discriminates which one.
 */
export function resolveAttestation<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
>(options: {
  /** The trusted set; its size bounds the valid registry slots. */
  readonly trusted: TrustedSet<D, PK>;
  /** The attestor that was asked. */
  readonly attestor: AttestorDescriptor<D, PK>;
  /** The attestation returned for that attestor. */
  readonly attestation: Attestation<D['kind'], z.output<D['claim']>, PK, S, MessageOf<D>>;
  /** The message the attestor was expected to sign; checked when provided. */
  readonly expectedMessage?: MessageOf<D>;
}): CollectedAttestation<D['kind'], z.output<D['claim']>, PK, S, MessageOf<D>> {
  const { trusted, attestor, attestation, expectedMessage } = options;

  if (!structuredEquals(attestation.publicKey, attestor.publicKey)) {
    throw new AttestationMismatchError(attestor.id, 'public-key');
  }
  if (expectedMessage !== undefined && !structuredEquals(attestation.message, expectedMessage)) {
    throw new AttestationMismatchError(attestor.id, 'message');
  }
  if (attestor.registryIndex < 0 || attestor.registryIndex >= trusted.attestors.length) {
    throw new AttestationMismatchError(attestor.id, 'registry-index');
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
