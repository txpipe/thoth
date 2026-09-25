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
 * string-named endpoints (e.g. operators keyed by attestor id) without
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
 * Checks a signature under the attestor signature scheme.
 *
 * Kind-agnostic: the client verifies every returned signature with it before
 * counting it toward a threshold.
 *
 * @typeParam PK — the public-key type.
 * @typeParam S — the signature type.
 * @typeParam Msg — the signed-message type; defaults to {@link FlatMessage}.
 */
export interface SignatureVerifier<PK, S, Msg = FlatMessage> {
  /**
   * @param publicKey — the key the signature must verify under.
   * @param message — the signed message.
   * @param signature — the signature to check.
   * @returns whether `signature` is valid for `message` under `publicKey`.
   */
  verify(publicKey: PK, message: Msg, signature: S): boolean;
}

/**
 * Validate one attestation against its descriptor and tag it with its slot.
 *
 * The client's per-attestation validity primitive: it checks that the
 * attestation comes from the pinned key (`'public-key'`), that its
 * `registryIndex` names a real slot in the trusted set (`'registry-index'`),
 * that the attestor signed the message the caller asked for when given
 * `expectedMessage` (`'message'`), and that the signature verifies under the
 * pinned key when given a `verifier` (`'signature'`).
 *
 * @param options — the trusted set, the attestor that was asked, the returned
 *   attestation, and optionally the expected signed message and a verifier.
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
  /** Verifies the signature under the attestor's pinned key; checked when provided. */
  readonly verifier?: SignatureVerifier<PK, S, MessageOf<D>>;
}): CollectedAttestation<D['kind'], z.output<D['claim']>, PK, S, MessageOf<D>> {
  const { trusted, attestor, attestation, expectedMessage, verifier } = options;

  if (!messagesEqual(attestation.publicKey, attestor.publicKey)) {
    throw new AttestationMismatchError(attestor.id, 'public-key');
  }
  if (expectedMessage !== undefined && !messagesEqual(attestation.message, expectedMessage)) {
    throw new AttestationMismatchError(attestor.id, 'message');
  }
  if (attestor.registryIndex < 0 || attestor.registryIndex >= trusted.attestors.length) {
    throw new AttestationMismatchError(attestor.id, 'registry-index');
  }
  if (
    verifier !== undefined &&
    !verifier.verify(attestor.publicKey, attestation.message, attestation.signature)
  ) {
    throw new AttestationMismatchError(attestor.id, 'signature');
  }

  return { registryIndex: attestor.registryIndex, attestation };
}

/**
 * Pick the first group of collected attestations that meets a threshold.
 *
 * Attestations are grouped by exact signed message, so signatures over
 * different messages are never combined. Within a group each registry slot
 * counts once. Verify each attestation (see {@link resolveAttestation}) before
 * grouping; this function trusts its input.
 *
 * @typeParam K — the attestor kind.
 * @typeParam C — the certified claim.
 * @typeParam PK — the attesting public key.
 * @typeParam S — the signature scheme type.
 * @typeParam Msg — the signed-message type.
 * @param collected — the verified, slot-tagged attestations, in any order.
 * @param threshold — how many distinct slots must agree.
 * @returns the agreeing attestations sorted by registry slot, one per slot, or
 *   `undefined` if no message reaches the threshold.
 */
export function thresholdGroup<K, C, PK, S, Msg>(
  collected: readonly CollectedAttestation<K, C, PK, S, Msg>[],
  threshold: number,
): CollectedAttestation<K, C, PK, S, Msg>[] | undefined {
  const groups: CollectedAttestation<K, C, PK, S, Msg>[][] = [];
  for (const entry of collected) {
    const group = groups.find((g) =>
      messagesEqual(g[0]?.attestation.message, entry.attestation.message),
    );
    if (group === undefined) {
      groups.push([entry]);
    } else if (!group.some((member) => member.registryIndex === entry.registryIndex)) {
      group.push(entry);
    }
  }
  return groups
    .find((group) => group.length >= threshold)
    ?.sort((a, b) => a.registryIndex - b.registryIndex);
}

/**
 * Compare signed messages structurally. Supports primitives (including
 * `bigint`), `Uint8Array`, arrays, and plain objects.
 *
 * @param a — the first signed message.
 * @param b — the second signed message.
 * @returns whether they contain the same fields in the same shape and order.
 */
export const messagesEqual = (a: unknown, b: unknown): boolean => {
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
      a.every((value, i) => messagesEqual(value, b[i]))
    );
  }
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  return (
    aKeys.length === bKeys.length &&
    aKeys.every((key) =>
      messagesEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]),
    )
  );
};
