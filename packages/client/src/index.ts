import type {
  Attestation,
  AttestationInput,
  AttestorDefinition,
  AttestorDescriptor,
  MessageOf,
} from '@txpipe/thoth-core';
import type { FlatMessage } from '@txpipe/thoth-core/claim';
import type { z } from 'zod';
import {
  AttestationMismatchError,
  AttestorNotInTrustedSetError,
  InvalidTrustedSetError,
} from './errors.js';

/**
 * One pinned attestor and the registry slot this app assigned to it.
 *
 * `attestor_registry.compact` verifies `signatures[i]` against `keys[i]`, so
 * `registryIndex` is the index of `attestor.publicKey` in the app's deployed
 * registry. The app assigns it; the attestor does not know it.
 */
export interface TrustedAttestor<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
> {
  /** The attestor's descriptor. */
  readonly attestor: AttestorDescriptor<D, PK>;
  /** This app's registry slot for the attestor's key. */
  readonly registryIndex: number;
}

/** Brands a {@link TrustedSet} as built, and so checked, by {@link buildTrustedSet}. */
declare const checked: unique symbol;

/**
 * The app's pinned attestors, each at its slot in a registry of `registrySize`
 * keys.
 *
 * The array carries no order: a member's `registryIndex` is its registry slot,
 * never its position in the list. Only {@link buildTrustedSet} produces one.
 */
export interface TrustedSet<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
> {
  /** The registry's key count (`#M`); every slot is below it. */
  readonly registrySize: number;
  /** The pinned attestors, each at its assigned slot. */
  readonly attestors: readonly TrustedAttestor<D, PK>[];
  /** Type-only brand: an object literal cannot pose as a checked set. */
  readonly [checked]: true;
}

/**
 * Build a checked {@link TrustedSet} from app-assigned slots.
 *
 * A set may pin fewer attestors than the registry holds. Members must have
 * distinct ids, keys and slots: a key pinned twice would let one attestor fill
 * two slots of the threshold.
 *
 * @throws {@link InvalidTrustedSetError} if `registrySize` is not a positive
 *   integer, the set is empty, two members share an id, a key or a slot, or a
 *   slot is outside `[0, registrySize)`; `reason` names the check.
 * @example
 * ```ts
 * const trusted = buildTrustedSet({
 *   registrySize: 3, // the contract's #M
 *   attestors: [
 *     { attestor: alice, registryIndex: 0 },
 *     { attestor: bob, registryIndex: 2 },
 *   ],
 * });
 * ```
 */
export function buildTrustedSet<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
>(options: {
  /** The deployed registry's key count (`#M`). */
  readonly registrySize: number;
  /** The pinned attestors, each with its slot in that registry. */
  readonly attestors: readonly TrustedAttestor<D, PK>[];
}): TrustedSet<D, PK> {
  const { registrySize, attestors } = options;
  if (!Number.isSafeInteger(registrySize) || registrySize < 1) {
    throw new InvalidTrustedSetError('', 'registry-size');
  }
  if (attestors.length === 0) {
    throw new InvalidTrustedSetError('', 'empty');
  }
  const ids = new Set<string>();
  const slots = new Set<number>();
  const keys: PK[] = [];
  for (const { attestor, registryIndex } of attestors) {
    if (ids.has(attestor.id)) {
      throw new InvalidTrustedSetError(attestor.id, 'duplicate-id');
    }
    if (keys.some((key) => structuredEquals(key, attestor.publicKey))) {
      throw new InvalidTrustedSetError(attestor.id, 'duplicate-key');
    }
    if (!isSlotOf(registrySize, registryIndex)) {
      throw new InvalidTrustedSetError(attestor.id, 'registry-index');
    }
    if (slots.has(registryIndex)) {
      throw new InvalidTrustedSetError(attestor.id, 'duplicate-slot');
    }
    ids.add(attestor.id);
    keys.push(attestor.publicKey);
    slots.add(registryIndex);
  }
  return { registrySize, attestors } as TrustedSet<D, PK>;
}

/**
 * Find a named attestor and its slot in the trusted set.
 *
 * @throws {@link AttestorNotInTrustedSetError} if no member has that `id`.
 * @see {@link attestorOf} for the descriptor alone.
 */
export function memberOf<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
>(trusted: TrustedSet<D, PK>, id: string): TrustedAttestor<D, PK> {
  const found = trusted.attestors.find((member) => member.attestor.id === id);
  if (found === undefined) {
    throw new AttestorNotInTrustedSetError(id);
  }
  return found;
}

/**
 * Find the descriptor of a named attestor in the trusted set.
 *
 * @throws {@link AttestorNotInTrustedSetError} if no member has that `id`.
 */
export function attestorOf<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
>(trusted: TrustedSet<D, PK>, id: string): AttestorDescriptor<D, PK> {
  return memberOf(trusted, id).attestor;
}

/** List the id of every attestor in the trusted set. */
export function attestorIdsOf<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
>(trusted: TrustedSet<D, PK>): string[] {
  return trusted.attestors.map((member) => member.attestor.id);
}

/** Whether `index` is a valid slot in a registry of `registrySize` keys. */
const isSlotOf = (registrySize: number, index: number): boolean =>
  Number.isSafeInteger(index) && index >= 0 && index < registrySize;

/**
 * How the client reaches a remote attestor.
 *
 * The client-side mirror of `Attestor.attest` in `@txpipe/thoth-attestor`: both take
 * the same raw {@link AttestationInput} and return the same
 * {@link Attestation}. This package defines only the interface; the kind's
 * client or the app supplies the transport (HTTP, in-process, mock).
 */
export interface AttestorTransport<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
> {
  /**
   * Request an attestation from one attestor.
   *
   * @param input — raw, unparsed values, forwarded as-is; the attestor parses
   *   them.
   * @throws if the attestor cannot be reached or rejects the request.
   */
  request(
    attestor: AttestorDescriptor<D, PK>,
    input: AttestationInput<z.input<D['policy']>, z.input<D['evidence']>, z.input<D['claim']>>,
  ): Promise<Attestation<z.output<D['claim']>, PK, S, MessageOf<D>>>;
}

/** One collected attestation and the registry slot it answered from. */
export interface CollectedAttestation<C, PK, S, Msg = FlatMessage> {
  /** The registry slot the attestation was collected from. */
  readonly registryIndex: number;
  /** The attestation collected from that slot. */
  readonly attestation: Attestation<C, PK, S, Msg>;
}

/** Signature verification for the app's signature scheme. */
export interface AttestationVerifier<PK, S, Msg = FlatMessage> {
  /** Check a signature against the pinned key and message; return `false` or throw to reject. */
  verify(publicKey: PK, message: Msg, signature: S): boolean | Promise<boolean>;
}

/**
 * Vet one attestation against its trusted member and tag it with the member's
 * slot.
 *
 * Checks, in order: `member` is in `trusted` (by id, slot and key, so a copy
 * is accepted), the returned key is the pinned key, the message equals
 * `expectedMessage` when given, the claim equals `expectedClaim`, the message
 * is `definition.message(expectedClaim)`, and the signature verifies. A
 * verifier that throws rejects the signature. The README's "Design decisions"
 * says why it vets before collection.
 *
 * @throws {@link AttestorNotInTrustedSetError} if `member` is not in `trusted`.
 * @throws {@link AttestationMismatchError} if a check fails; `reason` names it.
 */
export async function resolveAttestation<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
>(options: {
  /** The trusted set the member must belong to. */
  readonly trusted: TrustedSet<D, PK>;
  /** The member that was asked, as returned by {@link memberOf}; its slot tags the result. */
  readonly member: TrustedAttestor<D, PK>;
  /** The attestation returned for that attestor. */
  readonly attestation: Attestation<z.output<D['claim']>, PK, S, MessageOf<D>>;
  /** The scheme that verifies the returned signature. */
  readonly verifier: AttestationVerifier<PK, S, MessageOf<D>>;
  /** The parsed claim the attestor was asked to certify. */
  readonly expectedClaim: z.output<D['claim']>;
  /** The message the attestor was expected to sign; checked when provided. */
  readonly expectedMessage?: MessageOf<D>;
}): Promise<CollectedAttestation<z.output<D['claim']>, PK, S, MessageOf<D>>> {
  const { trusted, member, attestation, expectedMessage, verifier } = options;
  // The slot must be one the app assigned, not one the caller made up. Compare
  // by value, so a copy of a member is accepted.
  const pinned = trusted.attestors.find(
    (candidate) =>
      candidate.attestor.id === member.attestor.id &&
      candidate.registryIndex === member.registryIndex &&
      structuredEquals(candidate.attestor.publicKey, member.attestor.publicKey),
  );
  if (pinned === undefined) {
    throw new AttestorNotInTrustedSetError(member.attestor.id);
  }
  const { attestor, registryIndex } = pinned;

  if (!structuredEquals(attestation.publicKey, attestor.publicKey)) {
    throw new AttestationMismatchError(attestor.id, 'public-key');
  }
  if (expectedMessage !== undefined && !structuredEquals(attestation.message, expectedMessage)) {
    throw new AttestationMismatchError(attestor.id, 'message');
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
    // A malformed signature must fail vetting just like a cryptographic mismatch.
  }
  if (!validSignature) {
    throw new AttestationMismatchError(attestor.id, 'signature');
  }
  return { registryIndex, attestation };
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
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    for (let i = 0; i < a.length; i++) {
      if (Object.hasOwn(a, i) !== Object.hasOwn(b, i) || !structuredEquals(a[i], b[i])) {
        return false;
      }
    }
    return true;
  }
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  return (
    aKeys.length === bKeys.length &&
    aKeys.every(
      (key) =>
        Object.hasOwn(b, key) &&
        structuredEquals((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]),
    )
  );
};
