import type {
  Attestation,
  AttestationInput,
  AttestorDefinition,
  AttestorDescriptor,
  MessageOf,
} from '@thoth/core';
import type { z } from 'zod';

/**
 * The client's pinned set of attestors, in on-chain registry-slot order.
 *
 * Ordering is load-bearing: the client must submit collected signatures at the
 * index matching each attestor's `registryIndex`.
 *
 * @typeParam D — the attestor definition type for every member.
 * @typeParam PK — the public-key type.
 */
export interface TrustedSet<
  D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
> {
  /** Ordered (registry-slot) list of the attestors the client may query. */
  attestors: readonly AttestorDescriptor<D, PK>[];
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
 * The collected, positionally-ordered set of attestations, ready for submission.
 *
 * `signatures[i]` holds the signature from registry slot `i` (or `null` when
 * that slot did not vouch), so the vector aligns with the on-chain registry's
 * positional verification. `claim` and `message` are the single certified
 * values all collected signatures commit to.
 *
 * @typeParam C — the certified claim type.
 * @typeParam Msg — the signed-message type.
 * @typeParam PK — the public-key type.
 * @typeParam S — the signature scheme type.
 */
export interface AttestationBundle<C, Msg, PK, S> {
  /** The certified claim all collected signatures vouch for. */
  claim: C;
  /** The single message the collected signatures commit to. */
  message: Msg;
  /** Signature per registry slot; `null` when that slot did not vouch. */
  signatures: (S | null)[];
  /** Public key per registry slot; `null` when that slot did not vouch. */
  publicKeys: (PK | null)[];
  /** The registry slots that actually vouched, ascending. */
  registryIndexes: number[];
}

/**
 * A transport call failed for a specific attestor (network error, timeout, …).
 *
 * A rejection by the attestor's own `verify` is also surfaced here — this
 * package does not distinguish the reasons; it only reports reachability.
 */
export class AttestorUnavailableError extends Error {
  /** The id of the attestor that could not be reached. */
  readonly attestorId: string;
  /** The underlying failure. */
  readonly cause: unknown;

  /**
   * @param attestorId — the failing attestor's id.
   * @param cause — the underlying failure.
   */
  constructor(attestorId: string, cause: unknown) {
    super(`attestor "${attestorId}" unavailable`);
    this.attestorId = attestorId;
    this.cause = cause;
  }
}

/**
 * A collected attestation failed a structural integrity check.
 *
 * `reason` discriminates the failing check: the returned public key does not
 * match the descriptor's (`'public-key'`), the signed message disagrees with
 * the other collected attestations (`'message'`), or the attestor's
 * `registryIndex` is outside the trusted set's slot range (`'registry-index'`).
 */
export class AttestationMismatchError extends Error {
  /** The id of the offending attestor. */
  readonly attestorId: string;
  /** Which integrity check failed. */
  readonly reason: 'public-key' | 'message' | 'registry-index';

  /**
   * @param attestorId — the offending attestor's id.
   * @param reason — the failed check.
   */
  constructor(attestorId: string, reason: 'public-key' | 'message' | 'registry-index') {
    super(`attestation from "${attestorId}" failed ${reason} check`);
    this.attestorId = attestorId;
    this.reason = reason;
  }
}

/**
 * Fewer than the required threshold of valid attestations were collected.
 */
export class ThresholdNotMetError extends Error {
  /** How many valid attestations were collected. */
  readonly had: number;
  /** The threshold N required. */
  readonly needed: number;
  /** The attestors that could not be reached during collection. */
  readonly unavailable: readonly AttestorUnavailableError[];

  /**
   * @param had — how many valid attestations were collected.
   * @param needed — the threshold N required.
   * @param unavailable — the attestors that could not be reached.
   */
  constructor(had: number, needed: number, unavailable: readonly AttestorUnavailableError[]) {
    super(`threshold not met: ${had}/${needed}`);
    this.had = had;
    this.needed = needed;
    this.unavailable = unavailable;
  }
}

/**
 * Request attestations from every attestor in the trusted set, in parallel, and
 * assemble the positionally-ordered bundle once at least `threshold` converge.
 *
 * Every attestor is queried (no early-exit); transport failures are recorded,
 * not fatal. A returned attestation is kept only if its public key matches the
 * descriptor's and its signed message agrees with the other kept attestations.
 * If fewer than `threshold` valid attestations remain, a
 * {@link ThresholdNotMetError} is thrown. The input is forwarded raw — this
 * package does not validate it against the definition's schemas.
 *
 * @param options — the trusted set, the N-of-M threshold (N), the raw input,
 *   and the transport.
 * @returns the positionally-ordered {@link AttestationBundle}.
 * @throws {@link ThresholdNotMetError} if fewer than `threshold` valid
 *   attestations were collected.
 * @throws {@link AttestationMismatchError} if a kept attestation fails a
 *   structural integrity check.
 */
export async function collectAttestations<
  const D extends AttestorDefinition<string, z.ZodType, z.ZodType, z.ZodType>,
  PK,
  S,
>(options: {
  /** The trusted set; its order defines the registry slots. */
  trusted: TrustedSet<D, PK>;
  /** The N-of-M threshold (N). */
  threshold: number;
  /** The raw (unparsed) input to forward to every attestor. */
  input: AttestationInput<z.input<D['policy']>, z.input<D['evidence']>, z.input<D['claim']>>;
  /** How the client reaches the attestors. */
  transport: AttestorTransport<D, PK, S>;
}): Promise<AttestationBundle<z.output<D['claim']>, MessageOf<D>, PK, S>> {
  const { trusted, threshold, input, transport } = options;

  if (threshold < 1) {
    throw new ThresholdNotMetError(0, threshold, []);
  }

  const outcomes = await Promise.allSettled(
    trusted.attestors.map((attestor) =>
      transport.request(attestor, input).then(
        (attestation) => ({ attestor, attestation }) as const,
        (cause: unknown) => {
          throw new AttestorUnavailableError(attestor.id, cause);
        },
      ),
    ),
  );

  const successes: {
    attestor: AttestorDescriptor<D, PK>;
    attestation: Attestation<D['kind'], z.output<D['claim']>, PK, S, MessageOf<D>>;
  }[] = [];
  const unavailable: AttestorUnavailableError[] = [];

  for (const outcome of outcomes) {
    if (outcome.status === 'fulfilled') {
      successes.push(outcome.value);
    } else {
      unavailable.push(outcome.reason as AttestorUnavailableError);
    }
  }

  let reference: Attestation<D['kind'], z.output<D['claim']>, PK, S, MessageOf<D>> | null = null;
  for (const { attestor, attestation } of successes) {
    if (!structuredEquals(attestation.publicKey, attestor.publicKey)) {
      throw new AttestationMismatchError(attestor.id, 'public-key');
    }
    if (reference !== null && !structuredEquals(attestation.message, reference.message)) {
      throw new AttestationMismatchError(attestor.id, 'message');
    }
    reference ??= attestation;
  }

  if (successes.length < threshold) {
    throw new ThresholdNotMetError(successes.length, threshold, unavailable);
  }
  if (reference === null) {
    // threshold >= 1 means at least one success, which always sets `reference`.
    throw new ThresholdNotMetError(0, threshold, unavailable);
  }

  const m = trusted.attestors.length;
  const signatures: (S | null)[] = new Array<S | null>(m).fill(null);
  const publicKeys: (PK | null)[] = new Array<PK | null>(m).fill(null);
  const registryIndexes: number[] = [];

  for (const { attestor, attestation } of successes) {
    if (attestor.registryIndex < 0 || attestor.registryIndex >= m) {
      throw new AttestationMismatchError(attestor.id, 'registry-index');
    }
    signatures[attestor.registryIndex] = attestation.signature;
    publicKeys[attestor.registryIndex] = attestation.publicKey;
    registryIndexes.push(attestor.registryIndex);
  }

  return {
    claim: reference.claim,
    message: reference.message,
    signatures,
    publicKeys,
    registryIndexes: registryIndexes.sort(),
  };
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
