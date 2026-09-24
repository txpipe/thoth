/** Which {@link AttestationMismatchError} check failed. */
export type MismatchReason = 'public-key' | 'message' | 'registry-index' | 'signature';

/**
 * A collected attestation failed a structural integrity check.
 *
 * `reason` discriminates the failing check: the returned public key does not
 * match the descriptor's (`'public-key'`), the signed message disagrees with
 * the other collected attestation's (`'message'`), the attestor's
 * `registryIndex` is outside the trusted set's slot range (`'registry-index'`),
 * or the signature does not verify under the attestor's key (`'signature'`).
 */
export class AttestationMismatchError extends Error {
  /** The id of the offending attestor. */
  readonly attestorId: string;
  /** Which integrity check failed. */
  readonly reason: MismatchReason;

  /**
   * @param attestorId — the offending attestor's id.
   * @param reason — the failed check.
   */
  constructor(attestorId: string, reason: MismatchReason) {
    super(`attestation from "${attestorId}" failed ${reason} check`);
    this.attestorId = attestorId;
    this.reason = reason;
  }
}

/**
 * A named attestor is not a member of the trusted set.
 */
export class AttestorNotInTrustedSetError extends Error {
  /** The id that was looked up. */
  readonly attestorId: string;

  /**
   * @param attestorId — the id that was looked up.
   */
  constructor(attestorId: string) {
    super(`attestor "${attestorId}" is not in the trusted set`);
    this.attestorId = attestorId;
  }
}

/**
 * A trusted set failed its construction invariants.
 *
 * `reason` discriminates the failing check: an empty set (`'empty'`), two
 * members with the same `id` (`'duplicate-id'`), two members claiming the same
 * registry slot (`'duplicate-slot'`), or a `registryIndex` outside the set's
 * own range (`'registry-index'`).
 */
export class InvalidTrustedSetError extends Error {
  /** The offending attestor's id (`''` for a failed `'empty'` check). */
  readonly attestorId: string;
  /** Which construction invariant failed. */
  readonly reason: 'empty' | 'duplicate-id' | 'registry-index' | 'duplicate-slot';

  /**
   * @param attestorId — the offending attestor's id.
   * @param reason — the failed construction check.
   */
  constructor(
    attestorId: string,
    reason: 'empty' | 'duplicate-id' | 'registry-index' | 'duplicate-slot',
  ) {
    const detail: Record<'empty' | 'duplicate-id' | 'registry-index' | 'duplicate-slot', string> = {
      empty: 'the trusted set is empty',
      'duplicate-id': `attestor "${attestorId}" appears more than once`,
      'registry-index': `attestor "${attestorId}" has a registryIndex outside the set`,
      'duplicate-slot': `attestor "${attestorId}" claims an already-taken registry slot`,
    };
    super(`invalid trusted set: ${detail[reason]}`);
    this.attestorId = attestorId;
    this.reason = reason;
  }
}

/** Why an attestor's answer did not count; see {@link AttestorFailureError}. */
export type AttestorFailureReason = 'unreachable' | 'rejected' | 'message' | 'signature';

/**
 * One attestor did not contribute to a threshold attestation.
 *
 * `reason` discriminates what went wrong: the attestor (or the session feeding
 * it) could not be reached or timed out (`'unreachable'`), it refused the
 * request (`'rejected'`), it signed a different message than the one that won
 * (`'message'`), or its signature does not verify under its pinned key
 * (`'signature'`). The underlying error, if any, is the `cause`.
 *
 * A transport throws this with `'rejected'` when the attestor answered with a
 * refusal; anything else a transport throws is treated as `'unreachable'`.
 */
export class AttestorFailureError extends Error {
  /** The id of the failed attestor. */
  readonly attestorId: string;
  /** What went wrong. */
  readonly reason: AttestorFailureReason;

  /**
   * @param attestorId — the failed attestor's id.
   * @param reason — what went wrong.
   * @param cause — the underlying error, whose message is appended.
   */
  constructor(attestorId: string, reason: AttestorFailureReason, cause?: unknown) {
    const detail: Record<AttestorFailureReason, string> = {
      unreachable: 'was unreachable',
      rejected: 'rejected the request',
      message: 'returned a different message',
      signature: 'returned an invalid signature',
    };
    const why = cause instanceof Error ? `: ${cause.message}` : '';
    super(`attestor "${attestorId}" ${detail[reason]}${why}`, { cause });
    this.attestorId = attestorId;
    this.reason = reason;
  }
}
