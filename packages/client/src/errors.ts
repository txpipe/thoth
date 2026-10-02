/**
 * A collected attestation failed vetting.
 *
 * `reason` identifies a key, message, registry slot, kind, claim, or signature
 * mismatch. Verifier failures, including thrown errors, count as signature
 * mismatches.
 */
export class AttestationMismatchError extends Error {
  /** The id of the offending attestor. */
  readonly attestorId: string;
  /** Which integrity check failed. */
  readonly reason: 'public-key' | 'message' | 'registry-index' | 'kind' | 'claim' | 'signature';

  /**
   * @param attestorId — the offending attestor's id.
   * @param reason — the failed check.
   */
  constructor(
    attestorId: string,
    reason: 'public-key' | 'message' | 'registry-index' | 'kind' | 'claim' | 'signature',
  ) {
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
