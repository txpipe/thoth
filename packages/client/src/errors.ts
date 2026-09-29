/**
 * A collected attestation failed vetting.
 *
 * `reason` identifies a key, message, registry slot, claim, or signature
 * mismatch. Verifier failures, including thrown errors, count as signature
 * mismatches.
 */
export class AttestationMismatchError extends Error {
  /** The id of the offending attestor. */
  readonly attestorId: string;
  /** Which integrity check failed. */
  readonly reason: 'public-key' | 'message' | 'registry-index' | 'claim' | 'signature';

  /**
   * @param attestorId — the offending attestor's id.
   * @param reason — the failed check.
   */
  constructor(
    attestorId: string,
    reason: 'public-key' | 'message' | 'registry-index' | 'claim' | 'signature',
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

/** A {@link InvalidTrustedSetError} construction invariant. */
export type TrustedSetInvariant =
  | 'registry-size'
  | 'empty'
  | 'duplicate-id'
  | 'duplicate-key'
  | 'registry-index'
  | 'duplicate-slot';

/**
 * A trusted set failed its construction invariants.
 *
 * `reason` discriminates the failing check: a `registrySize` that is not a
 * positive integer (`'registry-size'`), an empty set (`'empty'`), two members
 * with the same `id` (`'duplicate-id'`), two members pinning the same public
 * key (`'duplicate-key'`), two members assigned the same
 * registry slot (`'duplicate-slot'`), or a `registryIndex` outside
 * `[0, registrySize)` (`'registry-index'`).
 */
export class InvalidTrustedSetError extends Error {
  /** The offending attestor's id (`''` for a failed `'empty'` or `'registry-size'` check). */
  readonly attestorId: string;
  /** Which construction invariant failed. */
  readonly reason: TrustedSetInvariant;

  /**
   * @param attestorId — the offending attestor's id.
   * @param reason — the failed construction check.
   */
  constructor(attestorId: string, reason: TrustedSetInvariant) {
    const detail: Record<TrustedSetInvariant, string> = {
      'registry-size': 'the registry size is not a positive integer',
      empty: 'the trusted set is empty',
      'duplicate-id': `attestor "${attestorId}" appears more than once`,
      'registry-index': `attestor "${attestorId}" has a registryIndex outside the registry`,
      'duplicate-key': `attestor "${attestorId}" pins an already-pinned public key`,
      'duplicate-slot': `attestor "${attestorId}" claims an already-taken registry slot`,
    };
    super(`invalid trusted set: ${detail[reason]}`);
    this.attestorId = attestorId;
    this.reason = reason;
  }
}
