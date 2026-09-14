/**
 * A collected attestation failed a structural integrity check.
 *
 * `reason` discriminates the failing check: the returned public key does not
 * match the descriptor's (`'public-key'`), the signed message disagrees with
 * the other collected attestation's (`'message'`), or the attestor's
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
