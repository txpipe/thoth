/**
 * A collected attestation failed a check in `resolveAttestation`; `reason`
 * names it. A verifier that returns `false` or throws is a `'signature'`
 * mismatch.
 */
export class AttestationMismatchError extends Error {
  /** The offending attestor's id. */
  readonly attestorId: string;
  /** Which check failed. */
  readonly reason: 'public-key' | 'message' | 'claim' | 'signature';

  constructor(attestorId: string, reason: 'public-key' | 'message' | 'claim' | 'signature') {
    super(`attestation from "${attestorId}" failed ${reason} check`);
    this.attestorId = attestorId;
    this.reason = reason;
  }
}

/** A named attestor is not a member of the trusted set. */
export class AttestorNotInTrustedSetError extends Error {
  /** The id that was looked up. */
  readonly attestorId: string;

  constructor(attestorId: string) {
    super(`attestor "${attestorId}" is not in the trusted set`);
    this.attestorId = attestorId;
  }
}

/** The check an {@link InvalidTrustedSetError} reports. */
export type TrustedSetInvariant =
  | 'registry-size'
  | 'empty'
  | 'duplicate-id'
  | 'duplicate-key'
  | 'registry-index'
  | 'duplicate-slot';

/** A trusted set failed a check in `buildTrustedSet`; `reason` names it. */
export class InvalidTrustedSetError extends Error {
  /** The offending attestor's id; `''` for `'empty'` and `'registry-size'`. */
  readonly attestorId: string;
  /** Which check failed. */
  readonly reason: TrustedSetInvariant;

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
