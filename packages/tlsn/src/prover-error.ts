// The error a prover throws to give `collect` a failure reason. Both the client and
// the prover entry points import it, so it imports nothing itself.

/**
 * A prover failure with a reason `collect` reports: `transport` when the notary
 * or the source cannot be reached, `no-match` when the response is not a 2xx or
 * fails the policy's redaction rules. Its message carries no remote error text.
 */
export class TlsnProverError extends Error {
  /** Why the prover failed. */
  readonly reason: 'transport' | 'no-match';

  /**
   * Build the error from its reason.
   *
   * @param options — `cause` is the underlying error, kept for local logs; `collect` drops it.
   */
  constructor(reason: TlsnProverError['reason'], options?: ErrorOptions) {
    super(`tlsn prover failed: ${reason}`, options);
    this.name = 'TlsnProverError';
    this.reason = reason;
  }
}
