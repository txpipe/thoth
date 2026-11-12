// The error a prover throws to give `collect` a failure reason. Both the client
// and the prover entry points import it, so it imports nothing itself.

/**
 * A prover failure with a reason `collect` reports: `transport` or `no-match`.
 * The package README's "Guarantees and limits" says what each one means. Its
 * message carries no remote error text.
 */
export class ZkFetchProverError extends Error {
  /** Why the prover failed. */
  readonly reason: 'transport' | 'no-match';

  /**
   * Build the error from its reason.
   *
   * @param options — `cause` is the underlying error, kept for local logs; `collect` drops it.
   */
  constructor(reason: ZkFetchProverError['reason'], options?: ErrorOptions) {
    super(`zkFetch prover failed: ${reason}`, options);
    this.name = 'ZkFetchProverError';
    this.reason = reason;
  }
}
