// The presentation verifier backed by the thoth-tlsn binary's `verify` subcommand.

import type { TlsnPresentationVerifier } from '../index.js';
import { runNative, TlsnNativeError } from '../native.js';

export { TlsnNativeError };

/**
 * A {@link TlsnPresentationVerifier} that runs `thoth-tlsn verify`.
 *
 * @example
 * ```ts
 * const verifier = nativePresentationVerifier({ binary: '/usr/local/bin/thoth-tlsn' });
 * ```
 */
export const nativePresentationVerifier = (options: {
  /** Path to the `thoth-tlsn` binary. */
  binary: string;
  /** A DER root certificate to trust in place of the Mozilla roots, for test servers. */
  rootCert?: string;
  /** Defaults to 30 seconds. */
  timeoutMs?: number;
}): TlsnPresentationVerifier => ({
  verify: (presentation) =>
    runNative({
      binary: options.binary,
      args: [
        'verify',
        ...(options.rootCert === undefined ? [] : ['--root-cert', options.rootCert]),
      ],
      stdin: JSON.stringify({ presentation }),
      timeoutMs: options.timeoutMs ?? 30_000,
    }),
});
