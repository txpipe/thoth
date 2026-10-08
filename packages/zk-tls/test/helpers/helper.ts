// Shared test fixtures: artifacts the zkFetch suites reuse so they do not
// drift apart. The disclosure rules below mirror the prover's default
// whole-response match (`(?<data>.*)`, see `src/prover/index.ts`).

import type { ZkFetchPolicy } from '@thoth/zk-tls';

/**
 * The disclosure rules every default policy and witness observation in the
 * test suites shares: the prover's default whole-response match and no
 * redactions.
 */
export const DISCLOSURE_RULES: Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'> = {
  responseMatches: [{ type: 'regex', value: '(?<data>.*)' }],
  responseRedactions: [],
};
