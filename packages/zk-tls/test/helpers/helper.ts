// Shared test fixtures: artifacts the zkFetch suites reuse so they do not
// drift apart. The disclosure rules below mirror the prover's default
// whole-response match (`(?<data>.*)`, see `src/prover/index.ts`).

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ZkFetchPolicy } from '@txpipe/thoth-zk-tls';

/**
 * The disclosure rules every default policy and witness observation in the
 * test suites shares: the prover's default whole-response match and no
 * redactions.
 */
export const DISCLOSURE_RULES: Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'> = {
  responseMatches: [{ type: 'regex', value: '(?<data>.*)' }],
  responseRedactions: [],
};

/**
 * The recorded evidence in `examples/demo-attestation/fixtures/`: a genuine,
 * offline-verifiable HTTPS fetch a Reclaim witness signed.
 */
export const FIXTURE = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      '..',
      '..',
      '..',
      '..',
      'examples',
      'demo-attestation',
      'fixtures',
      'fixture-github-attestor-core-x-0m.json',
    ),
    'utf-8',
  ),
) as { claim: Record<string, unknown> } & Record<string, unknown>;
