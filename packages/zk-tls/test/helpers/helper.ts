// Shared test fixtures: artifacts the zkFetch suites reuse so they do not
// drift apart. The disclosure rules below build one whole-response match,
// `(?<name>.*)`, for each slot name a policy declares.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ZkFetchPolicy } from '@thoth/zk-tls';

/**
 * The disclosure rules a fixture policy needs to certify `names`: one
 * whole-response `regex` match per name, and no redactions. A policy slot must
 * be a named group of a `regex` match, so build the rules from its slots.
 */
export const disclosureRules = (
  ...names: readonly string[]
): Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'> => ({
  responseMatches: names.map((name) => ({ type: 'regex', value: `(?<${name}>.*)` })),
  responseRedactions: [],
});

/** {@link disclosureRules} for the names of `slots`. */
export const disclosureRulesOf = (
  slots: ZkFetchPolicy['slots'],
): Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'> =>
  disclosureRules(...slots.map(({ name }) => name));

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
