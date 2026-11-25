// Shared test fixtures and builders for the zkFetch suites so they do not drift
// apart. Keeps Reclaim- and zkFetch-specific helpers inside this package.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Claim } from '@txpipe/thoth-core/claim';
import { filled } from '@txpipe/thoth-test-utils/bytes';
import { parseEnvList } from '@txpipe/thoth-test-utils/env';
import { disclosureRulesOf } from '@txpipe/thoth-test-utils/zk-fetch';
import {
  deriveClaimFromEvidence,
  type VerifiedEvidence,
  type ZkFetchPolicy,
} from '@txpipe/thoth-zk-tls';

/** Fixed 32-byte app id shared across the zkFetch test suites. */
export const APP_ID = filled(0xa1);

/** Fixed 32-byte holder commitment shared across the zkFetch test suites. */
export const HOLDER = filled(0xc1);

/** Default observation timestamp (Unix seconds) shared by offline zkFetch tests. */
export const DEFAULT_TIMESTAMP_S = 1_786_122_944;

/** Parse `WITNESS_URLS` into trimmed non-empty URLs; empty keeps live suites skipped. */
export const parseWitnessUrls = (): string[] => parseEnvList('WITNESS_URLS');

/**
 * Build a `ZkFetchPolicy` for `slots` with `api.github.com` allowlisted,
 * `bodyPolicy: 'ignored'`, and matching regex disclosure rules.
 */
export const policyWithSlots = (
  slots: ZkFetchPolicy['slots'],
  overrides: Partial<Omit<ZkFetchPolicy, 'slots'>> = {},
): ZkFetchPolicy => ({
  allowedHosts: ['api.github.com'],
  slots,
  bodyPolicy: 'ignored',
  ...disclosureRulesOf(slots),
  ...overrides,
});

/** Derive a zkFetch claim with fixture defaults for appId, holder, slots and window. */
export const deriveClaim = (options: {
  verified: VerifiedEvidence;
  policy: ZkFetchPolicy;
  appId?: Uint8Array;
  holder?: Uint8Array;
  valueSlots?: number;
  byteSlots?: number;
  windowStart?: bigint;
  windowEnd?: bigint;
}): Claim<number, number> =>
  deriveClaimFromEvidence({
    verified: options.verified,
    policy: options.policy,
    appId: options.appId ?? APP_ID,
    holder: options.holder ?? HOLDER,
    valueSlots: options.valueSlots ?? 1,
    byteSlots: options.byteSlots,
    windowStart: options.windowStart ?? BigInt(DEFAULT_TIMESTAMP_S),
    windowEnd: options.windowEnd ?? BigInt(DEFAULT_TIMESTAMP_S),
  });

/** Unparsed claim input fixture shared by the claim-schema and input-limit suites. */
export const sampleClaimInput = (overrides: Record<string, unknown> = {}) => ({
  version: 1,
  appId: APP_ID,
  holder: HOLDER,
  salt: filled(0xcd),
  policyHash: new Uint8Array(32),
  windowStart: DEFAULT_TIMESTAMP_S,
  windowEnd: DEFAULT_TIMESTAMP_S,
  subjectHash: new Uint8Array(32),
  present: [false],
  values: [0],
  ...overrides,
});

/** Wrap a transport to count calls and record which attestor ids were contacted. */
export const countingTransport = <A extends { readonly id: string }, I, O>(base: {
  request(attestor: A, input: I): Promise<O>;
}) => {
  let count = 0;
  const contactedIds = new Set<string>();
  const transport = {
    request: async (attestor: A, input: I): Promise<O> => {
      count += 1;
      contactedIds.add(attestor.id);
      return base.request(attestor, input);
    },
  };
  return {
    transport,
    calls: () => count,
    contacted: (id: string) => contactedIds.has(id),
  };
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
