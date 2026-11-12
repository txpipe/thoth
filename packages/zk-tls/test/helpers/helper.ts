// Shared test fixtures: artifacts the zkFetch suites reuse so they do not
// drift apart. The disclosure rules below mirror the prover's default
// whole-response match (`(?<data>.*)`, see `src/prover/index.ts`).

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ZkFetchPolicy } from '@thoth/zk-tls';

/** The app id every claim in the test suites is for. */
export const APP_ID = new Uint8Array(32).fill(0xa1);
/** The holder every claim in the test suites is for. */
export const HOLDER = new Uint8Array(32).fill(0xc1);

/**
 * The witnesses the opt-in live suites run against: the comma-separated
 * `WITNESS_URLS` environment variable, empty when it is unset.
 */
export const WITNESS_URLS = (process.env.WITNESS_URLS ?? '')
  .split(',')
  .map((url) => url.trim())
  .filter((url) => url !== '');

/** Lowercase hex of `bytes`. */
export const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** UTF-8 encode `value` and zero-pad it to 32 bytes (the `'bytes'` parse rule). */
export const padded = (value: string): Uint8Array => {
  const out = new Uint8Array(32);
  out.set(new TextEncoder().encode(value));
  return out;
};

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
