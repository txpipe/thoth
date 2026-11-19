// Policy regexes run under RE2 on the prover and on every witness, so the schema checks that
// RE2 compiles each one with the flags Reclaim's attestor-core passes.

import { createRequire } from 'node:module';

type RE2Constructor = new (source: string, flags: string) => RegExp;

/** The flags attestor-core compiles every policy regex with. */
const RECLAIM_FLAGS = 'sgiu';

let re2: RE2Constructor | undefined;

// Loaded on first use, so importing the package doesn't load the native module.
const loadRe2 = (): RE2Constructor => {
  re2 ??= createRequire(import.meta.url)('re2') as RE2Constructor;
  return re2;
};

/**
 * RE2's reason for refusing `source`, or `undefined` when RE2 compiles it.
 *
 * @throws if the native `re2` module does not load.
 */
export const re2CompileError = (source: string): string | undefined => {
  const RE2 = loadRe2();
  try {
    new RE2(source, RECLAIM_FLAGS);
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};

/**
 * The named groups `source` declares, as RE2 reads them; empty when RE2 refuses
 * `source`, which `re2CompileError` reports.
 *
 * @throws if the native `re2` module does not load.
 */
export const re2GroupNames = (source: string): ReadonlySet<string> => {
  const RE2 = loadRe2();
  try {
    // The empty alternative matches '', and a match lists every declared group,
    // matched or not, so RE2 names the groups instead of a parser of its syntax.
    const match = new RE2(`|${source}`, RECLAIM_FLAGS).exec('');
    return new Set(Object.keys(match?.groups ?? {}));
  } catch {
    return new Set();
  }
};
