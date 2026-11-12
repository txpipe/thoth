// Policy regexes run under RE2 on the prover and on every witness, so the schema checks that
// RE2 compiles each one with the flags Reclaim's attestor-core passes.

import { createRequire } from 'node:module';

type RE2Constructor = new (source: string, flags: string) => RegExp;

/** The flags attestor-core compiles every policy regex with. */
const RECLAIM_FLAGS = 'sgiu';

let re2: RE2Constructor | undefined;

/**
 * RE2's reason for refusing `source`, or `undefined` when RE2 compiles it.
 *
 * @throws if the native `re2` module does not load.
 */
export const re2CompileError = (source: string): string | undefined => {
  // Loaded on first use, so importing the package doesn't load the native module.
  re2 ??= createRequire(import.meta.url)('re2') as RE2Constructor;
  try {
    new re2(source, RECLAIM_FLAGS);
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};
