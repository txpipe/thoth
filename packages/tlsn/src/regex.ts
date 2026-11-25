// Policy regexes run under RE2 with the flags Reclaim's witness uses (`sgiu`), so a
// policy reads the same response the same way under tlsn@1 and zkFetch.

import { createRequire } from 'node:module';

type RE2Constructor = new (source: string, flags: string) => RegExp;

/** The flags Reclaim's attestor-core passes to RE2 for every response rule. */
const WITNESS_FLAGS = 'sgiu';

let re2: RE2Constructor | undefined;

// Loaded on first use, so importing the package does not load the native module.
const loadRe2 = (): RE2Constructor => {
  re2 ??= createRequire(import.meta.url)('re2') as RE2Constructor;
  return re2;
};

/**
 * Compile a response rule as the witness does.
 *
 * @throws if RE2 cannot compile it, or the native `re2` module does not load.
 */
export const compileRule = (source: string): RegExp => new (loadRe2())(source, WITNESS_FLAGS);

/** Why RE2 refuses `source`, or `undefined` when it compiles. */
export const ruleCompileError = (source: string): string | undefined => {
  try {
    compileRule(source);
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};

/**
 * The named groups `source` declares, or `undefined` when RE2 refuses it.
 *
 * A leading empty alternative matches the empty string, and RE2 reports every
 * declared group in a match, so one match lists them all.
 */
export const ruleGroupNames = (source: string): ReadonlySet<string> | undefined => {
  try {
    return new Set(Object.keys(compileRule(`|${source}`).exec('')?.groups ?? {}));
  } catch {
    return undefined;
  }
};
