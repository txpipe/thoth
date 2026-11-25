// The zkFetch witness's response check, run by the tlsn@1 attestor on the redacted text:
// every rule must hold, and each regex's named groups become the disclosed values.

import { compileRule } from './regex.js';

/** One response pattern; its named groups become disclosed values. */
export interface TlsnResponseMatch {
  /** `regex` extracts named groups; `contains` only guards the response. */
  type: 'regex' | 'contains';
  value: string;
}

/**
 * Run the response rules over the redacted response text, as the zkFetch
 * witness does, and return the disclosed values by group name.
 *
 * @throws if a regex does not match, a `contains` text is absent, or two
 *   regexes disclose the same group name.
 */
export const disclosedValuesOf = (
  text: string,
  matches: readonly TlsnResponseMatch[],
): Readonly<Record<string, string>> => {
  // A null prototype, so a group named like an Object method stays a plain key.
  const disclosed: Record<string, string> = Object.create(null);
  for (const { type, value } of matches) {
    if (type === 'contains') {
      if (!text.includes(value)) {
        throw new Error(`the response does not contain ${JSON.stringify(value)}`);
      }
      continue;
    }
    const match = compileRule(value).exec(text);
    if (match === null) {
      throw new Error(`the response does not match ${JSON.stringify(value)}`);
    }
    for (const [name, group] of Object.entries(match.groups ?? {})) {
      if (Object.hasOwn(disclosed, name)) {
        throw new Error(`two response matches disclose ${JSON.stringify(name)}`);
      }
      if (typeof group === 'string') {
        disclosed[name] = group;
      }
    }
  }
  return disclosed;
};
