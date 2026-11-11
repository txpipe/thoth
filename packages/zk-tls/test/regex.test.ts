// The regex subset: zkFetchPolicySchema accepts a regex only when RE2 and RegExp, under the
// flags Reclaim compiles with, accept it and match it the same way.
//
// Reclaim compiles with RE2 ('sgiu') when the optional native `re2` module loaded, else with
// RegExp: 'sgiu' in attestor-core 5.0.x, 'sgi' in 5.1.x. The RE2 side skips when `re2` does not
// load on this machine.

import { createRequire } from 'node:module';
import { type ZkFetchPolicy, zkFetchPolicySchema } from '@thoth/zk-tls';
import { describe, expect, it } from 'vitest';

type Compile = (source: string) => RegExp;

const loadRe2 = (): Compile | undefined => {
  try {
    const RE2 = createRequire(import.meta.url)('re2') as new (s: string, f: string) => RegExp;
    return (source) => new RE2(source, 'sgiu');
  } catch {
    return undefined;
  }
};

const re2 = loadRe2();

const ENGINES: Readonly<Record<string, Compile>> = {
  'RegExp sgi': (source) => new RegExp(source, 'sgi'),
  'RegExp sgiu': (source) => new RegExp(source, 'sgiu'),
  ...(re2 === undefined ? {} : { 'RE2 sgiu': re2 }),
};

/** Every regex in the repo's examples, fixtures and docs, plus the rest of the subset. */
const ACCEPTED = [
  '(?<data>.*)',
  '(?<distance>[\\d.]+)',
  '(?<distance>[0-9.]+)',
  '(?<token>secret-[0-9]+)',
  '"distance":\\s*(?<distance>[\\d.]+)',
  '"distance":\\s*[\\d.]+',
  '"fee":\\s*(?<price>\\d+)',
  '"full_name":\\s*"(?<name>[^"]+)"',
  '"full_name":\\s*"[^"]*"',
  '"moving_time":\\s*(?<movingTime>\\d+)',
  '"moving_time":\\s*(?<price>[\\d.]+)',
  '"moving_time":\\s*[\\d.]+',
  '"moving_time":\\s*\\d+',
  '"price":\\s*(?<price>\\d+)',
  '"price":\\s*\\d+',
  '"q":\\s*(?<q>\\d+)',
  '"stargazers_count":\\s*(?<stars>\\d+)',
  '"stargazers_count":\\s*\\d+',
  '"volume":\\s*(?<volume>\\d+)',
  'a',
  'b',
  '^HTTP/1\\.1 (\\d{3})$',
  '\\bid\\b:\\B',
  '(?:ab|a)(?:c|bcd)\\w*?',
  '[\\w-]+@[^\\s\\]]{2,}',
  '[-a-c]x[a-c-]',
  '\\x41\\t\\n\\r\\f\\v\\/\\{\\}\\[\\]\\(\\)\\|\\^\\$\\.\\*\\+\\?\\\\',
  '(?<first>[A-Z])(?<second>[a-z]{1,3}?)(?:\\d{2,})?',
  '.{1000}',
];

/**
 * ASCII response text. The vertical tab sits where no fixture's `\s` can reach it: RE2's `\s`
 * does not match it, a documented limit.
 */
const TEXTS = [
  '',
  'a',
  'B',
  'HTTP/1.1 200\r\n',
  '{"distance": 1234.5, "moving_time":\t42, "fee": 7}',
  '{"price":12,"q":3,"volume":99,"stargazers_count": 105}',
  '{"full_name": "txpipe/dolos", "secret-123": true}',
  'id: x id:y',
  'abcd abcbcd',
  'me-1@x.org [b] ] -a c-',
  'A\t\n\r\f\v/{}[]()|^$.*+?\\',
  'Kab12 Zz9 Abcd123',
  'x'.repeat(1001),
];

const policyWith = (
  rules: Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'>,
): ZkFetchPolicy => ({
  allowedHosts: ['example.com'],
  slots: [{ slot: 0, name: 'v', parse: 'int' }],
  bodyPolicy: 'ignored',
  ...rules,
});

const matchPolicy = (value: string) =>
  policyWith({ responseMatches: [{ type: 'regex', value }], responseRedactions: [] });

const redactionPolicy = (regex: string) =>
  policyWith({
    responseMatches: [{ type: 'contains', value: 'x' }],
    responseRedactions: [{ regex }],
  });

/** What one engine's `exec` returns, as a comparable string. */
const execOf = (regex: RegExp, text: string): string => {
  regex.lastIndex = 0;
  const match = regex.exec(text);
  return match === null ? 'null' : JSON.stringify([match.index, ...match, match.groups ?? null]);
};

/** Each engine's result for every text, or the engine's compile error. */
const resultsOf = (source: string, engines: Readonly<Record<string, Compile>>) =>
  Object.fromEntries(
    Object.entries(engines).map(([name, compile]) => {
      try {
        const regex = compile(source);
        return [name, TEXTS.map((text) => execOf(regex, text))];
      } catch (error) {
        return [name, `compile error: ${(error as Error).message}`];
      }
    }),
  );

describe('the regex subset', () => {
  it.each(ACCEPTED)('accepts %s as a match and as a redaction', (source) => {
    expect(() => zkFetchPolicySchema.parse(matchPolicy(source))).not.toThrow();
    expect(() => zkFetchPolicySchema.parse(redactionPolicy(source))).not.toThrow();
  });

  it.each(ACCEPTED)('RegExp with and without u reads %s the same way', (source) => {
    const results = resultsOf(source, ENGINES);
    expect(results['RegExp sgiu']).toEqual(results['RegExp sgi']);
  });

  it.skipIf(re2 === undefined).each(ACCEPTED)('RE2 reads %s like RegExp', (source) => {
    const results = resultsOf(source, ENGINES);
    expect(results['RE2 sgiu']).toEqual(results['RegExp sgi']);
  });

  it.each([
    ['(?=x)a', /lookahead \(\?= at index 0/],
    ['a(?!x)', /negative lookahead \(\?! at index 1/],
    ['(?<=x)a', /lookbehind \(\?<= at index 0/],
    ['(?<!x)a', /negative lookbehind \(\?<! at index 0/],
    ['(a)\\1', /backreference \\1 at index 3/],
    ['(?<n>a)\\k<n>', /named backreference \\k at index 7/],
    ['\\p{L}', /Unicode property escape \\p at index 0/],
    ['\\P{L}', /Unicode property escape \\P at index 0/],
    ['(?P<n>a)', /\(\?P group at index 0/],
    ['(?i)a', /inline flags or an unknown group/],
    ['(?i:a)', /inline flags or an unknown group/],
    ['café', /non-ASCII character U\+00E9 at index 3/],
    ['a😀', /non-ASCII character U\+1F600 at index 1/],
    ['\\xE9', /\\x escape above \\x7F/],
    ['\\u0041', /escape \\u/],
    ['\\A', /escape \\A/],
    ['a\\z', /escape \\z/],
    ['\\-', /escape \\-/],
    ['a{', /unescaped \{/],
    ['a{,2}', /unescaped \{/],
    ['}', /unescaped \}/],
    [']', /unescaped \]/],
    ['a)', /unmatched \)/],
    ['(a', /unclosed \(/],
    ['[a', /unclosed \[/],
    ['[]a]', /empty class/],
    ['[^]', /empty class/],
    ['[[:alpha:]]', /unescaped \[ in a class/],
    ['[\\b]', /\\b in a class/],
    ['[\\d-z]', /class escape as a range bound/],
    ['[a-c-e]', /unescaped - that is not first, last or a range/],
    ['[z-a]', /bounds are out of order/],
    ['a{2,1}', /maximum is below its minimum/],
    ['a**', /quantifier on a quantifier/],
    ['a*+', /quantifier on a quantifier/],
    ['*a', /nothing to repeat/],
    ['^*', /match the empty string/],
    ['(?:|a)*', /match the empty string/],
    ['(?:a*?)+', /match the empty string/],
    ['(?:(?<x>a)|b)+', /quantifier on a capture group/],
    ['(a*)?', /quantifier on a capture group/],
    ['(?<x>a)(?<x>b)', /duplicate group name x/],
    ['(?<x>a)|(?<x>b)', /duplicate group name x/],
    ['(?<1x>a)', /group name that is not an ASCII identifier/],
    ['a{1001}', /more than 1000 atoms/],
    ['(?:a{100}){11}', /more than 1000 atoms/],
    ['.{1000}x', /more than 1000 atoms/],
    ['a\tb', /control character U\+0009/],
    ['a\\', /trailing \\/],
  ])('refuses %s, naming the construct', (source, construct) => {
    for (const policy of [matchPolicy(source), redactionPolicy(source)]) {
      const parsed = zkFetchPolicySchema.safeParse(policy);
      expect(parsed.success).toBe(false);
      const messages = parsed.error?.issues.map((issue) => issue.message) ?? [];
      expect(messages).toHaveLength(1);
      expect(messages[0]).toMatch(construct);
      expect(messages[0]).toMatch(/regex subset/);
    }
  });

  it('does not read a contains value or an empty redaction regex as a regex', () => {
    const policy = policyWith({
      responseMatches: [{ type: 'contains', value: '(?=x' }],
      responseRedactions: [{ regex: '', jsonPath: '$.a' }],
    });
    expect(() => zkFetchPolicySchema.parse(policy)).not.toThrow();
  });

  // A seeded walk over a grammar wider than the subset: every pattern the schema accepts must
  // compile in every engine and match every text the same way.
  it('agrees across engines on generated patterns the schema accepts', () => {
    let seed = 198;
    const random = (): number => {
      seed = (seed * 1_103_515_245 + 12_345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
    const ATOMS = [
      ...['a', 'k', 'K', 's', '_', '-', ' ', '"', ':', '.', '^', '$', '\\.', '\\-', '\\t'],
      ...['\\d', '\\D', '\\w', '\\W', '\\s', '\\S', '\\b', '\\B', '\\x2d', '\\]', '\\{'],
      ...['[a-c]', '[^a]', '[\\d.]', '[^"]', '[A-z]', '[Z-a]', '[-a]', '[\\w-]', '[--a]'],
      ...['[^\\W]', '[^\\s]', '[k-s]', '[\\x00-\\x7f]', '{', ']', '\\1', '(?=a)', '\\p{L}'],
    ];
    const QUANTIFIERS = ['', '', '', '*', '+', '?', '*?', '+?', '??', '{2}', '{0,2}', '{1,}'];
    const generate = (depth: number): string => {
      let source = '';
      for (let term = 0; term < 1 + Math.floor(random() * 3); term += 1) {
        const atom =
          depth < 3 && random() < 0.25
            ? `${pick(['(', '(?:', `(?<g${Math.floor(random() * 3)}>`])}${generate(depth + 1)}` +
              `${random() < 0.3 ? `|${random() < 0.3 ? '' : generate(depth + 1)}` : ''})`
            : pick(ATOMS);
        source += atom + pick(QUANTIFIERS);
      }
      return source;
    };
    const ALPHABET = [...'aAbkKsS_- ":.\t\n\r\f/{}]^$x019'];
    const texts = Array.from({ length: 40 }, () =>
      Array.from({ length: Math.floor(random() * 8) }, () => pick(ALPHABET)).join(''),
    );

    let accepted = 0;
    const disagreements: string[] = [];
    for (let attempt = 0; attempt < 3000; attempt += 1) {
      const source = generate(0);
      if (!zkFetchPolicySchema.safeParse(matchPolicy(source)).success) {
        continue;
      }
      accepted += 1;
      const results = Object.entries(ENGINES).map(([name, compile]) => {
        try {
          const regex = compile(source);
          return texts.map((text) => execOf(regex, text)).join('\n');
        } catch (error) {
          return `${name}: ${(error as Error).message}`;
        }
      });
      if (new Set(results).size > 1) {
        disagreements.push(source);
      }
    }
    expect(accepted).toBeGreaterThan(500);
    expect(disagreements).toEqual([]);
  });
});
