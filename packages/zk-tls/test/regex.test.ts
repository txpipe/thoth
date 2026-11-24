// Policy regexes are RE2: zkFetchPolicySchema refuses one RE2 can't compile, and the prover's
// attestor-core runs them with RE2 once `re2` has loaded.

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { type ZkFetchPolicy, zkFetchPolicySchema } from '@txpipe/thoth-zk-tls';
import { describe, expect, it } from 'vitest';

/** Every regex in the repo's examples, fixtures and docs. */
const REPO_REGEXES = [
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
  '"price":(?<price>\\d+)',
  '"price":\\d+',
  '"q":\\s*(?<q>\\d+)',
  '"q":\\s*\\d+',
  '"stargazers_count":\\s*(?<stars>\\d+)',
  '"stargazers_count":\\s*\\d+',
  '"volume":\\s*(?<volume>\\d+)',
  '"moving_time":\\s*(?<data>[\\d.]+)',
  '"moving_time":\\s*(?<distance>[\\d.]+)',
  'a',
  'b',
  'x',
];

/** Syntax only RE2 reads, accepted because RE2 is the engine that runs it. */
const RE2_SYNTAX = ['(?i)a', '(?P<n>a)', '\\pL+', '\\Aa\\z', '[[:digit:]]+'];

const policyWith = (
  rules: Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'>,
): ZkFetchPolicy => ({
  allowedHosts: ['example.com'],
  slots: [{ slot: 0, name: 'v', parse: 'int' }],
  bodyPolicy: 'ignored',
  ...rules,
});

const matchPolicy = (value: string) =>
  policyWith({
    // The second match covers the slot, so each case tests only `value`.
    responseMatches: [
      { type: 'regex', value },
      { type: 'regex', value: '(?<v>.*)' },
    ],
    responseRedactions: [],
  });

const redactionPolicy = (regex: string) =>
  policyWith({
    responseMatches: [{ type: 'regex', value: '(?<v>.*)' }],
    responseRedactions: [{ regex }],
  });

describe('policy regexes', () => {
  it.each([...REPO_REGEXES, ...RE2_SYNTAX])(
    'accepts %s as a match and as a redaction',
    (source) => {
      expect(() => zkFetchPolicySchema.parse(matchPolicy(source))).not.toThrow();
      expect(() => zkFetchPolicySchema.parse(redactionPolicy(source))).not.toThrow();
    },
  );

  it.each([
    ['(?=x)a', /invalid perl operator: \(\?=/],
    ['a(?!x)', /invalid perl operator: \(\?!/],
    ['(?<=x)a', /invalid perl operator: \(\?<=/],
    ['(?<!x)a', /invalid perl operator: \(\?<!/],
    ['(a)\\1', /invalid escape sequence: \\1/],
    ['(?<n>a)\\k<n>', /invalid escape sequence: \\k/],
    ['\\p{Nope}', /invalid character class range/],
    ['(?<x>a)(?<x>b)', /duplicate capture group name/],
    ['a{1001}', /invalid repetition size/],
    ['(?:a{100}){11}', /invalid repetition size/],
    [`(?:${'\\W{1000}'.repeat(16)})`, /pattern too large/],
    ['(a', /missing \)/],
    ['*a', /no argument for repetition operator/],
  ])('refuses %s with RE2s reason', (source, reason) => {
    for (const policy of [matchPolicy(source), redactionPolicy(source)]) {
      const parsed = zkFetchPolicySchema.safeParse(policy);
      expect(parsed.success).toBe(false);
      const messages = parsed.error?.issues.map((issue) => issue.message) ?? [];
      expect(messages).toHaveLength(1);
      expect(messages[0]).toMatch(/^regex does not compile under RE2: /);
      expect(messages[0]).toMatch(reason);
    }
  });

  it.each([
    ['deep groups', `${'(?:'.repeat(1365)}a${')'.repeat(1365)}`],
    ['many named groups', Array.from({ length: 400 }, (_, i) => `(?<g${i}>a)`).join('')],
    ['a long pattern', 'a'.repeat(4096)],
  ])('checks %s quickly, without throwing out of safeParse', (_label, source) => {
    const started = performance.now();
    expect(() => zkFetchPolicySchema.safeParse(matchPolicy(source))).not.toThrow();
    expect(performance.now() - started).toBeLessThan(250);
  });

  it('does not read a contains value or an empty redaction regex as a regex', () => {
    const policy = policyWith({
      responseMatches: [
        { type: 'contains', value: '(?=x' },
        { type: 'regex', value: '(?<v>.*)' },
      ],
      responseRedactions: [{ regex: '', jsonPath: '$.a' }],
    });
    expect(() => zkFetchPolicySchema.parse(policy)).not.toThrow();
  });
});

// The prover awaits `re2` after importing attestor-core, which loads it asynchronously and runs
// regexes with RegExp until then. A fresh process repeats the prover's imports, so this pins that
// ordering on the attestor-core version in package.json.
describe("attestor-core's regex engine", () => {
  // `(?i)` is a syntax error under RegExp, so the redaction compiles only under RE2.
  const PROBE = `
    const silent = { debug() {}, error() {}, info() {}, trace() {}, warn() {}, child: () => silent };
    const engine = (core) => {
      try {
        core.providers.http.getResponseRedactions({
          response: new TextEncoder().encode('HTTP/1.1 200 OK\\r\\nContent-Length: 1\\r\\n\\r\\na'),
          params: { url: 'https://example.com', method: 'GET', responseMatches: [],
            responseRedactions: [{ regex: '(?i)a' }] },
          logger: silent,
          ctx: {},
        });
        return 'RE2';
      } catch {
        return 'RegExp';
      }
    };
    const [core] = await Promise.all([
      import('@reclaimprotocol/attestor-core'),
      import('@reclaimprotocol/tls'),
      import('@reclaimprotocol/tls/webcrypto'),
    ]);
    const before = engine(core);
    await import('re2');
    console.log(JSON.stringify({ before, after: engine(core) }));
  `;

  it('runs policy regexes with RE2 once the prover has awaited re2', () => {
    const output = execFileSync(process.execPath, ['--input-type=module', '-e', PROBE], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
      encoding: 'utf8',
    });
    const lines = output.trim().split('\n');
    expect(JSON.parse(lines[lines.length - 1] ?? '')).toEqual({ before: 'RegExp', after: 'RE2' });
  }, 30_000);
});
