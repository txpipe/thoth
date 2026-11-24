// The host allowlist: which attested URLs a policy's `allowedHosts` admits, and
// which entries the policy schema refuses.
import {
  assertEvidenceMatchesPolicy,
  normalizePolicy,
  parsedEvidenceView,
  ZK_FETCH_CLAIM_CONTEXT_KEY,
  type ZkFetchPolicy,
  zkFetchClaimContextDigestOf,
  zkFetchPolicyHashOf,
} from '@txpipe/thoth-zk-tls';
import { describe, expect, it } from 'vitest';
import { disclosureRules } from './helpers/helper.js';
import { testWitness } from './helpers/witness.js';

const witness = testWitness(`0x${'11'.repeat(32)}`);

const policyFor = (allowedHosts: string[]): ZkFetchPolicy => ({
  allowedHosts,
  slots: [{ slot: 0, name: 'balance', parse: 'int' }],
  bodyPolicy: 'ignored',
  ...disclosureRules('balance'),
});

/** Check evidence a witness signed for `url` against a policy allowing `allowedHosts`. */
const check = async (allowedHosts: string[], url: string): Promise<string> => {
  const policy = policyFor(allowedHosts);
  const parameters = { url, method: 'GET', body: '', ...disclosureRules('balance') };
  const evidence = await witness.sign({
    values: { balance: '1' },
    timestampS: 1_786_000_000,
    parameters,
    context: {
      [ZK_FETCH_CLAIM_CONTEXT_KEY]: zkFetchClaimContextDigestOf({
        policy,
        request: { url, method: 'GET', body: '' },
        holder: new Uint8Array(32).fill(0xc1),
        windowStart: 1_786_000_000n,
        windowEnd: 1_786_000_010n,
      }),
    },
  });
  return assertEvidenceMatchesPolicy(parsedEvidenceView(evidence), policy);
};

describe('allowedHosts entries', () => {
  it.each([[''], ['   '], ['.'], ['..']])('refuses the empty entry %j', (entry) => {
    expect(() => zkFetchPolicyHashOf(policyFor(['api.example.com', entry]))).toThrow(
      /allowedHosts/,
    );
  });

  it.each([
    ['api.example.com:0'],
    ['api.example.com:65536'],
    ['api.example.com:'],
    ['api.example.com/v1'],
    ['api example.com'],
  ])('refuses the malformed entry %j', (entry) => {
    expect(() => zkFetchPolicyHashOf(policyFor([entry]))).toThrow(/allowedHosts/);
  });

  it('normalizes case, trailing dots and the default port', () => {
    expect(
      normalizePolicy(
        policyFor(['API.example.com.', 'api.example.com:443', 'b.example:8443', 'b.example.:8443']),
      ).allowedHosts,
    ).toEqual(['api.example.com', 'b.example:8443']);
  });
});

describe('the host check', () => {
  it('admits the exact host and its subdomains on the default port', async () => {
    await expect(check(['example.com'], 'https://example.com/x')).resolves.toBe('example.com');
    await expect(check(['example.com'], 'https://api.example.com/x')).resolves.toBe(
      'api.example.com',
    );
    await expect(check(['example.com'], 'https://api.example.com:443/x')).resolves.toBe(
      'api.example.com',
    );
  });

  it('does not admit a host that only shares a suffix', async () => {
    await expect(check(['example.com'], 'https://evilexample.com/x')).rejects.toThrow(
      /not in allowlist/,
    );
  });

  it('treats a trailing dot on the attested host as the same host', async () => {
    await expect(check(['api.example.com'], 'https://api.example.com./x')).resolves.toBe(
      'api.example.com',
    );
    await expect(check(['api.example.com.'], 'https://api.example.com/x')).resolves.toBe(
      'api.example.com',
    );
  });

  it('does not admit a host with a trailing dot that no entry names', async () => {
    await expect(check(['api.example.com'], 'https://evil.com./x')).rejects.toThrow(
      /not in allowlist/,
    );
  });

  it('refuses a non-default port the entry does not name', async () => {
    await expect(check(['api.example.com'], 'https://api.example.com:8443/x')).rejects.toThrow(
      /not in allowlist/,
    );
  });

  it('admits only the port an entry names', async () => {
    await expect(check(['api.example.com:8443'], 'https://api.example.com:8443/x')).resolves.toBe(
      'api.example.com:8443',
    );
    await expect(check(['api.example.com:8443'], 'https://api.example.com/x')).rejects.toThrow(
      /not in allowlist/,
    );
    await expect(check(['api.example.com:8443'], 'https://api.example.com:9443/x')).rejects.toThrow(
      /not in allowlist/,
    );
  });
});
