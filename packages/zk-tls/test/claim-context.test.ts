// Unit tests for the zkFetch claim context (`@thoth/zk-tls`): the kind's
// policy hash and its request subject.

import { createHash } from 'node:crypto';
import { policyHashOf, subjectHashOf } from '@thoth/core/claim-context';
import {
  type ZkFetchPolicy,
  zkFetchPolicyHashOf,
  zkFetchSubjectHashOf,
  zkFetchSubjectOf,
} from '@thoth/zk-tls';
import { describe, expect, it } from 'vitest';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const sha256 = (text: string): string => createHash('sha256').update(text, 'utf-8').digest('hex');

const DISCLOSURE_RULES: Pick<ZkFetchPolicy, 'responseMatches' | 'responseRedactions'> = {
  responseMatches: [{ type: 'regex', value: '(?<data>.*)' }],
  responseRedactions: [],
};

const policy: ZkFetchPolicy = {
  allowedHosts: ['api.example.com'],
  slots: [{ slot: 0, name: 'price', parse: 'int' }],
  ...DISCLOSURE_RULES,
};

describe('zkFetchPolicyHashOf', () => {
  it('is the policy hash of the normalized policy under the zk-fetch@1 law', () => {
    const normalized = {
      allowedHosts: ['api.example.com'],
      slots: [{ slot: 0, name: 'price', parse: 'int', optional: false }],
      responseMatches: [{ type: 'regex', value: '(?<data>.*)' }],
      responseRedactions: [],
      claimVersion: 1n,
    };

    expect(hex(zkFetchPolicyHashOf(policy))).toBe(hex(policyHashOf('zk-fetch@1', normalized, 1n)));
  });

  it('signs under the policy claim version', () => {
    const v2 = zkFetchPolicyHashOf({ ...policy, claimVersion: 2n });

    expect(hex(v2)).not.toBe(hex(zkFetchPolicyHashOf(policy)));
  });

  it('hashes policies that differ only in defaults, host order or slot order the same', () => {
    const twoSlots: ZkFetchPolicy = {
      allowedHosts: ['b.example', 'a.example'],
      slots: [
        { slot: 1, name: 'volume', parse: 'float' },
        { slot: 0, name: 'price', parse: 'int' },
      ],
      ...DISCLOSURE_RULES,
    };
    const spelledOut: ZkFetchPolicy = {
      allowedHosts: ['A.example', 'b.example', 'a.example'],
      slots: [
        { slot: 0, name: 'price', parse: 'int', optional: false },
        { slot: 1, name: 'volume', parse: 'float', optional: false },
      ],
      claimVersion: 1n,
      ...DISCLOSURE_RULES,
    };

    expect(hex(zkFetchPolicyHashOf(spelledOut))).toBe(hex(zkFetchPolicyHashOf(twoSlots)));
  });

  it('ignores keys the policy schema does not know', () => {
    const extended = { ...policy, attestorAddresses: ['0xabc'] } as ZkFetchPolicy;

    expect(hex(zkFetchPolicyHashOf(extended))).toBe(hex(zkFetchPolicyHashOf(policy)));
  });

  it('distinguishes policies', () => {
    expect(hex(zkFetchPolicyHashOf({ ...policy, allowedHosts: ['evil.example'] }))).not.toBe(
      hex(zkFetchPolicyHashOf(policy)),
    );
  });

  it('binds the disclosure rules', () => {
    const substituted = zkFetchPolicyHashOf({
      ...policy,
      responseMatches: [{ type: 'regex', value: '"moving_time":\\s*(?<price>[\\d.]+)' }],
    });
    expect(hex(substituted)).not.toBe(hex(zkFetchPolicyHashOf(policy)));
  });

  it('rejects a malformed policy', () => {
    expect(() => zkFetchPolicyHashOf({ ...policy, allowedHosts: [] })).toThrow();
  });

  it('pins the canonical form of a normalized policy', () => {
    // Hand-written canonical JSON, not this implementation's output: the
    // policy hash is the on-chain binding, so its bytes must not drift.
    expect(hex(zkFetchPolicyHashOf(policy))).toBe(
      sha256(
        '["zk-fetch@1","1",{"allowedHosts":["api.example.com"],"claimVersion":"1",' +
          '"responseMatches":[{"type":"regex","value":"(?<data>.*)"}],"responseRedactions":[],' +
          '"slots":[{"name":"price","optional":false,"parse":"int","slot":0}]}]',
      ),
    );
  });
});

describe('zkFetchSubjectOf', () => {
  it('digests the method, host, path and body of the request', () => {
    const subject = zkFetchSubjectOf({
      method: 'post',
      url: 'https://API.Example.com:8443/v1/account?id=7#ignored',
      body: '{"a":1}',
    });

    expect(hex(subject.method)).toBe(sha256('POST'));
    expect(hex(subject.host)).toBe(sha256('api.example.com:8443'));
    expect(hex(subject.path)).toBe(sha256('/v1/account?id=7'));
    expect(hex(subject.body)).toBe(sha256('{"a":1}'));
  });

  it('treats a missing body as empty', () => {
    const subject = zkFetchSubjectOf({ method: 'GET', url: 'https://api.example.com/' });

    expect(hex(subject.body)).toBe(sha256(''));
  });

  it('keeps the host apart from the path', () => {
    const a = zkFetchSubjectOf({ method: 'GET', url: 'https://api.example.com/accounts/1' });
    const b = zkFetchSubjectOf({ method: 'GET', url: 'https://api.example.com/accounts/2' });

    expect(hex(a.host)).toBe(hex(b.host));
    expect(hex(a.path)).not.toBe(hex(b.path));
  });

  it('rejects a url it cannot parse', () => {
    expect(() => zkFetchSubjectOf({ method: 'GET', url: 'not a url' })).toThrow();
  });
});

describe('zkFetchSubjectHashOf', () => {
  it('hashes the subject fields in struct order', () => {
    const request = { method: 'GET', url: 'https://api.example.com/v1/price', body: '' };
    const { method, host, path, body } = zkFetchSubjectOf(request);

    expect(hex(zkFetchSubjectHashOf(request))).toBe(hex(subjectHashOf([method, host, path, body])));
  });
});
