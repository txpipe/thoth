// Unit tests for the claim-context hashes (`@thoth/core/claim-context`): the
// policy hash, the subject hash, and the claim-context digest.
//
// Each expected digest is rebuilt from a hand-written canonical serialization
// (or, for the subject hash, a digest the compiled circuit produced), so the
// vectors pin the encoding itself rather than this implementation's output.
// The subject hash's circuit parity is re-checked in the contracts suite
// (`packages/contracts/test/subject-parity.test.ts`).

import { createHash } from 'node:crypto';
import { claimContextDigestOf, policyHashOf, subjectHashOf } from '@thoth/core/claim-context';
import { describe, expect, it } from 'vitest';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const sha256 = (text: string): string => createHash('sha256').update(text, 'utf-8').digest('hex');
const filled = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

describe('policyHashOf', () => {
  it('hashes the law tag, the wire version, and the canonical policy', () => {
    const policy = { slots: [{ slot: 0, name: 'price' }], allowedHosts: ['example.com'], max: 5n };

    expect(hex(policyHashOf('zk-fetch@1', policy))).toBe(
      sha256(
        '["zk-fetch@1","1",{"allowedHosts":["example.com"],"max":"5","slots":[{"name":"price","slot":0}]}]',
      ),
    );
  });

  it('does not depend on key order or on undefined keys', () => {
    const a = { b: 1, a: { d: true, c: null }, skipped: undefined };
    const b = { a: { c: null, d: true }, b: 1 };

    expect(hex(policyHashOf('law', a))).toBe(hex(policyHashOf('law', b)));
  });

  it('separates laws and wire versions', () => {
    const policy = { allowedHosts: ['example.com'] };
    const base = hex(policyHashOf('zk-fetch@1', policy));

    expect(hex(policyHashOf('event@1', policy))).not.toBe(base);
    expect(hex(policyHashOf('zk-fetch@1', policy, 2n))).not.toBe(base);
  });

  it('keeps array order', () => {
    expect(hex(policyHashOf('law', { hosts: ['a', 'b'] }))).not.toBe(
      hex(policyHashOf('law', { hosts: ['b', 'a'] })),
    );
  });

  it('rejects values with no canonical form', () => {
    expect(() => policyHashOf('law', { n: Number.NaN })).toThrow(/finite/);
    expect(() => policyHashOf('law', { d: new Date(0) } as never)).toThrow(/canonical/);
  });
});

describe('subjectHashOf', () => {
  it('matches the circuit hash of a struct of Bytes<32> fields', () => {
    // persistentHash<Subject>({ method, host, path, body }) of a compiled
    // Compact struct whose four Bytes<32> fields are filled with 1, 2, 3, 4.
    expect(hex(subjectHashOf([filled(1), filled(2), filled(3), filled(4)]))).toBe(
      'fefe0b60760d09ad6bc1add63edfb27b3fd077d1237a807c768a8e20416d1151',
    );
  });

  it('keeps field order', () => {
    expect(hex(subjectHashOf([filled(1), filled(2)]))).not.toBe(
      hex(subjectHashOf([filled(2), filled(1)])),
    );
  });

  it('rejects an empty subject and fields that are not 32 bytes', () => {
    expect(() => subjectHashOf([])).toThrow(/at least one field/);
    expect(() => subjectHashOf([filled(1), new Uint8Array(31)])).toThrow(/field 1/);
  });
});

describe('claimContextDigestOf', () => {
  const context = {
    policyHash: filled(0xaa),
    subjectHash: filled(0xbb),
    holder: filled(0xcc),
    nonce: filled(0xdd),
    windowStart: 1_700_000_000n,
    windowEnd: 1_700_000_300n,
  };

  it('hashes the tagged canonical context', () => {
    expect(hex(claimContextDigestOf(context))).toBe(
      sha256(
        `["thoth:claim-context",{"holder":"${'cc'.repeat(32)}","nonce":"${'dd'.repeat(32)}",` +
          `"policyHash":"${'aa'.repeat(32)}","subjectHash":"${'bb'.repeat(32)}",` +
          '"windowEnd":"1700000300","windowStart":"1700000000"}]',
      ),
    );
  });

  it('changes with every field', () => {
    const base = hex(claimContextDigestOf(context));
    const variants = [
      { ...context, policyHash: filled(1) },
      { ...context, subjectHash: filled(1) },
      { ...context, holder: filled(1) },
      { ...context, nonce: filled(1) },
      { ...context, windowStart: context.windowStart + 1n },
      { ...context, windowEnd: context.windowEnd + 1n },
    ];

    for (const variant of variants) {
      expect(hex(claimContextDigestOf(variant))).not.toBe(base);
    }
  });

  it('rejects a byte field that is not 32 bytes and a negative window bound', () => {
    expect(() => claimContextDigestOf({ ...context, nonce: new Uint8Array(16) })).toThrow(/nonce/);
    expect(() => claimContextDigestOf({ ...context, windowStart: -1n })).toThrow(/windowStart/);
  });
});
