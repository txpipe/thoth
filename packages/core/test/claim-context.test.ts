// Unit tests for the claim context hashes (`@txpipe/thoth-core/claim-context`): the
// policy hash, the subject hash, the holder commitment, and the claim context
// digest.
//
// Each expected digest is rebuilt from a hand-written canonical serialization
// (or, for the subject hash, a digest the compiled circuit produced), so the
// vectors pin the encoding itself rather than this implementation's output.
// The subject hash's and the holder commitment's circuit parity is re-checked
// in the contracts suite (`packages/contracts/test/subject-parity.test.ts`,
// `packages/contracts/test/holder-parity.test.ts`).

import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import {
  type CanonicalValue,
  claimContextDigestOf,
  holderCommitmentOf,
  policyHashOf,
  subjectHashOf,
} from '@txpipe/thoth-core/claim-context';
import fc from 'fast-check';
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

  it('separates laws and wire versions', () => {
    const policy = { allowedHosts: ['example.com'] };
    const base = hex(policyHashOf('zk-fetch@1', policy));

    expect(hex(policyHashOf('event@1', policy))).not.toBe(base);
    expect(hex(policyHashOf('zk-fetch@1', policy, 2n))).not.toBe(base);
  });

  it('rejects values with no canonical form', () => {
    expect(() => policyHashOf('law', { n: Number.NaN })).toThrow(/finite/);
    expect(() => policyHashOf('law', { d: new Date(0) } as never)).toThrow(/canonical/);
    expect(() => policyHashOf('law', Array(1))).toThrow(/sparse/);
    expect(() => policyHashOf('law', { slots: Array(2) })).toThrow(/sparse/);
  });
});

describe('policyHashOf canonical serialization', () => {
  type Plain = { readonly [key: string]: CanonicalValue | undefined };

  // Nested JSON data with bigint and byte leaves. Keys mix letters, an
  // integer-like key (which JavaScript always enumerates first) and characters
  // JSON escapes.
  const key = fc.string({ unit: fc.constantFrom('a', 'b', '1', '"', '\\', 'é'), maxLength: 2 });
  const { value: anyValue } = fc.letrec<{ value: CanonicalValue }>((tie) => ({
    value: fc.oneof(
      { depthSize: 'small' },
      fc.constant(null),
      fc.boolean(),
      fc.string({ unit: 'binary', maxLength: 6 }),
      fc.double({ noNaN: true, noDefaultInfinity: true }),
      fc.bigInt(),
      fc.uint8Array({ maxLength: 4 }),
      fc.array(tie('value'), { maxLength: 3 }),
      fc.dictionary(key, tie('value'), { maxKeys: 3 }),
    ),
  }));

  // Random choices a test transform consumes in turn, so fast-check replays
  // and shrinks the transform along with the value.
  const choices = fc.array(fc.nat(), { minLength: 1, maxLength: 32 });
  const picker = (drawn: readonly number[]) => {
    let k = 0;
    return (count: number): number => (drawn[k++ % drawn.length] ?? 0) % count;
  };
  const isRecord = (node: CanonicalValue | undefined): node is Plain =>
    node !== null &&
    typeof node === 'object' &&
    !Array.isArray(node) &&
    !(node instanceof Uint8Array);

  // A Fisher-Yates shuffle of a copy of `items`.
  const shuffle = <T>(items: readonly T[], pick: (count: number) => number): T[] => {
    const copy = [...items];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = pick(i + 1);
      [copy[i], copy[j]] = [copy[j] as T, copy[i] as T];
    }
    return copy;
  };

  // A copy with every object's keys in another order and some keys added with
  // the value `undefined`.
  const reorder = (value: CanonicalValue, drawn: readonly number[]): CanonicalValue => {
    const pick = picker(drawn);
    const walk = (node: CanonicalValue): CanonicalValue => {
      if (Array.isArray(node)) {
        return node.map((item: CanonicalValue) => walk(item));
      }
      if (!isRecord(node)) {
        return node;
      }
      const entries: [string, CanonicalValue | undefined][] = Object.keys(node).map((k) => {
        const member = node[k];
        return [k, member === undefined ? undefined : walk(member)];
      });
      for (const extra of ['a', 'zz', '~']) {
        if (!(extra in node) && pick(2) === 1) {
          entries.push([extra, undefined]);
        }
      }
      return Object.fromEntries(shuffle(entries, pick));
    };
    return walk(value);
  };

  it('ignores object key order and keys whose value is undefined', () => {
    fc.assert(
      fc.property(fc.string(), anyValue, choices, (law, value, drawn) => {
        expect(policyHashOf(law, reorder(value, drawn))).toEqual(policyHashOf(law, value));
      }),
    );
  });

  // Two values that mean the same canonical data. A bigint and its decimal
  // string, bytes and their lowercase hex string, and -0 and 0 share one
  // serialization by design; key order and undefined keys do not count.
  const model = (value: CanonicalValue | undefined): unknown => {
    if (typeof value === 'bigint') {
      return value.toString(10);
    }
    if (value instanceof Uint8Array) {
      return Buffer.from(value).toString('hex');
    }
    if (typeof value === 'number') {
      return value === 0 ? 0 : value;
    }
    if (Array.isArray(value)) {
      return { array: value.map((item: CanonicalValue) => model(item)) };
    }
    if (isRecord(value)) {
      const keys = Object.keys(value)
        .filter((k) => value[k] !== undefined)
        .sort();
      return { object: keys.map((k) => [k, model(value[k])]) };
    }
    return value;
  };

  // A small domain, so pairs often share structure and differ in one leaf,
  // and include values of different types that serialize alike.
  const SMALL_LEAVES: readonly CanonicalValue[] = [
    null,
    true,
    false,
    0,
    -0,
    1,
    0n,
    1n,
    '',
    '0',
    '1',
    'ab',
    new Uint8Array(0),
    Uint8Array.of(0xab),
  ];
  const { value: smallValue } = fc.letrec<{ value: CanonicalValue }>((tie) => ({
    value: fc.oneof(
      { depthSize: 'small', maxDepth: 3 },
      fc.constantFrom(...SMALL_LEAVES),
      fc.array(tie('value'), { maxLength: 2 }),
      fc.dictionary(
        fc.constantFrom('a', 'b'),
        fc.option(tie('value'), { nil: undefined, freq: 4 }),
        { maxKeys: 2 },
      ),
    ),
  }));

  // A copy with one node edited: an array reversed, shortened or extended, an
  // object key dropped or added, or a leaf replaced.
  const edit = (value: CanonicalValue, drawn: readonly number[]): CanonicalValue => {
    const pick = picker(drawn);
    const size = (node: CanonicalValue | undefined): number =>
      node === undefined
        ? 0
        : 1 +
          (Array.isArray(node)
            ? node.reduce((sum: number, item: CanonicalValue) => sum + size(item), 0)
            : isRecord(node)
              ? Object.values(node).reduce((sum: number, member) => sum + size(member), 0)
              : 0);
    const change = (node: CanonicalValue): CanonicalValue => {
      if (Array.isArray(node)) {
        const items: CanonicalValue[] = [...node];
        const kind = pick(3);
        if (kind === 0) {
          return items.reverse();
        }
        if (kind === 1 && items.length > 0) {
          items.splice(pick(items.length), 1);
          return items;
        }
        return [...items, null];
      }
      if (isRecord(node)) {
        const keys = Object.keys(node).filter((k) => node[k] !== undefined);
        if (pick(2) === 0 && keys.length > 0) {
          const dropped = keys[pick(keys.length)] as string;
          return Object.fromEntries(Object.entries(node).filter(([k]) => k !== dropped));
        }
        return { ...node, c: null };
      }
      return SMALL_LEAVES[pick(SMALL_LEAVES.length)] ?? null;
    };
    let target = pick(size(value));
    const walk = (node: CanonicalValue): CanonicalValue => {
      if (target-- === 0) {
        return change(node);
      }
      if (Array.isArray(node)) {
        return node.map((item: CanonicalValue) => walk(item));
      }
      if (isRecord(node)) {
        return Object.fromEntries(
          Object.entries(node).map(([k, member]) => [
            k,
            member === undefined ? member : walk(member),
          ]),
        );
      }
      return node;
    };
    return walk(value);
  };

  it('gives two values the same hash exactly when they mean the same data', () => {
    const pairs = fc.oneof(
      fc.tuple(smallValue, smallValue),
      fc
        .tuple(fc.oneof(smallValue, anyValue), choices)
        .map(([value, drawn]) => [value, edit(value, drawn)] as const),
      // Leaves in reverse order, so an array that loses its order shows up.
      fc
        .array(
          fc.oneof(
            fc.constantFrom(...SMALL_LEAVES),
            fc.string({ unit: fc.constantFrom('a', 'b') }),
          ),
          { minLength: 2, maxLength: 4 },
        )
        .map((items) => [items, [...items].reverse()] as const),
    );
    fc.assert(
      fc.property(pairs, ([a, b]) => {
        const sameHash = isDeepStrictEqual(policyHashOf('law', a), policyHashOf('law', b));
        expect(sameHash).toBe(isDeepStrictEqual(model(a), model(b)));
      }),
    );
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

describe('holderCommitmentOf', () => {
  it('matches the holderCommitment circuit', () => {
    // holderCommitment(secret) of the compiled attestation module, for a
    // secret filled with 1.
    expect(hex(holderCommitmentOf(filled(1)))).toBe(
      '9276ed0a85553eebda01f7dc401428f107b97ec6ccd4806f89f222d4b636e914',
    );
  });

  it('rejects a secret that is not 32 bytes', () => {
    expect(() => holderCommitmentOf(new Uint8Array(31))).toThrow(/holder secret/);
  });
});

describe('claimContextDigestOf', () => {
  const context = {
    policyHash: filled(0xaa),
    subjectHash: filled(0xbb),
    holder: filled(0xcc),
    windowStart: 1_700_000_000n,
    windowEnd: 1_700_000_300n,
  };

  it('hashes the tagged canonical context', () => {
    expect(hex(claimContextDigestOf(context))).toBe(
      sha256(
        `["thoth:claim-context",{"holder":"${'cc'.repeat(32)}",` +
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
      { ...context, windowStart: context.windowStart + 1n },
      { ...context, windowEnd: context.windowEnd + 1n },
    ];

    for (const variant of variants) {
      expect(hex(claimContextDigestOf(variant))).not.toBe(base);
    }
  });

  it('rejects a byte field that is not 32 bytes and a negative window bound', () => {
    expect(() => claimContextDigestOf({ ...context, holder: new Uint8Array(16) })).toThrow(
      /holder/,
    );
    expect(() => claimContextDigestOf({ ...context, windowStart: -1n })).toThrow(/windowStart/);
  });
});
