// Unit tests for the canonical claim shape (`@txpipe/thoth-core/claim`): the schema's
// length and numeric-bound validation, `claimToMessage`'s wire encoding
// (per-half byte flag duplication, adjacent 16-byte halves), and
// `toContractClaim`'s mask guard (its parity lives in the contracts tests).
import { type Claim, claimSchema, claimToMessage, toContractClaim } from '@txpipe/thoth-core/claim';
import { filled, fullSpan, le } from '@txpipe/thoth-test-utils/bytes';
import { describe, expect, it } from 'vitest';

// `W = 0` shape: a `V + W = 3` mask.
const numericBase = {
  appId: filled(0x11),
  policyHash: filled(0x22),
  windowStart: 100n,
  windowEnd: 200n,
  subjectHash: filled(0x33),
  holder: filled(0x44),
  salt: filled(0x55),
  present: [true, false, true],
  values: [7n, 0n, 9n],
};

// `W = 1` shape: a `V + W = 4` mask (numeric slots, then the byte slot).
const byteBase = {
  ...numericBase,
  present: [true, false, true, true],
  byteValues: [fullSpan()],
};

describe('claimSchema', () => {
  it('parses a claim with present length V + W, values length V, byteValues length W', () => {
    const parsed = claimSchema(3, 1).parse(byteBase);
    expect(parsed.present).toEqual([true, false, true, true]);
    expect(parsed.values).toEqual([7n, 0n, 9n]);
    expect(parsed.byteValues).toHaveLength(1);
  });

  it('defaults omitted byteValues to [] and keeps Claim<V> meaning W = 0', () => {
    const parsed = claimSchema(3).parse(numericBase);
    expect(parsed.byteValues).toEqual([]);
  });

  it('owns copies of the byte arrays, even over shared memory', () => {
    const holder = new Uint8Array(new SharedArrayBuffer(32));
    holder.set(filled(0x44));
    const input = { ...byteBase, appId: filled(0x11), holder, byteValues: [fullSpan()] };
    const parsed = claimSchema(3, 1).parse(input);
    for (const bytes of [input.appId, holder, ...input.byteValues]) {
      bytes.fill(0xee);
    }
    expect(parsed.appId).toEqual(filled(0x11));
    expect(parsed.holder).toEqual(filled(0x44));
    expect(parsed.byteValues).toEqual([fullSpan()]);
  });

  it('checks the length of the copy, not of the caller object', () => {
    // A Proxy reports 32 bytes to the check but yields 64 when copied.
    const holder = new Proxy(filled(0x44), {
      get: (target, key) =>
        key === Symbol.iterator
          ? function* () {
              yield* new Uint8Array(64).fill(0xee);
            }
          : Reflect.get(target, key),
    });
    expect(() => claimSchema(3, 1).parse({ ...byteBase, holder })).toThrow(/expected 32 bytes/);
  });

  it('rejects a present mask of the wrong length', () => {
    expect(() => claimSchema(3, 1).parse({ ...byteBase, present: [true, false, true] })).toThrow();
  });

  it('skips the exact-length constraints when v is omitted', () => {
    const parsed = claimSchema().parse(byteBase);
    expect(parsed.present).toEqual([true, false, true, true]);
    expect(parsed.values).toEqual([7n, 0n, 9n]);
    expect(parsed.byteValues).toHaveLength(1);
    expect(claimSchema().parse(numericBase).byteValues).toEqual([]);
  });

  it('requires one flag per slot even without counts', () => {
    expect(() => claimSchema().parse({ ...byteBase, present: [true] })).toThrow(
      /one flag per value/,
    );
  });

  it('rejects a byteValues array of the wrong length when W is given', () => {
    expect(() => claimSchema(3, 1).parse({ ...byteBase, byteValues: [] })).toThrow();
    expect(() => claimSchema(3, 1).parse(numericBase)).toThrow();
  });

  it('requires a 32-byte salt', () => {
    expect(() => claimSchema(3).parse({ ...numericBase, salt: new Uint8Array(31) })).toThrow();
    const { salt: _, ...unsalted } = numericBase;
    expect(() => claimSchema(3).parse(unsalted)).toThrow();
  });

  it('rejects a byte value that is not 32 bytes', () => {
    expect(() =>
      claimSchema(3, 1).parse({ ...byteBase, byteValues: [new Uint8Array(31)] }),
    ).toThrow();
  });
});

describe('claimSchema numeric bounds', () => {
  // Each numeric field with the contract type it lands in: values are
  // `Uint<64>`, the window bounds `Uint<32>`, the version `Uint<8>`.
  const fields = [
    { path: 'values.0', bits: 64, set: (n: number | bigint) => ({ values: [n, 0n, 9n] }) },
    { path: 'windowStart', bits: 32, set: (n: number | bigint) => ({ windowStart: n }) },
    { path: 'windowEnd', bits: 32, set: (n: number | bigint) => ({ windowEnd: n }) },
    { path: 'version', bits: 8, set: (n: number | bigint) => ({ version: n }) },
  ];
  const parse = (patch: object) => claimSchema(3).safeParse({ ...numericBase, ...patch });

  for (const { path, bits, set } of fields) {
    const bound = 1n << BigInt(bits);
    const invalid: [string, number | bigint][] = [
      ['a negative number', -1],
      ['a negative bigint', -1n],
      ['a fractional number', 1.5],
      ['an unsafe integer', Number.MAX_SAFE_INTEGER + 1],
      ['NaN', Number.NaN],
      [`2^${bits}`, bound],
    ];
    for (const [label, input] of invalid) {
      it(`rejects ${label} in ${path} with a validation error`, () => {
        const result = parse(set(input));
        expect(result.success).toBe(false);
        expect(result.error?.issues.map((issue) => issue.path.join('.'))).toContain(path);
      });
    }

    it(`accepts 0 and 2^${bits} - 1 in ${path}`, () => {
      expect(parse(set(0)).success).toBe(true);
      expect(parse(set(bound - 1n)).success).toBe(true);
    });
  }

  it('accepts a safe-integer number and coerces it to bigint', () => {
    const parsed = claimSchema(3).parse({ ...numericBase, windowStart: 100, values: [7, 0, 9] });
    expect(parsed.windowStart).toBe(100n);
    expect(parsed.values).toEqual([7n, 0n, 9n]);
  });

  it('bounds values when v is omitted', () => {
    expect(claimSchema().safeParse({ ...numericBase, values: [-1n, 0n, 9n] }).success).toBe(false);
  });
});

describe('claimToMessage', () => {
  it('duplicates the byte flag per half and splits each value into adjacent halves', () => {
    const value = fullSpan();
    const message = claimToMessage(claimSchema(3, 1).parse(byteBase));
    // header(14) + present(3) + bytePresent(2) + values(3) + halves(2) = 24
    expect(message).toHaveLength(14 + 2 * 3 + 2 * 2);
    // the header's last field is the byte-half count B = 2W
    expect(message[13]).toBe(2n);
    // numeric flags, then the byte slot's flag once per half
    expect(message.slice(14, 19)).toEqual([1n, 0n, 1n, 1n, 1n]);
    expect(message.slice(19, 22)).toEqual([7n, 0n, 9n]);
    // bytes 0–15 then bytes 16–31, each as its little-endian value; the two
    // differ, so a swapped or reversed half would fail this.
    const low = le(value.slice(0, 16));
    const high = le(value.slice(16));
    expect(low).not.toBe(high);
    expect(message.slice(22, 24)).toEqual([low, high]);
  });

  it('signs the salt in the two header fields after the holder', () => {
    const salt = fullSpan();
    const message = claimToMessage(claimSchema(3).parse({ ...numericBase, salt }));
    expect(message.slice(11, 13)).toEqual([le(salt.slice(0, 16)), le(salt.slice(16))]);
  });

  it('keeps the numeric-only layout when W = 0', () => {
    const claim: Claim<3, 0> = claimSchema(3).parse(numericBase);
    const message = claimToMessage(claim);
    expect(message).toHaveLength(2 * 3 + 14);
    expect(message.slice(13, 17)).toEqual([0n, 1n, 0n, 1n]);
    expect(message.slice(17, 20)).toEqual([7n, 0n, 9n]);
  });

  it('interleaves flags and halves across two byte slots (W = 2)', () => {
    const first = Uint8Array.from({ length: 32 }, (_, i) => i);
    const second = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
    const claim = claimSchema(2, 2).parse({
      ...numericBase,
      present: [false, true, true, false],
      values: [0n, 0n],
      byteValues: [first, second],
    });
    const message = claimToMessage(claim);
    // header(14) + present(2) + bytePresent(4) + values(2) + halves(4) = 26
    expect(message).toHaveLength(14 + 2 * 2 + 2 * 4);
    expect(message[13]).toBe(4n);
    // numeric flags, then each byte slot's flag duplicated once per half
    expect(message.slice(14, 16)).toEqual([0n, 1n]);
    expect(message.slice(16, 20)).toEqual([1n, 1n, 0n, 0n]);
    expect(message.slice(20, 22)).toEqual([0n, 0n]);
    // halves in value order, each value bytes 0–15 / 16–31 as LE Uint<128>
    expect(message.slice(22, 26)).toEqual([
      le(first.slice(0, 16)),
      le(first.slice(16)),
      le(second.slice(0, 16)),
      le(second.slice(16)),
    ]);
  });
});

describe('toContractClaim', () => {
  it('rejects a mask without one flag per slot', () => {
    const claim = claimSchema().parse(byteBase);
    expect(() => toContractClaim({ ...claim, present: [true] })).toThrow(
      /present must have length 4/,
    );
  });
});
