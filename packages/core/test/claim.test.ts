// Unit tests for the canonical claim shape (`@txpipe/thoth-core/claim`): the schema's
// length and numeric-bound validation, `claimToMessage`'s seven-field encoding,
// what `nullifierOf` hashes and rejects, and `toContractClaim`'s mask guard.
// Their parity with the circuits lives in the contracts tests.
import {
  type Claim,
  claimSchema,
  claimToMessage,
  nullifierOf,
  toContractClaim,
} from '@txpipe/thoth-core/claim';
import { describe, expect, it } from 'vitest';

const bytes32 = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

// A value with a different byte at every position, so a reordered value
// cannot pass the assertions below.
const fullSpan = (): Uint8Array => Uint8Array.from({ length: 32 }, (_, i) => i);

// Little-endian value of a byte vector, as Compact's `convertBytesToUint` reads
// it (first byte least significant), computed independently of the encoder.
const le = (bytes: Uint8Array): bigint =>
  bytes.reduce((acc, byte, i) => acc + BigInt(byte) * 256n ** BigInt(i), 0n);

// `W = 0` shape: a `V + W = 3` mask.
const numericBase = {
  appId: bytes32(0x11),
  policyHash: bytes32(0x22),
  windowStart: 100n,
  windowEnd: 200n,
  subjectHash: bytes32(0x33),
  holder: bytes32(0x44),
  salt: bytes32(0x55),
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
    holder.set(bytes32(0x44));
    const input = { ...byteBase, appId: bytes32(0x11), holder, byteValues: [fullSpan()] };
    const parsed = claimSchema(3, 1).parse(input);
    for (const bytes of [input.appId, holder, ...input.byteValues]) {
      bytes.fill(0xee);
    }
    expect(parsed.appId).toEqual(bytes32(0x11));
    expect(parsed.holder).toEqual(bytes32(0x44));
    expect(parsed.byteValues).toEqual([fullSpan()]);
  });

  it('checks the length of the copy, not of the caller object', () => {
    // A Proxy reports 32 bytes to the check but yields 64 when copied.
    const holder = new Proxy(bytes32(0x44), {
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
  it('signs the version, the layout, the nullifier and the holder as seven fields', () => {
    const holder = fullSpan();
    const claim = claimSchema(3, 1).parse({ ...byteBase, holder });
    const nullifier = nullifierOf(claim);
    expect(claimToMessage(claim)).toEqual([
      1n,
      3n, // V
      1n, // W, the byte-slot count
      BigInt(nullifier[31] ?? -1),
      le(nullifier.slice(0, 31)),
      31n, // holder byte 31
      le(holder.slice(0, 31)),
    ]);
  });

  it('signs the byte-slot count of a layout with two byte slots', () => {
    const claim = claimSchema(2, 2).parse({
      ...numericBase,
      present: [false, true, true, false],
      values: [0n, 0n],
      byteValues: [fullSpan(), new Uint8Array(32)],
    });
    expect(claimToMessage(claim).slice(0, 3)).toEqual([1n, 2n, 2n]);
  });

  it.each([256n, -1n])('rejects version %s, outside Uint<8>', (version) => {
    const claim = claimSchema(3).parse(numericBase);
    expect(() => claimToMessage({ ...claim, version })).toThrow(
      `version must be in [0, 2^8), got ${version}`,
    );
  });

  it('rejects a holder that is not 32 bytes', () => {
    const claim = claimSchema(3).parse(numericBase);
    expect(() => claimToMessage({ ...claim, holder: new Uint8Array(31) })).toThrow(
      'holder must be 32 bytes, got 31',
    );
  });
});

describe('nullifierOf', () => {
  it('matches the circuit nullifier of a fixed claim', () => {
    // From the compiled bytes mock's `nullifierOf` over this claim.
    expect(Buffer.from(nullifierOf(claimSchema(3, 1).parse(byteBase))).toString('hex')).toBe(
      '32075c25495f4acc3b5df19ba958d9c171fbaff68cb70e069d1a60d87eda2960',
    );
  });

  it('does not hash the holder or the version', () => {
    const claim = claimSchema(3, 1).parse(byteBase);
    expect(nullifierOf({ ...claim, holder: bytes32(0x99), version: 2n })).toEqual(
      nullifierOf(claim),
    );
  });

  it('changes with every field of the observation identity', () => {
    const claim = claimSchema(3, 1).parse(byteBase);
    const changed: Claim<3, 1>[] = [
      { ...claim, appId: bytes32(0x12) },
      { ...claim, policyHash: bytes32(0x23) },
      { ...claim, subjectHash: bytes32(0x34) },
      { ...claim, salt: bytes32(0x56) },
      { ...claim, windowStart: 101n },
      { ...claim, windowEnd: 201n },
      { ...claim, values: [7n, 1n, 9n] },
      { ...claim, byteValues: [bytes32(0x01)] },
      { ...claim, present: [true, true, true, true] },
      { ...claim, present: [true, false, true, false] },
    ];
    const nullifiers = new Set(changed.map((c) => Buffer.from(nullifierOf(c)).toString('hex')));
    nullifiers.add(Buffer.from(nullifierOf(claim)).toString('hex'));
    expect(nullifiers.size).toBe(changed.length + 1);
  });

  it.each([
    { name: 'a window bound of 2^32', change: { windowEnd: 1n << 32n }, error: /windowEnd/ },
    { name: 'a value of 2^64', change: { values: [1n << 64n, 0n, 9n] }, error: /values\[0\]/ },
    { name: 'a negative value', change: { values: [-1n, 0n, 9n] }, error: /values\[0\]/ },
    { name: 'a short salt', change: { salt: new Uint8Array(31) }, error: /salt must be 32 bytes/ },
    {
      name: 'a short byte value',
      change: { byteValues: [new Uint8Array(31)] },
      error: /byteValues\[0\] must be 32 bytes/,
    },
    { name: 'a mask without one flag per slot', change: { present: [true] }, error: /present/ },
  ])('rejects $name', ({ change, error }) => {
    const claim = claimSchema(3, 1).parse(byteBase);
    expect(() => nullifierOf({ ...claim, ...change })).toThrow(error);
  });
});

describe('toContractClaim', () => {
  it('carries each byte value whole, with one flag per byte slot', () => {
    const claim = claimSchema(2, 2).parse({
      ...numericBase,
      present: [true, false, false, true],
      values: [7n, 0n],
      byteValues: [new Uint8Array(32), fullSpan()],
    });
    const contract = toContractClaim(claim);
    expect(contract.present).toEqual([true, false]);
    expect(contract.bytePresent).toEqual([false, true]);
    expect(contract.byteValues).toEqual([new Uint8Array(32), fullSpan()]);
  });

  it('rejects a mask without one flag per slot', () => {
    const claim = claimSchema().parse(byteBase);
    expect(() => toContractClaim({ ...claim, present: [true] })).toThrow(
      /present must have length 4/,
    );
  });
});
