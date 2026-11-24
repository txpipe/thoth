// Unit tests for the canonical claim shape (`@thoth/core/claim`): the schema's
// length and numeric-bound validation, the wire encoding (`nullifierOf`'s
// preimage, `claimToMessage`'s fields, layout binding, every byte bound), and
// `toContractClaim`'s split. Parity with the compiled circuits lives in the
// contracts tests.
import { createHash } from 'node:crypto';
import {
  type Claim,
  claimSchema,
  claimToMessage,
  nullifierOf,
  toContractClaim,
} from '@thoth/core/claim';
import { describe, expect, it } from 'vitest';

const bytes32 = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

// A value whose 32 bytes all differ, so a swapped or reversed byte order
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

// The observation preimage written out from the wire layout in the
// `attestation.compact` header, independently of the encoder: the 32-byte
// fields, the windows as 4-byte and the values as 8-byte little-endian
// integers, the byte values, then one flag byte per slot.
const preimageOf = (claim: Claim<number, number>): Buffer => {
  const integers = Buffer.alloc(8 + 8 * claim.values.length);
  integers.writeUInt32LE(Number(claim.windowStart), 0);
  integers.writeUInt32LE(Number(claim.windowEnd), 4);
  claim.values.forEach((value, i) => {
    integers.writeBigUInt64LE(value, 8 + 8 * i);
  });
  return Buffer.concat([
    claim.appId,
    claim.policyHash,
    claim.subjectHash,
    claim.salt,
    integers,
    ...claim.byteValues,
    Buffer.from(claim.present.map(Number)),
  ]);
};

const sha256 = (bytes: Uint8Array): Uint8Array =>
  new Uint8Array(createHash('sha256').update(bytes).digest());

// A 32-byte value's two message fields: byte 31, then bytes 0–30 little-endian.
const limbsOf = (bytes: Uint8Array): bigint[] => [BigInt(bytes[31] ?? 0), le(bytes.slice(0, 31))];

describe('nullifierOf', () => {
  it('hashes the documented observation preimage', () => {
    const numeric = claimSchema(3).parse(numericBase);
    expect(preimageOf(numeric)).toHaveLength(136 + 9 * 3);
    expect(nullifierOf(numeric)).toEqual(sha256(preimageOf(numeric)));
    const bytes = claimSchema(3, 1).parse(byteBase);
    expect(preimageOf(bytes)).toHaveLength(136 + 9 * 3 + 33);
    expect(nullifierOf(bytes)).toEqual(sha256(preimageOf(bytes)));
  });

  it('pins the numeric-only nullifier against serialization drift', () => {
    expect(Buffer.from(nullifierOf(claimSchema(3).parse(numericBase))).toString('hex')).toBe(
      '772d284dab51211b2f772099e7ea9fd2c353db35acc09cc380a7f44b35d9c8a4',
    );
  });

  it('hashes neither the holder nor the version', () => {
    const claim = claimSchema(3, 1).parse(byteBase);
    expect(nullifierOf({ ...claim, holder: bytes32(0x99), version: 2n })).toEqual(
      nullifierOf(claim),
    );
  });

  it('hashes the byte values after the numeric values, and the byte flags last', () => {
    const first = fullSpan();
    const second = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);
    const claim = claimSchema(2, 2).parse({
      ...numericBase,
      present: [false, true, true, false],
      values: [0n, 5n],
      byteValues: [first, second],
    });
    const preimage = preimageOf(claim);
    expect(preimage.subarray(-68, -4)).toEqual(Buffer.concat([first, second]));
    expect(preimage.subarray(-4)).toEqual(Buffer.from([0, 1, 1, 0]));
    expect(nullifierOf(claim)).toEqual(sha256(preimage));
  });

  it('rejects an integer outside its contract type instead of wrapping it', () => {
    const claim = claimSchema(3).parse(numericBase);
    expect(() => nullifierOf({ ...claim, values: [1n << 64n, 0n, 9n] })).toThrow(/values\[0\]/);
    expect(() => nullifierOf({ ...claim, windowEnd: 1n << 32n })).toThrow(/windowEnd/);
    expect(() => nullifierOf({ ...claim, windowStart: -1n })).toThrow(/windowStart/);
  });

  // V = 11, W = 0 and V = 0, W = 3 have identities of one length (136 + 99
  // bytes): the 11 values and 8 of their flags read as 3 byte values, the
  // other 3 flags as the byte flags. The nullifier alone cannot tell them
  // apart, so the message signs the layout.
  it('shares one nullifier between two layouts of one identity length', () => {
    const values = Array.from({ length: 11 }, (_, i) => 0x0101_0101_0101_0101n * BigInt(i + 1));
    const wide = claimSchema(11).parse({ ...numericBase, present: values.map(() => true), values });
    const tail = Buffer.concat([
      ...values.map((value) => {
        const bytes = Buffer.alloc(8);
        bytes.writeBigUInt64LE(value);
        return bytes;
      }),
      Buffer.alloc(8, 1),
    ]);
    const byteValues = [0, 1, 2].map((i) => Uint8Array.from(tail.subarray(32 * i, 32 * i + 32)));
    const bytes = claimSchema(0, 3).parse({
      ...numericBase,
      present: [true, true, true],
      values: [],
      byteValues,
    });
    expect(nullifierOf(bytes)).toEqual(nullifierOf(wide));
    const [wideMessage, bytesMessage] = [claimToMessage(wide), claimToMessage(bytes)];
    expect(wideMessage.slice(1, 3)).toEqual([11n, 0n]);
    expect(bytesMessage.slice(1, 3)).toEqual([0n, 3n]);
    const withoutLayout = (message: readonly bigint[]) => [message[0], ...message.slice(3)];
    expect(withoutLayout(wideMessage)).toEqual(withoutLayout(bytesMessage));
  });
});

describe('claimToMessage', () => {
  it('signs the version, the layout, the nullifier and the holder, in that order', () => {
    const claim = claimSchema(3, 1).parse({ ...byteBase, holder: fullSpan() });
    const message = claimToMessage(claim);
    expect(message).toEqual([
      1n,
      3n,
      1n,
      ...limbsOf(sha256(preimageOf(claim))),
      ...limbsOf(fullSpan()),
    ]);
    // Byte 31 first, then bytes 0–30, so a reversed or rotated holder fails.
    expect(message.slice(5)).toEqual([31n, le(fullSpan().slice(0, 31))]);
  });

  it('signs W = 0 for a numeric-only claim', () => {
    const claim: Claim<3, 0> = claimSchema(3).parse(numericBase);
    const message = claimToMessage(claim);
    expect(message).toHaveLength(7);
    expect(message.slice(0, 3)).toEqual([1n, 3n, 0n]);
  });

  it('changes with every byte of every 32-byte field and every other field', () => {
    const claim = claimSchema(3, 1).parse(byteBase);
    const message = claimToMessage(claim);
    for (const field of ['appId', 'policyHash', 'subjectHash', 'holder', 'salt'] as const) {
      for (let i = 0; i < 32; i++) {
        const bytes = claim[field].slice();
        bytes[i] = (bytes[i] ?? 0) ^ 0x01;
        expect(claimToMessage({ ...claim, [field]: bytes })).not.toEqual(message);
      }
    }
    for (let i = 0; i < 32; i++) {
      const bytes = fullSpan();
      bytes[i] = (bytes[i] ?? 0) ^ 0x01;
      expect(claimToMessage({ ...claim, byteValues: [bytes] })).not.toEqual(message);
    }
    for (const changed of [
      { version: 2n },
      { windowStart: 101n },
      { windowEnd: 201n },
      { values: [7n, 1n, 9n] },
      { present: [true, true, true, true] },
      { present: [true, false, true, false] },
    ]) {
      expect(claimToMessage({ ...claim, ...changed })).not.toEqual(message);
    }
  });
});

describe('toContractClaim', () => {
  it('splits the mask into numeric and byte flags and keeps each byte value whole', () => {
    const value = fullSpan();
    const contract = toContractClaim(claimSchema(3, 1).parse(byteBase));
    expect(contract.present).toEqual([true, false, true]);
    expect(contract.bytePresent).toEqual([true]);
    expect(contract.byteValues).toEqual([value]);
  });

  it('rejects a mask without one flag per slot', () => {
    const claim = claimSchema().parse(byteBase);
    expect(() => toContractClaim({ ...claim, present: [true] })).toThrow(
      /present must have length 4/,
    );
  });
});
