// Unit and property tests for `@txpipe/thoth-core/claim`: schema validation, the wire
// encoding and its injectivity, and the schema-to-encoder round trip.
import { isDeepStrictEqual } from 'node:util';
import { type Claim, claimSchema, claimToMessage, toContractClaim } from '@txpipe/thoth-core/claim';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  anyBytes32,
  anyClaim,
  anySlots,
  anyUint,
  fitsUint,
  HEADER_BYTE_FIELDS,
  HEADER_UINT_BITS,
  type Slots,
} from './arbitraries.js';

const bytes32 = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);

// A value whose bytes differ across the 16-byte half boundary, so a swapped or
// reversed half cannot pass the assertions below.
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

describe('claimToMessage injectivity', () => {
  type Header = (typeof HEADER_BYTE_FIELDS)[number] | keyof typeof HEADER_UINT_BITS;
  const CHANGEABLE: readonly (Header | 'slots')[] = [
    ...HEADER_BYTE_FIELDS,
    ...(Object.keys(HEADER_UINT_BITS) as (keyof typeof HEADER_UINT_BITS)[]),
    'slots',
  ];
  const isUintField = (field: Header): field is keyof typeof HEADER_UINT_BITS =>
    field in HEADER_UINT_BITS;

  // A field value near the original, so that two claims differ by as little
  // as one byte or one unit, or a fresh value anywhere in the field's range.
  const nearBytes = (bytes: Uint8Array) =>
    fc.oneof(
      fc
        .tuple(fc.nat({ max: 31 }), fc.integer({ min: 1, max: 255 }))
        .map(([i, mask]) => bytes.map((byte, j) => (i === j ? byte ^ mask : byte))),
      anyBytes32(),
    );
  const nearUint = (value: bigint, bits: number) =>
    fc.oneof(
      fc.constantFrom(value + 1n, value - 1n).filter((v) => fitsUint(v, bits)),
      anyUint(bits),
    );
  // Flip one slot's flag, keeping an absent slot zero, or redraw every slot at
  // any shape, so a claim can change layout as well as content.
  const nearSlots = (claim: Claim<number, number>): fc.Arbitrary<Slots> => {
    if (claim.present.length === 0) {
      return anySlots();
    }
    const numeric = claim.values.length;
    const flip = fc.nat({ max: claim.present.length - 1 }).map((i) => {
      const present = claim.present.map((flag, j) => (i === j ? !flag : flag));
      return {
        present,
        values: claim.values.map((value, j) => (present[j] ? value : 0n)),
        byteValues: claim.byteValues.map((bytes, j) =>
          present[numeric + j] ? bytes : new Uint8Array(32),
        ),
      };
    });
    return fc.oneof(flip, anySlots());
  };

  // The new value of one field, as a patch over the claim.
  const patch = (
    claim: Claim<number, number>,
    field: Header | 'slots',
  ): fc.Arbitrary<Partial<Claim<number, number>>> => {
    if (field === 'slots') {
      return nearSlots(claim);
    }
    if (isUintField(field)) {
      return nearUint(claim[field], HEADER_UINT_BITS[field]).map((value) => ({ [field]: value }));
    }
    return nearBytes(claim[field]).map((value) => ({ [field]: value }));
  };

  type Pair = [Claim<number, number>, Claim<number, number>];

  // A claim and a copy with some fields changed: mostly one, so that a field
  // the encoder drops shows up, and sometimes several at once.
  const changed = anyClaim().chain((claim) =>
    fc
      .oneof(
        fc.constantFrom(...CHANGEABLE).map((field) => [field]),
        fc.subarray([...CHANGEABLE], { minLength: 1 }),
      )
      .chain((fields) => fc.tuple(...fields.map((field) => patch(claim, field))))
      .map((patches): Pair => [claim, Object.assign({ ...claim }, ...patches)]),
  );

  // A claim and a copy whose slots take another shape with the same message
  // length (V + 2W fields of flags and of values). Slots drawn from a small,
  // mostly-absent domain, so the two encodings often match field for field
  // except where the layout itself is signed.
  const tiny = {
    present: fc.oneof({ weight: 3, arbitrary: fc.constant(false) }, fc.constant(true)),
    value: fc.constantFrom(0n, 1n),
    byteValue: fc.constantFrom(
      new Uint8Array(32),
      Uint8Array.from({ length: 32 }, (_, i) => +(i === 0)),
    ),
  };
  const relaidOut = anyClaim(tiny).chain((claim) => {
    const length = claim.values.length + 2 * claim.byteValues.length;
    return fc
      .nat({ max: Math.floor(length / 2) })
      .chain((w) => anySlots({ ...tiny, v: length - 2 * w, w }))
      .map((other): Pair => [claim, { ...claim, ...other }]);
  });

  it('gives two different claims different messages, even when several fields differ', () => {
    fc.assert(
      fc.property(fc.oneof(changed, relaidOut), ([claim, other]) => {
        fc.pre(!isDeepStrictEqual(other, claim));
        expect(claimToMessage(other)).not.toEqual(claimToMessage(claim));
      }),
    );
  });

  // A dropped or truncated byte is one position in 32 per field, which a
  // random one-byte change rarely hits, so every position is changed here.
  it('changes the message when any one byte of any 32-byte field changes', () => {
    const flipped = (bytes: Uint8Array, i: number, mask: number) =>
      bytes.map((byte, j) => (i === j ? byte ^ mask : byte));
    fc.assert(
      fc.property(anyClaim({ w: 1 }), fc.integer({ min: 1, max: 255 }), (claim, mask) => {
        const message = claimToMessage(claim);
        for (let i = 0; i < 32; i++) {
          for (const field of HEADER_BYTE_FIELDS) {
            const other = { ...claim, [field]: flipped(claim[field], i, mask) };
            expect(claimToMessage(other)).not.toEqual(message);
          }
          const byteValues = claim.byteValues.map((bytes) => flipped(bytes, i, mask));
          // An absent byte slot must stay zero, so flip it only when measured.
          if (claim.present.at(-1)) {
            expect(claimToMessage({ ...claim, byteValues })).not.toEqual(message);
          }
        }
      }),
      { numRuns: 20 },
    );
  });
});

describe('claimSchema to claimToMessage round trip', () => {
  // About one raw field in ten is out of its bounds or the wrong length, so
  // the schema rejects some inputs and accepts most.
  const sometimes = <T, U>(valid: fc.Arbitrary<T>, invalid: fc.Arbitrary<U>) =>
    fc.oneof({ weight: 9, arbitrary: valid }, { weight: 1, arbitrary: invalid });
  const rawUint = (bits: number) => {
    const bound = 1n << BigInt(bits);
    return sometimes(
      fc.oneof(anyUint(bits), anyUint(Math.min(bits, 53)).map(Number)),
      fc.constantFrom(
        -1n,
        bound,
        -1,
        0.5,
        Number.MAX_SAFE_INTEGER + 1,
        Number.NaN,
        Number.POSITIVE_INFINITY,
      ),
    );
  };
  const rawBytes = sometimes(
    anyBytes32(),
    fc.uint8Array({ maxLength: 40 }).filter((bytes) => bytes.length !== 32),
  );
  const rawClaim = fc
    .record({
      version: fc.option(rawUint(HEADER_UINT_BITS.version), { nil: undefined }),
      appId: rawBytes,
      policyHash: rawBytes,
      windowStart: rawUint(HEADER_UINT_BITS.windowStart),
      windowEnd: rawUint(HEADER_UINT_BITS.windowEnd),
      subjectHash: rawBytes,
      holder: rawBytes,
      salt: rawBytes,
      values: fc.array(rawUint(64), { maxLength: 4 }),
      byteValues: fc.option(fc.array(rawBytes, { maxLength: 3 }), { nil: undefined }),
      flags: fc.array(fc.boolean(), { maxLength: 8 }),
      fitMask: sometimes(fc.constant(true), fc.constant(false)),
    })
    .map(({ flags, fitMask, ...raw }) => {
      const count = raw.values.length + (raw.byteValues?.length ?? 0);
      const present = fitMask ? Array.from({ length: count }, (_, i) => flags[i] ?? false) : flags;
      return { ...raw, present };
    });
  // The schema's sizes: none, the input's own, or one off.
  const sizes = sometimes(
    fc.constantFrom('any' as const, 'own' as const),
    fc.tuple(fc.integer({ min: -1, max: 1 }), fc.integer({ min: -1, max: 1 })),
  );

  const is32 = (bytes: Uint8Array) => bytes instanceof Uint8Array && bytes.length === 32;

  it('encodes every claim it accepts, with each field in its Compact type', () => {
    fc.assert(
      fc.property(rawClaim, sizes, (raw, size) => {
        const own = { v: raw.values.length, w: raw.byteValues?.length ?? 0 };
        const schema =
          size === 'any'
            ? claimSchema()
            : size === 'own'
              ? claimSchema(own.v, own.w)
              : claimSchema(Math.max(own.v + size[0], 0), Math.max(own.w + size[1], 0));
        const result = schema.safeParse(raw);
        if (!result.success) {
          return;
        }
        const claim = result.data;
        for (const [field, bits] of Object.entries(HEADER_UINT_BITS)) {
          expect(fitsUint(claim[field as keyof typeof HEADER_UINT_BITS], bits)).toBe(true);
        }
        expect(claim.values.every((value) => fitsUint(value, 64))).toBe(true);
        expect(HEADER_BYTE_FIELDS.every((field) => is32(claim[field]))).toBe(true);
        expect(claim.byteValues.every(is32)).toBe(true);
        expect(claim.present).toHaveLength(claim.values.length + claim.byteValues.length);
        expect(() => claimToMessage(claim)).not.toThrow();
        expect(() => toContractClaim(claim)).not.toThrow();
      }),
    );
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
