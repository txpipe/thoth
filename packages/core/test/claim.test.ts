// Unit tests for the canonical claim shape (`@thoth/core/claim`): the schema's
// length validation and `claimToMessage`'s wire encoding, including the
// per-half byte flag duplication and the adjacent 16-byte halves, and
// `toContractClaim`'s mask guard (its parity lives in the contracts tests).
import { type Claim, claimSchema, claimToMessage, toContractClaim } from '@thoth/core/claim';
import { describe, expect, it } from 'vitest';

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

  it('rejects a byteValues array of the wrong length when W is given', () => {
    expect(() => claimSchema(3, 1).parse({ ...byteBase, byteValues: [] })).toThrow();
    expect(() => claimSchema(3, 1).parse(numericBase)).toThrow();
  });

  it('rejects a byte value that is not 32 bytes', () => {
    expect(() =>
      claimSchema(3, 1).parse({ ...byteBase, byteValues: [new Uint8Array(31)] }),
    ).toThrow();
  });
});

describe('claimToMessage', () => {
  it('duplicates the byte flag per half and splits each value into adjacent halves', () => {
    const value = fullSpan();
    const message = claimToMessage(claimSchema(3, 1).parse(byteBase));
    // header(11) + present(3) + bytePresent(2) + values(3) + halves(2) = 21
    expect(message).toHaveLength(11 + 2 * 3 + 2 * 2);
    // numeric flags, then the byte slot's flag once per half
    expect(message.slice(11, 16)).toEqual([1n, 0n, 1n, 1n, 1n]);
    expect(message.slice(16, 19)).toEqual([7n, 0n, 9n]);
    // bytes 0–15 then bytes 16–31, each as its little-endian value; the two
    // differ, so a swapped or reversed half would fail this.
    const low = le(value.slice(0, 16));
    const high = le(value.slice(16));
    expect(low).not.toBe(high);
    expect(message.slice(19, 21)).toEqual([low, high]);
  });

  it('keeps the numeric-only layout when W = 0', () => {
    const claim: Claim<3, 0> = claimSchema(3).parse(numericBase);
    const message = claimToMessage(claim);
    expect(message).toHaveLength(2 * 3 + 11);
    expect(message.slice(11, 14)).toEqual([1n, 0n, 1n]);
    expect(message.slice(14, 17)).toEqual([7n, 0n, 9n]);
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
    // header(11) + present(2) + bytePresent(4) + values(2) + halves(4) = 23
    expect(message).toHaveLength(11 + 2 * 2 + 2 * 4);
    // numeric flags, then each byte slot's flag duplicated once per half
    expect(message.slice(11, 13)).toEqual([0n, 1n]);
    expect(message.slice(13, 17)).toEqual([1n, 1n, 0n, 0n]);
    expect(message.slice(17, 19)).toEqual([0n, 0n]);
    // halves in value order, each value bytes 0–15 / 16–31 as LE Uint<128>
    expect(message.slice(19, 23)).toEqual([
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
