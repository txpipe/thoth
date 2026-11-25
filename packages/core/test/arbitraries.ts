// fast-check generators for valid claims, shared by the core property tests and
// the contracts circuit-parity tests.
import type { Claim } from '@txpipe/thoth-core/claim';
import fc from 'fast-check';

/** The header's integer fields and the bit width of each one's Compact `Uint` type. */
export const HEADER_UINT_BITS = { version: 8, windowStart: 32, windowEnd: 32 } as const;

/** The header's 32-byte fields. */
export const HEADER_BYTE_FIELDS = ['appId', 'policyHash', 'subjectHash', 'holder', 'salt'] as const;

/** Whether `value` fits the Compact type `Uint<bits>`. */
export const fitsUint = (value: bigint, bits: number): boolean =>
  value >= 0n && value < 1n << BigInt(bits);

/** A uniformly random 32-byte array. */
export const anyBytes32 = (): fc.Arbitrary<Uint8Array> =>
  fc.uint8Array({ minLength: 32, maxLength: 32 });

/** An unsigned integer of the Compact type `Uint<bits>`. */
export const anyUint = (bits: number): fc.Arbitrary<bigint> =>
  fc.bigInt({ min: 0n, max: (1n << BigInt(bits)) - 1n });

type Slot<T> = { present: boolean; value: T };

// A slot is either absent, carrying zero, or measured with any value. A
// measured value may still be zero, so `present` is the only absence marker.
const slot = <T>(
  present: fc.Arbitrary<boolean>,
  value: fc.Arbitrary<T>,
  zero: () => T,
): fc.Arbitrary<Slot<T>> =>
  fc
    .tuple(present, value)
    .map(([measured, v]) =>
      measured ? { present: true, value: v } : { present: false, value: zero() },
    );

/** The numeric slots then the byte slots, as a claim's `present`, `values` and `byteValues`. */
export type Slots = Pick<Claim<number, number>, 'present' | 'values' | 'byteValues'>;

const sized = (count: number | undefined, max: number) =>
  count === undefined ? { maxLength: max } : { minLength: count, maxLength: count };

/** The number of numeric (`v`) and byte (`w`) slots, and the values a slot takes. */
export interface Shape {
  /** Omitted: 0 to 4. */
  v?: number;
  /** Omitted: 0 to 3. */
  w?: number;
  /** Whether a slot is measured. Omitted: either, evenly. */
  present?: fc.Arbitrary<boolean>;
  /** Omitted: any `Uint<64>`. */
  value?: fc.Arbitrary<bigint>;
  /** Omitted: any 32 bytes. */
  byteValue?: fc.Arbitrary<Uint8Array>;
}

/** The slot section of a claim of the given shape. */
export const anySlots = ({
  v,
  w,
  present = fc.boolean(),
  value = anyUint(64),
  byteValue = anyBytes32(),
}: Shape = {}): fc.Arbitrary<Slots> =>
  fc
    .tuple(
      fc.array(
        slot(present, value, () => 0n),
        sized(v, 4),
      ),
      fc.array(
        slot(present, byteValue, () => new Uint8Array(32)),
        sized(w, 3),
      ),
    )
    .map(([numeric, bytes]) => ({
      present: [...numeric, ...bytes].map((s) => s.present),
      values: numeric.map((s) => s.value),
      byteValues: bytes.map((s) => s.value),
    }));

/**
 * A claim `claimSchema` accepts, with every header field anywhere in its
 * Compact type's range. Pass `v` and `w` to match a mock's shape; omit them for
 * any shape.
 */
export const anyClaim = (shape: Shape = {}): fc.Arbitrary<Claim<number, number>> =>
  fc
    .record({
      version: anyUint(HEADER_UINT_BITS.version),
      appId: anyBytes32(),
      policyHash: anyBytes32(),
      windowStart: anyUint(HEADER_UINT_BITS.windowStart),
      windowEnd: anyUint(HEADER_UINT_BITS.windowEnd),
      subjectHash: anyBytes32(),
      holder: anyBytes32(),
      salt: anyBytes32(),
      slots: anySlots(shape),
    })
    .map(({ slots, ...header }) => ({ ...header, ...slots }));
