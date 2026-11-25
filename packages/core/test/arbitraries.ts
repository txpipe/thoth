// fast-check generators for valid claims, shared by the core property tests and
// the contracts circuit-parity tests.
import type { Claim } from '@txpipe/thoth-core/claim';
import fc from 'fast-check';

/** A uniformly random 32-byte array. */
export const bytes32 = (): fc.Arbitrary<Uint8Array> =>
  fc.uint8Array({ minLength: 32, maxLength: 32 });

/** An unsigned integer of the Compact type `Uint<bits>`. */
export const uint = (bits: number): fc.Arbitrary<bigint> =>
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
export const slots = ({
  v,
  w,
  present = fc.boolean(),
  value = uint(64),
  byteValue = bytes32(),
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
export const claim = (shape: Shape = {}): fc.Arbitrary<Claim<number, number>> =>
  fc
    .record({
      version: uint(8),
      appId: bytes32(),
      policyHash: bytes32(),
      windowStart: uint(32),
      windowEnd: uint(32),
      subjectHash: bytes32(),
      holder: bytes32(),
      salt: bytes32(),
      slots: slots(shape),
    })
    .map(({ slots, ...header }) => ({ ...header, ...slots }));
