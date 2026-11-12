// The attestation module's parameters, derived from the policy's layout, the
// attestor list and the threshold, so no app computes them by hand.
import type { KindLayout } from '@thoth/core/kind';

/**
 * The parameters of `import "attestation"<K, V, B, N, M>`, plus `W`, the byte
 * value count `B` is derived from.
 */
export interface ModuleParameters {
  /** Numeric value slots: the module's `#V`. */
  readonly V: number;
  /** Byte value slots: the client's `byteSlots`. */
  readonly W: number;
  /** Byte halves, `2 * W`: the module's `#B`. */
  readonly B: number;
  /** Signed-message length in fields: the module's `#K`. */
  readonly K: number;
  /** The threshold: the module's `#N`. */
  readonly N: number;
  /** Registry slots, one per attestor: the module's `#M`. */
  readonly M: number;
}

// The fixed fields of the wire layout in the `attestation.compact` header:
// version, appId, policyHash, the window, subjectHash, holder, salt and B.
const HEADER_FIELDS = 14;

/**
 * Derive the module parameters. `K` follows the wire layout in the
 * `attestation.compact` header.
 *
 * @param attestors - the number of attestors, `#M`.
 * @param threshold - `#N`, from 1 to `attestors`.
 * @throws `Error` if there is no attestor, the threshold is out of range, or
 *   the layout has no slot.
 */
export function moduleParameters(
  layout: Pick<KindLayout, 'valueSlots' | 'byteSlots'>,
  attestors: number,
  threshold: number,
): ModuleParameters {
  if (attestors < 1) {
    throw new Error('the config needs at least one attestor');
  }
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > attestors) {
    throw new Error(`threshold must be an integer from 1 to ${attestors}, got ${threshold}`);
  }
  const V = layout.valueSlots;
  const W = layout.byteSlots;
  if (V + W === 0) {
    throw new Error('the policy has no slot');
  }
  const B = 2 * W;
  return { V, W, B, K: HEADER_FIELDS + 2 * V + 2 * B, N: threshold, M: attestors };
}
