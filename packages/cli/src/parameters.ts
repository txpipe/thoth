// The attestation module's parameters, derived from the policy's layout, the
// attestor list and the threshold, so no app computes them by hand.
import { CLAIM_VERSION, claimToMessage } from '@thoth/core/claim';
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

const zeros = (length: number): Uint8Array => new Uint8Array(length);

// The signed-message length, from the off-chain encoder rather than a copy of
// the wire layout: an all-absent claim of V numeric and W byte values.
const messageLength = (V: number, W: number): number =>
  claimToMessage({
    version: CLAIM_VERSION,
    appId: zeros(32),
    policyHash: zeros(32),
    windowStart: 0n,
    windowEnd: 0n,
    subjectHash: zeros(32),
    holder: zeros(32),
    salt: zeros(32),
    present: Array.from({ length: V + W }, () => false),
    values: Array.from({ length: V }, () => 0n),
    byteValues: Array.from({ length: W }, () => zeros(32)),
  }).length;

/**
 * Derive the module parameters. `K` is the length of the message
 * `claimToMessage` from `@thoth/core/claim` encodes for this layout.
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
  return { V, W, B, K: messageLength(V, W), N: threshold, M: attestors };
}
