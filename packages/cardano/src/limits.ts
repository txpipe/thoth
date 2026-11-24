// The cardano@1 kind's slot limits: an attestor is a network service, so a
// client-supplied claim may not size the work it does.

/**
 * The slot counts a cardano@1 claim may carry: the contract's `#V` numeric
 * slots and `W` byte slots. A client uses the same limits so a contract that
 * exceeds them fails at init, and a larger proposal is rejected before its
 * arrays are parsed.
 */
export const CARDANO_LIMITS = Object.freeze({
  valueSlots: 64,
  byteSlots: 64,
} as const);
