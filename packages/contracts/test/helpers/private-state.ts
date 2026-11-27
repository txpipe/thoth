import type { JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { A_Claim } from '../../artifacts/mock_attestation/contract/index.js';

/** One signature and the registry slot whose key the contract checks it against. */
export type SlotSignature = {
  readonly registryIndex: bigint;
  readonly signature: JubjubSchnorrSignature;
};

/**
 * Private state the simulator threads through a mock contract's witnesses.
 *
 * @typeParam Claim — the artifact's claim type; defaults to the numeric-only
 *   mock's `A_Claim` so existing call sites stay unchanged.
 */
export type PrivateState<Claim = A_Claim> = {
  readonly claim: Claim | null;
  readonly signatures: readonly SlotSignature[];
  readonly holderSecret: Uint8Array;
};

export const createPrivateState = <Claim = A_Claim>(
  holderSecret: Uint8Array,
): PrivateState<Claim> => ({
  claim: null,
  signatures: [],
  holderSecret,
});
