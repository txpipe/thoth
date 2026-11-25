import type { JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { A_Claim } from '../../artifacts/mock_attestation/contract/index.js';

/**
 * Private state the simulator threads through a mock contract's witnesses.
 *
 * @typeParam Claim — the artifact's claim type; defaults to the numeric-only
 *   mock's `A_Claim` so existing call sites stay unchanged.
 */
export type PrivateState<Claim = A_Claim> = {
  readonly claim: Claim | null;
  readonly signatures: JubjubSchnorrSignature[];
  readonly commitRand: Uint8Array;
  readonly holderSecret: Uint8Array;
};

export const createPrivateState = <Claim = A_Claim>(
  holderSecret: Uint8Array,
): PrivateState<Claim> => ({
  claim: null,
  signatures: [],
  commitRand: new Uint8Array(32),
  holderSecret,
});

/** Build a mock private state bound to `holderSecret` with optional field overrides. */
export const privateStateWith = <Claim = A_Claim>(
  holderSecret: Uint8Array,
  overrides: Partial<PrivateState<Claim>> = {},
): PrivateState<Claim> => ({
  ...createPrivateState<Claim>(holderSecret),
  ...overrides,
});
