import type { A_Claim } from '../../artifacts/mock_attestation/contract/index.js';

export type SchnorrSignature = {
  announcement: { x: bigint; y: bigint };
  response: bigint;
};

export type PrivateState = {
  readonly claim: A_Claim | null;
  readonly signatures: SchnorrSignature[];
  readonly commitRand: Uint8Array;
  readonly holderSecret: Uint8Array;
};

export const createPrivateState = (holderSecret: Uint8Array): PrivateState => ({
  claim: null,
  signatures: [],
  commitRand: new Uint8Array(32),
  holderSecret,
});
