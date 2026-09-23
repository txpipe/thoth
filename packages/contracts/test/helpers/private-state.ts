import type { JubjubSchnorrSignature } from '@midnight-ntwrk/compact-runtime';
import type { A_Claim } from '../../artifacts/mock_attestation/contract/index.js';

export type PrivateState = {
  readonly claim: A_Claim | null;
  readonly signatures: JubjubSchnorrSignature[];
  readonly commitRand: Uint8Array;
  readonly holderSecret: Uint8Array;
};

export const createPrivateState = (holderSecret: Uint8Array): PrivateState => ({
  claim: null,
  signatures: [],
  commitRand: new Uint8Array(32),
  holderSecret,
});
