import type { WitnessContext } from '@midnight-ntwrk/compact-runtime';
import type {
  A_Claim,
  Ledger,
  Witnesses,
} from '../../artifacts/mock_attestation/contract/index.js';
import type { PrivateState } from './private-state.js';
import { TWO_248 } from './sign.js';

export type WitnessBase = WitnessContext<Ledger, PrivateState>;

export const makeWitnesses = (
  registryKeys: { x: bigint; y: bigint }[],
  freshnessWindow = 0n,
): Witnesses<PrivateState> => ({
  getAttestationWitness: ({
    privateState,
  }: WitnessBase): [PrivateState, [A_Claim, PrivateState['signatures'], Uint8Array]] => {
    if (!privateState.claim) {
      throw new Error('getAttestationWitness: no claim in private state');
    }
    return [privateState, [privateState.claim, privateState.signatures, privateState.commitRand]];
  },

  getHolderSecret: ({ privateState }: WitnessBase): [PrivateState, Uint8Array] => [
    privateState,
    privateState.holderSecret,
  ],

  getSchnorrReduction: (
    { privateState }: WitnessBase,
    challengeHash: bigint,
  ): [PrivateState, [bigint, bigint]] => [
    privateState,
    [challengeHash / TWO_248, challengeHash % TWO_248],
  ],

  seedKeys: ({ privateState }: WitnessBase): [PrivateState, { x: bigint; y: bigint }[]] => [
    privateState,
    registryKeys,
  ],

  freshWindow: ({ privateState }: WitnessBase): [PrivateState, bigint] => [
    privateState,
    freshnessWindow,
  ],
});
