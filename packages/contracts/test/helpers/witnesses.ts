import type { JubjubPoint, WitnessContext } from '@midnight-ntwrk/compact-runtime';
import type {
  A_Claim,
  Ledger,
  Witnesses,
} from '../../artifacts/mock_attestation/contract/index.js';
import { ACCEPTED_POLICIES } from './fixtures.js';
import type { PrivateState } from './private-state.js';

export type WitnessBase = WitnessContext<Ledger, PrivateState>;

export const makeWitnesses = (
  registryKeys: JubjubPoint[],
  freshnessWindow = 0n,
  policyHashes: readonly Uint8Array[] = ACCEPTED_POLICIES,
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

  seedKeys: ({ privateState }: WitnessBase): [PrivateState, JubjubPoint[]] => [
    privateState,
    registryKeys,
  ],

  freshWindow: ({ privateState }: WitnessBase): [PrivateState, bigint] => [
    privateState,
    freshnessWindow,
  ],

  acceptedPolicies: ({ privateState }: WitnessBase): [PrivateState, Uint8Array[]] => [
    privateState,
    [...policyHashes],
  ],
});
