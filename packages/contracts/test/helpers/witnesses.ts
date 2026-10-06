import type { JubjubPoint, WitnessContext } from '@midnight-ntwrk/compact-runtime';
import type {
  A_Claim,
  Ledger,
  Witnesses,
} from '../../artifacts/mock_attestation/contract/index.js';
import { ACCEPTED_POLICIES, DEFAULT_FRESHNESS_WINDOW, DEFAULT_MAX_WINDOW } from './fixtures.js';
import type { PrivateState } from './private-state.js';

export type WitnessBase = WitnessContext<Ledger, PrivateState>;

/** Deploy-time values sealed by the mock constructor. Omitted values use fixture defaults. */
export type DeploySeals = {
  freshnessWindow?: bigint;
  maxWindow?: bigint;
  policyHashes?: readonly Uint8Array[];
};

export const makeWitnesses = (
  registryKeys: JubjubPoint[],
  {
    freshnessWindow = DEFAULT_FRESHNESS_WINDOW,
    maxWindow = DEFAULT_MAX_WINDOW,
    policyHashes = ACCEPTED_POLICIES,
  }: DeploySeals = {},
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

  maxWin: ({ privateState }: WitnessBase): [PrivateState, bigint] => [privateState, maxWindow],

  seedPolicies: ({ privateState }: WitnessBase): [PrivateState, Uint8Array[]] => [
    privateState,
    [...policyHashes],
  ],
});
