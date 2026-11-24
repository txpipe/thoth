import { degradeToTransient, type JubjubPoint } from '@midnight-ntwrk/compact-runtime';
import {
  ACCEPTED_POLICIES,
  APP_ID,
  DEFAULT_FRESHNESS_WINDOW,
  DEFAULT_MAX_WINDOW,
} from './fixtures.js';
import type { PrivateState } from './private-state.js';

/**
 * The context each witness reads. Every artifact's `WitnessContext` is
 * assignable to it, so one implementation serves every mock specialization.
 *
 * @typeParam Claim — the artifact's claim type.
 */
export type WitnessBase<Claim> = {
  readonly privateState: PrivateState<Claim>;
};

/** Deploy-time values sealed by the mock constructor. Omitted values use fixture defaults. */
export type DeploySeals = {
  appId?: Uint8Array;
  freshnessWindow?: bigint;
  maxWindow?: bigint;
  policyHashes?: readonly Uint8Array[];
};

/**
 * Witness implementations shared by every mock artifact: the attestation
 * witness is typed to the artifact's `Claim`, everything else is
 * artifact-independent.
 *
 * @typeParam Claim — the artifact's claim type.
 * @param registryKeys — the Jubjub points the constructor seals.
 * @param seals — deploy-time values; omitted ones use fixture defaults.
 * @returns the witness record the artifact's `Contract` constructor accepts.
 */
export const makeWitnesses = <Claim>(
  registryKeys: JubjubPoint[],
  {
    appId = APP_ID,
    freshnessWindow = DEFAULT_FRESHNESS_WINDOW,
    maxWindow = DEFAULT_MAX_WINDOW,
    policyHashes = ACCEPTED_POLICIES,
  }: DeploySeals = {},
) => ({
  getAttestationWitness: ({ privateState }: WitnessBase<Claim>): [PrivateState<Claim>, Claim] => {
    if (!privateState.claim) {
      throw new Error('getAttestationWitness: no claim in private state');
    }
    return [privateState, privateState.claim];
  },

  getSignatures: ({
    privateState,
  }: WitnessBase<Claim>): [PrivateState<Claim>, PrivateState<Claim>['signatures']] => [
    privateState,
    privateState.signatures,
  ],

  getHolderSecret: ({ privateState }: WitnessBase<Claim>): [PrivateState<Claim>, Uint8Array] => [
    privateState,
    privateState.holderSecret,
  ],

  // The pseudonym's scalar: the secret's first 31 bytes read little-endian.
  getHolderScalar: ({ privateState }: WitnessBase<Claim>): [PrivateState<Claim>, bigint] => [
    privateState,
    degradeToTransient(privateState.holderSecret),
  ],

  seedKeys: ({ privateState }: WitnessBase<Claim>): [PrivateState<Claim>, JubjubPoint[]] => [
    privateState,
    registryKeys,
  ],

  seedAppId: ({ privateState }: WitnessBase<Claim>): [PrivateState<Claim>, Uint8Array] => [
    privateState,
    appId,
  ],

  freshWindow: ({ privateState }: WitnessBase<Claim>): [PrivateState<Claim>, bigint] => [
    privateState,
    freshnessWindow,
  ],

  maxWin: ({ privateState }: WitnessBase<Claim>): [PrivateState<Claim>, bigint] => [
    privateState,
    maxWindow,
  ],

  seedPolicies: ({ privateState }: WitnessBase<Claim>): [PrivateState<Claim>, Uint8Array[]] => [
    privateState,
    [...policyHashes],
  ],
});
