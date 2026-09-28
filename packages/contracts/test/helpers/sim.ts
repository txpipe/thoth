import {
  type ChargedState,
  type CircuitContext,
  type CircuitResults,
  createCircuitContext,
  createConstructorContext,
  dummyContractAddress,
  type Effects,
  type JubjubPoint,
  type StateValue,
} from '@midnight-ntwrk/compact-runtime';
import { Contract, type Ledger, ledger } from '../../artifacts/mock_attestation/contract/index.js';
import type { PrivateState } from './private-state.js';
import { makeWitnesses } from './witnesses.js';

const ADDR = dummyContractAddress();
const COIN_PK = '0'.repeat(64);

export class MockAttestationSim {
  private lastEffects: Effects | null = null;
  private lastSigs: PrivateState['signatures'] | null = null;

  // Block-time override (seconds). Leave null to use the runtime default;
  // set it (e.g. to the claim timestamp ± offsets) to test freshness.
  now: number | null = null;

  readonly contract: Contract<PrivateState>;
  private state: StateValue | ChargedState;

  private constructor(contract: Contract<PrivateState>, state: StateValue | ChargedState) {
    this.contract = contract;
    this.state = state;
  }

  // Deploy is async under runtime 0.19 (`initialState` returns a Promise), so
  // construction goes through this factory.
  static async create(
    privateState: PrivateState,
    registryKeys: JubjubPoint[],
    freshnessWindow = 0n,
  ): Promise<MockAttestationSim> {
    const contract = new Contract<PrivateState>(makeWitnesses(registryKeys, freshnessWindow));
    const deploy = await contract.initialState(createConstructorContext(privateState, COIN_PK));
    return new MockAttestationSim(contract, deploy.currentContractState.data);
  }

  async call(name: string, ps: PrivateState, ...args: unknown[]): Promise<unknown> {
    const ctx = createCircuitContext(
      name,
      ADDR,
      COIN_PK,
      this.state,
      ps,
      undefined, // stateProvider
      undefined, // gasLimit
      undefined, // costModel
      this.now ?? undefined,
    );
    const circuit = (
      this.contract.circuits as Record<
        string,
        (
          c: CircuitContext<PrivateState>,
          ...a: unknown[]
        ) => Promise<CircuitResults<PrivateState, unknown>>
      >
    )[name];
    if (!circuit) {
      throw new Error(`no circuit named '${name}'`);
    }
    const res = await circuit(ctx, ...args);
    this.state = res.context.callContext.currentQueryContext.state;
    this.lastEffects = res.context.callContext.currentQueryContext.effects;
    this.lastSigs = ps.signatures;
    return res.result;
  }

  effects(): Effects {
    if (!this.lastEffects) {
      throw new Error('no circuit call executed yet');
    }
    return this.lastEffects;
  }

  lastSignatures(): PrivateState['signatures'] {
    if (!this.lastSigs) {
      throw new Error('no circuit call executed yet');
    }
    return this.lastSigs;
  }

  ledgerView(): Ledger {
    return ledger(this.state);
  }
}
