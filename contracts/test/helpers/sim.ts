import {
  type CircuitContext,
  type CircuitResults,
  createCircuitContext,
  createConstructorContext,
  dummyContractAddress,
  type Effects,
} from '@midnight-ntwrk/compact-runtime';
import type * as ocrt from '@midnight-ntwrk/onchain-runtime-v3';
import { Contract, type Ledger, ledger } from '../../artifacts/mock_attestation/contract/index.js';
import type { PrivateState } from './private-state.js';
import { makeWitnesses } from './witnesses.js';

const ADDR = dummyContractAddress();
const COIN_PK = '0'.repeat(64);

export class MockAttestationSim {
  private state: ocrt.StateValue | ocrt.ChargedState;
  private lastEffects: Effects | null = null;
  private lastSigs: PrivateState['signatures'] | null = null;

  // Block-time override (seconds). Leave null to use the runtime default;
  // set it (e.g. to the claim timestamp ± offsets) to test freshness.
  now: number | null = null;

  readonly contract: Contract<PrivateState>;

  constructor(
    privateState: PrivateState,
    registryKeys: { x: bigint; y: bigint }[],
    freshnessWindow = 0n,
  ) {
    this.contract = new Contract<PrivateState>(makeWitnesses(registryKeys, freshnessWindow));
    const deploy = this.contract.initialState(createConstructorContext(privateState, COIN_PK));
    this.state = deploy.currentContractState;
  }

  call(name: string, ps: PrivateState, ...args: unknown[]): unknown {
    const ctx = createCircuitContext(
      ADDR,
      COIN_PK,
      this.state,
      ps,
      undefined,
      undefined,
      this.now ?? undefined,
    );
    const circuit = (
      this.contract.circuits as Record<
        string,
        (c: CircuitContext<PrivateState>, ...a: unknown[]) => CircuitResults<PrivateState, unknown>
      >
    )[name];
    const res = circuit(ctx, ...args);
    this.state = res.context.currentQueryContext.state;
    this.lastEffects = res.context.currentQueryContext.effects;
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
