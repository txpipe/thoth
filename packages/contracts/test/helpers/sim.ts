import {
  type ChargedState,
  type CircuitContext,
  type CircuitResults,
  type ConstructorContext,
  createCircuitContext,
  createConstructorContext,
  dummyContractAddress,
  type Effects,
  type JubjubPoint,
  type StateValue,
} from '@midnight-ntwrk/compact-runtime';
import {
  type A_Claim,
  Contract as MockContract,
  type Ledger as MockLedger,
  ledger as mockLedger,
} from '../../artifacts/mock_attestation/contract/index.js';
import {
  type B_Claim,
  Contract as BytesContract,
  type Ledger as BytesLedger,
  ledger as bytesLedger,
} from '../../artifacts/mock_attestation_bytes/contract/index.js';
import type { PrivateState, SlotSignature } from './private-state.js';
import { type DeploySeals, makeWitnesses } from './witnesses.js';

const ADDR = dummyContractAddress();
const COIN_PK = '0'.repeat(64);

type SimState = StateValue | ChargedState;

/** The parts of a generated `Contract` class the simulator drives. */
type ContractLike<PS> = {
  circuits: Record<string, unknown>;
  initialState(context: ConstructorContext<PS>): Promise<{
    currentContractState: { data: SimState };
  }>;
};

/**
 * Build a simulator class for one mock artifact.
 *
 * @typeParam PS — the artifact's private-state type (`PrivateState<Claim>`).
 * @typeParam L — the artifact's ledger view type.
 * @param options — how to construct the artifact's contract and read its ledger.
 * @returns a class whose `create` deploys the mock and whose `call` runs circuits.
 */
const makeSimClass = <PS extends { signatures: SlotSignature[] }, L>(options: {
  newContract: (
    privateState: PS,
    registryKeys: JubjubPoint[],
    seals: DeploySeals,
  ) => ContractLike<PS>;
  ledgerOf: (state: SimState) => L;
}) => {
  const { newContract, ledgerOf } = options;
  return class MockSim {
    // Internal simulator bookkeeping (kept public so the factory's class type
    // can be exported; tests should use effects()/lastSignatures()).
    lastEffects: Effects | null = null;
    lastSigs: SlotSignature[] | null = null;

    // Block-time override (seconds). Leave null to use the runtime default;
    // set it (e.g. to the claim window ± offsets) to test the window checks.
    now: number | null = null;

    readonly contract: ContractLike<PS>;
    state: SimState;

    constructor(contract: ContractLike<PS>, state: SimState) {
      this.contract = contract;
      this.state = state;
    }

    // Deploy is async (`initialState` returns a Promise), so construction goes
    // through this factory.
    static async create(
      privateState: PS,
      registryKeys: JubjubPoint[],
      seals: DeploySeals = {},
    ): Promise<MockSim> {
      const contract = newContract(privateState, registryKeys, seals);
      const deploy = await contract.initialState(createConstructorContext(privateState, COIN_PK));
      return new MockSim(contract, deploy.currentContractState.data);
    }

    async call(name: string, ps: PS, ...args: unknown[]): Promise<unknown> {
      const ctx = createCircuitContext({
        circuitId: name,
        contractAddress: ADDR,
        coinPublicKeyOrZswapState: COIN_PK,
        contractState: this.state,
        privateState: ps,
        time: this.now ?? undefined,
      });
      const circuit = this.contract.circuits[name] as
        | ((
            context: CircuitContext<PS>,
            ...args: unknown[]
          ) => Promise<CircuitResults<PS, unknown>>)
        | undefined;
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

    lastSignatures(): SlotSignature[] {
      if (!this.lastSigs) {
        throw new Error('no circuit call executed yet');
      }
      return this.lastSigs;
    }

    ledgerView(): L {
      return ledgerOf(this.state);
    }
  };
};

/** Simulator for the numeric-only mock (`MockAttestation.compact`). */
export const MockAttestationSim = makeSimClass<PrivateState<A_Claim>, MockLedger>({
  newContract: (_privateState, registryKeys, seals) =>
    new MockContract<PrivateState<A_Claim>>(makeWitnesses<A_Claim>(registryKeys, seals)),
  ledgerOf: mockLedger,
});
export type MockAttestationSim = InstanceType<typeof MockAttestationSim>;

/** Simulator for the byte-slot mock (`MockAttestationBytes.compact`). */
export const MockAttestationBytesSim = makeSimClass<PrivateState<B_Claim>, BytesLedger>({
  newContract: (_privateState, registryKeys, seals) =>
    new BytesContract<PrivateState<B_Claim>>(makeWitnesses<B_Claim>(registryKeys, seals)),
  ledgerOf: bytesLedger,
});
export type MockAttestationBytesSim = InstanceType<typeof MockAttestationBytesSim>;
