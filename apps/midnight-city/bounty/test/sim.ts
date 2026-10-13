// Simulator driver for the Bounty: deploys it and calls its circuits at a chosen
// block time, like packages/contracts/test/helpers/sim.ts. Claims are signed with
// @thoth/core's claimToMessage, the encoder real attestors use.
import { randomBytes } from 'node:crypto';
import {
  type ChargedState,
  type CircuitContext,
  type CircuitResults,
  CompactTypeField,
  CompactTypeVector,
  createCircuitContext,
  createConstructorContext,
  dummyContractAddress,
  type Effects,
  type JubjubPoint,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  type StateValue,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';
import { claimToMessage } from '@thoth/core/claim';
import { parseDisclosedValue } from '@thoth/zk-tls';
import {
  type A_Claim,
  Contract,
  type Ledger,
  ledger,
  pureCircuits,
  type Witnesses,
} from '../artifacts/bounty/contract/index.js';

const COIN_PK = '0'.repeat(64);

/** A vaulted or vaultable claim, as its holder keeps it. */
export type Attestation = {
  claim: A_Claim;
  signatures: JubjubSchnorrSignature[];
  commitRand: Uint8Array;
};

/**
 * The caller's private state: the claims its next call opens, in order, and its
 * secret. `pathFor` makes the payout-path witness return another leaf's path, to
 * stage a forged Payout.
 */
export type PrivateState = {
  attestations: Attestation[];
  holderSecret: Uint8Array;
  pathFor?: Uint8Array | undefined;
};

/** A Midnight `UserAddress`, as the compiled contract takes it. */
export type UserAddress = { bytes: Uint8Array };

const witnesses: Witnesses<PrivateState> = {
  // Each call takes the next queued claim, so one circuit can open several.
  getAttestationWitness: ({ privateState }) => {
    const [next, ...rest] = privateState.attestations;
    if (next === undefined) {
      throw new Error('getAttestationWitness: no claim queued');
    }
    return [
      { ...privateState, attestations: rest },
      [next.claim, next.signatures, next.commitRand],
    ];
  },
  getHolderSecret: ({ privateState }) => [privateState, privateState.holderSecret],
  payoutSecret: ({ privateState }) => [privateState, privateState.holderSecret],
  // An honest holder's own path; a leaf not in the tree gets a path that can't match the root.
  payoutPath: ({ ledger, privateState }, leaf) => {
    const target = privateState.pathFor ?? leaf;
    return [
      privateState,
      ledger.qualifiedPayees.findPathForLeaf(target) ??
        ledger.qualifiedPayees.pathForLeaf(0n, target),
    ];
  },
};

/** The Bounty's deploy-time terms. */
export type Terms = {
  keys: JubjubPoint[];
  controlPolicy: Uint8Array;
  readingPolicy: Uint8Array;
  threshold: bigint;
  opensAt: bigint;
  deadline: bigint;
  payoutEnd: bigint;
  sponsor: UserAddress;
  freshnessWindow: bigint;
  maxWindow: bigint;
};

export class BountySim {
  /** Block time (Unix seconds) for the next call. */
  now = 0n;

  private readonly contract: Contract<PrivateState>;
  private state: StateValue | ChargedState;

  private constructor(contract: Contract<PrivateState>, state: StateValue | ChargedState) {
    this.contract = contract;
    this.state = state;
  }

  static async deploy(terms: Terms): Promise<BountySim> {
    const contract = new Contract<PrivateState>(witnesses);
    const deploy = await contract.initialState(
      createConstructorContext({ attestations: [], holderSecret: new Uint8Array(32) }, COIN_PK),
      terms.keys,
      terms.controlPolicy,
      terms.readingPolicy,
      terms.threshold,
      terms.opensAt,
      terms.deadline,
      terms.payoutEnd,
      terms.sponsor,
      terms.freshnessWindow,
      terms.maxWindow,
    );
    return new BountySim(contract, deploy.currentContractState.data);
  }

  /** Call circuit `name` as the caller holding `ps`; returns the token effects. */
  async call(name: string, ps: PrivateState, ...args: unknown[]): Promise<Effects> {
    const ctx = createCircuitContext(
      name,
      dummyContractAddress(),
      COIN_PK,
      this.state,
      ps,
      undefined,
      undefined,
      undefined,
      Number(this.now),
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
    if (circuit === undefined) {
      throw new Error(`no circuit named '${name}'`);
    }
    const result = await circuit(ctx, ...args);
    this.state = result.context.callContext.currentQueryContext.state;
    return result.context.callContext.currentQueryContext.effects;
  }

  ledger(): Ledger {
    return ledger(this.state);
  }
}

export type NotaryKey = { sk: bigint; pk: JubjubPoint };

export const makeNotaryKey = (): NotaryKey => {
  const sk = sampleJubjubSchnorrSk();
  return { sk, pk: jubjubSchnorrVerifyingKey(sk) };
};

/** A signature that never verifies, for an attestor that didn't sign. */
export const UNSIGNED: JubjubSchnorrSignature = { announcement: { x: 0n, y: 1n }, response: 0n };

/** Sign a flat message, as an attestor's signer does. */
export const signMessage = (sk: bigint, message: readonly bigint[]): JubjubSchnorrSignature =>
  jubjubSchnorrSign(new CompactTypeVector(message.length, CompactTypeField), [...message], sk);

/** Sign `claim` with `keys` (null: that attestor didn't sign) and pick its vault randomness. */
export const sign = (claim: A_Claim, keys: readonly (NotaryKey | null)[]): Attestation => {
  const message = claimToMessage(claim);
  return {
    claim,
    signatures: keys.map((key) => (key === null ? UNSIGNED : signMessage(key.sk, message))),
    commitRand: randomBytes(32),
  };
};

/** The vault id an attestation is stored under. */
export const idOf = (attestation: Attestation): Uint8Array =>
  pureCircuits.computeId(attestation.claim, attestation.commitRand);

/**
 * An agent ID as the five `bytes8` slots its claims carry: the part after
 * `user-agent-` in 8-character chunks, as the policies' regex groups split it.
 */
export const agentSlots = (agentId: string): bigint[] => {
  const id = agentId.replace(/^user-agent-/, '');
  return Array.from({ length: 5 }, (_, i) => {
    const value = parseDisclosedValue(id.slice(i * 8, i * 8 + 8), 'bytes8');
    if (value === null) {
      throw new Error(`agent ID ${agentId} doesn't fit five bytes8 slots`);
    }
    return value;
  });
};

/** The claim a holder gets: XP in slot 0 for a Reading, the agent ID in slots 1-5. */
export const claimFor = (options: {
  policy: Uint8Array;
  agentId: string;
  xp: bigint | null;
  window: readonly [bigint, bigint];
  secret: Uint8Array;
}): A_Claim => ({
  version: 1n,
  appId: new Uint8Array(32).fill(0xa1),
  policyHash: options.policy,
  windowStart: options.window[0],
  windowEnd: options.window[1],
  subjectHash: randomBytes(32),
  holder: pureCircuits.holderCommitment(options.secret),
  present: [options.xp !== null, true, true, true, true, true],
  values: [options.xp ?? 0n, ...agentSlots(options.agentId)],
});

/** The agent key a Registration is stored under, for an agent ID. */
export const agentKey = (agentId: string): Uint8Array => pureCircuits.agentKey(agentSlots(agentId));

/** The payout leaf a Registration commits to: the address under the holder's secret. */
export const payoutLeaf = (secret: Uint8Array, to: UserAddress): Uint8Array =>
  pureCircuits.payoutLeaf(secret, to);
