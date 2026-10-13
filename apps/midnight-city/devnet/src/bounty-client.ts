// A Bounty on the devnet as a small client: deploy one or join one by address, call its
// circuits as a given holder, and read its ledger. The Sponsor's demo (bounty.ts) and
// Hermes's skill both use it. Artifacts come from compiler 0.35.0 (`npm run compact:bounty`).
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  JubjubPoint,
  JubjubSchnorrSignature,
  WitnessContext,
} from '@midnight-ntwrk/compact-runtime';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { CompiledContract } from '@midnight-ntwrk/midnight-js-protocol/compact-js';
import type { MidnightProviders } from '@midnight-ntwrk/midnight-js-types';
import { createMidnightProviders } from '@midnight-ntwrk/midnight-js-utils';
import type * as Bounty from '../artifacts/bounty/contract/index.js';
import { LOCAL_ENDPOINTS, type WalletContext, walletProviders } from './wallet.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const ARTIFACTS = path.resolve(process.env.ARTIFACTS ?? path.join(here, '../artifacts/bounty'));
const PRIVATE_STATE_ID = 'bounty';

export type Claim = Bounty.A_Claim;
export type UserAddress = { bytes: Uint8Array };
export type Attestation = {
  claim: Claim;
  signatures: JubjubSchnorrSignature[];
  commitRand: Uint8Array;
};
/** A caller's private state: the claims its next call opens, in order, and its secret. */
export type PrivateState = { attestations: Attestation[]; holderSecret: Uint8Array };
export type Circuit = 'verifyAttestation' | 'register' | 'qualify' | 'fund' | 'payout' | 'refund';

/** A Bounty's terms, sealed at deploy. */
export interface Terms {
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
}

/** Where a client keeps its private state, and the NIGHT cap its wallet enforces. */
export interface ClientOptions {
  stateDir: string;
  capNight?: bigint;
}

export interface BountyClient {
  readonly address: string;
  readonly pure: typeof Bounty.pureCircuits;
  ledger(): Promise<Bounty.Ledger>;
  /** Run `circuit` holding `as`; resolves once the transaction is in a block. */
  call(as: PrivateState, circuit: Circuit, ...args: unknown[]): Promise<{ blockHeight: bigint }>;
}

/** An empty private state, for calls that open no claim. */
export const NO_CLAIMS: PrivateState = { attestations: [], holderSecret: new Uint8Array(32) };

/** The wallet's own address, as a circuit takes it. */
export const userAddressOf = ({ unshieldedKeystore }: WalletContext): UserAddress => ({
  bytes: Buffer.from(unshieldedKeystore.getAddress(), 'hex'),
});

type Ctx = WitnessContext<Bounty.Ledger, PrivateState>;
const witnesses = {
  // Each call takes the next queued claim, so Registration can open two.
  getAttestationWitness: ({ privateState }: Ctx) => {
    const [next, ...rest] = privateState.attestations;
    if (next === undefined) {
      throw new Error('getAttestationWitness: no claim queued');
    }
    return [
      { ...privateState, attestations: rest },
      [next.claim, next.signatures, next.commitRand],
    ] as [PrivateState, [Claim, JubjubSchnorrSignature[], Uint8Array]];
  },
  getHolderSecret: ({ privateState }: Ctx) =>
    [privateState, privateState.holderSecret] as [PrivateState, Uint8Array],
  payoutSecret: ({ privateState }: Ctx) =>
    [privateState, privateState.holderSecret] as [PrivateState, Uint8Array],
  payoutPath: ({ ledger, privateState }: Ctx, leaf: Uint8Array) =>
    [
      privateState,
      ledger.qualifiedPayees.findPathForLeaf(leaf) ?? ledger.qualifiedPayees.pathForLeaf(0n, leaf),
    ] as const,
};

/** The compiled Bounty module. */
export const loadBounty = async (): Promise<typeof Bounty> =>
  (await import(path.join(ARTIFACTS, 'contract/index.js'))) as typeof Bounty;

const setUp = async (walletContext: WalletContext, options: ClientOptions) => {
  const bounty = await loadBounty();
  const wallet = walletProviders(walletContext, options.capNight);
  // Node 2.1.0 rejects a transaction whose cost to dismiss exceeds max(15 ms, 2 µs per byte)
  // (`OutsideTimeToDismiss`, custom error 231). A long TTL makes balancing add DUST inputs and
  // their proofs, which a small call like `fund` can't afford, so calls use a short TTL. The
  // large deploy can, and needs the long one on a young chain whose DUST is still generating.
  const config = { networkId: 'undeployed', ttlSeconds: 3_600 };
  const zkConfigProvider = new NodeZkConfigProvider<Circuit>(ARTIFACTS);
  const providers: MidnightProviders<Circuit, typeof PRIVATE_STATE_ID, PrivateState> =
    createMidnightProviders({
      privateStateProvider: levelPrivateStateProvider<typeof PRIVATE_STATE_ID, PrivateState>({
        midnightDbName: path.join(options.stateDir, 'midnight-level-db'),
        privateStateStoreName: 'bounty-private-state',
        signingKeyStoreName: 'bounty-signing-keys',
        privateStoragePasswordProvider: () => 'Thoth-devnet-only-Passw0rd!',
        accountId: Buffer.from(wallet.getCoinPublicKey()).toString('hex'),
      }),
      publicDataProvider: indexerPublicDataProvider(
        LOCAL_ENDPOINTS.indexer,
        LOCAL_ENDPOINTS.indexerWS,
      ),
      zkConfigProvider,
      proofProvider: httpClientProofProvider(LOCAL_ENDPOINTS.proofServer, zkConfigProvider),
      walletProvider: wallet,
      midnightProvider: wallet,
      config,
    });
  const compiledContract = CompiledContract.make<Bounty.Contract<PrivateState>>(
    'Bounty',
    bounty.Contract<PrivateState>,
  ).pipe(
    CompiledContract.withWitnesses(witnesses as never),
    CompiledContract.withCompiledFileAssets(ARTIFACTS),
  );
  const shortTtl = () => {
    config.ttlSeconds = Number(process.env.TX_TTL_SECONDS ?? 120);
  };
  return { bounty, providers, compiledContract, shortTtl };
};

type SetUp = Awaited<ReturnType<typeof setUp>>;

const clientOf = (
  { bounty, providers }: SetUp,
  address: string,
  callTx: Record<string, (...args: unknown[]) => Promise<{ public: { blockHeight: number } }>>,
): BountyClient => ({
  address,
  pure: bounty.pureCircuits,
  ledger: async () => {
    const state = await providers.publicDataProvider.queryContractState(address);
    if (!state) {
      throw new Error(`no Bounty at ${address}`);
    }
    return bounty.ledger(state.data);
  },
  call: async (as, circuit, ...args) => {
    await providers.privateStateProvider.set(PRIVATE_STATE_ID, as);
    const run = callTx[circuit];
    if (run === undefined) {
      throw new Error(`no circuit named '${circuit}'`);
    }
    const tx = await run(...args);
    return { blockHeight: BigInt(tx.public.blockHeight) };
  },
});

/**
 * Deploy a Bounty with `terms`, paying from `walletContext`.
 *
 * @returns a client for the new Bounty.
 */
export const deployBounty = async (
  walletContext: WalletContext,
  terms: Terms,
  options: ClientOptions,
): Promise<BountyClient> => {
  const ready = await setUp(walletContext, options);
  const deployed = await deployContract(ready.providers, {
    compiledContract: ready.compiledContract,
    privateStateId: PRIVATE_STATE_ID,
    initialPrivateState: NO_CLAIMS,
    args: [
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
    ],
  } as never);
  const deployTx = deployed.deployTxData;
  if (!('public' in deployTx)) {
    throw new Error('expected a ledger-9 deploy');
  }
  // shortcut: the `as never` deploy options erase the contract's types; type them if this outlives the spike.
  const address = (deployTx.public as { contractAddress: string }).contractAddress;
  ready.shortTtl();
  return clientOf(ready, address, deployed.callTx as never);
};

/**
 * Join the Bounty at `address`.
 *
 * @returns a client for it.
 */
export const joinBounty = async (
  walletContext: WalletContext,
  address: string,
  options: ClientOptions,
): Promise<BountyClient> => {
  const ready = await setUp(walletContext, options);
  ready.shortTtl();
  const found = await findDeployedContract(ready.providers, {
    compiledContract: ready.compiledContract,
    contractAddress: address,
    privateStateId: PRIVATE_STATE_ID,
    initialPrivateState: NO_CLAIMS,
  } as never);
  return clientOf(ready, address, found.callTx as never);
};

/**
 * Read the Bounty at `address` from the indexer, without a wallet.
 *
 * @returns its ledger.
 */
export const readBounty = async (address: string): Promise<Bounty.Ledger> => {
  const bounty = await loadBounty();
  const state = await indexerPublicDataProvider(
    LOCAL_ENDPOINTS.indexer,
    LOCAL_ENDPOINTS.indexerWS,
  ).queryContractState(address);
  if (!state) {
    throw new Error(`no Bounty at ${address}`);
  }
  return bounty.ledger(state.data);
};
