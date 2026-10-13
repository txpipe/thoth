// Run a Bounty (#122) on the local ledger-9 devnet with real tNIGHT: deploy it,
// fund the pot, register and qualify two agents, pay one Qualifier its Share,
// and refund the rest to the Sponsor after the Payout period. The genesis wallet
// plays the Sponsor and both Controllers, each Controller with a fresh secret.
//
// Claims are signed by three test attestor keys pinned at deploy, as in the
// Bounty's simulator tests: this run checks the contract on a chain (proofs,
// block time, tNIGHT moving), not zkFetch, which recorded.test.ts covers.
// Its windows follow the wall clock, because the chain checks them against
// block time.
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
  type WitnessContext,
} from '@midnight-ntwrk/compact-runtime';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { CompiledContract } from '@midnight-ntwrk/midnight-js-protocol/compact-js';
import type { MidnightProviders } from '@midnight-ntwrk/midnight-js-types';
import { createMidnightProviders } from '@midnight-ntwrk/midnight-js-utils';
import { Token } from '@midnightntwrk/wallet-sdk';
import { claimToMessage } from '@thoth/core/claim';
import { parseDisclosedValue } from '@thoth/zk-tls';
import * as Rx from 'rxjs';
import type * as Bounty from '../artifacts/bounty/contract/index.js';
import { buildWallet, GENESIS_SEED, LOCAL_ENDPOINTS, walletProviders } from './wallet.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const artifacts = path.resolve(process.env.ARTIFACTS ?? path.join(here, '../artifacts/bounty'));
const PRIVATE_STATE_ID = 'bounty';

type Claim = Bounty.A_Claim;
type UserAddress = { bytes: Uint8Array };
type Attestation = { claim: Claim; signatures: JubjubSchnorrSignature[]; commitRand: Uint8Array };
type PrivateState = { attestations: Attestation[]; holderSecret: Uint8Array };
type Circuit = 'verifyAttestation' | 'register' | 'qualify' | 'fund' | 'payout' | 'refund';

const CONTROL_POLICY = new Uint8Array(32).fill(0xc0);
const READING_POLICY = new Uint8Array(32).fill(0xe0);
const THRESHOLD = 10_000n;
const POT = 1_001n;
const AGENT_A = 'user-agent-lhb10ef8yjy1wfc';
const AGENT_B = 'user-agent-dc4ccc6f-53ce-4e17-921c-8f5848590269';

const step = (message: string): void => console.log(`\n▸ ${message}`);
const now = (): bigint => BigInt(Math.floor(Date.now() / 1000));
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Sleep until block time can be past `t` (Unix seconds), with a margin for block lag. */
const waitUntil = async (t: bigint, label: string): Promise<void> => {
  const ms = Number(t - now() + 10n) * 1000;
  if (ms > 0) {
    console.log(`  waiting ${Math.ceil(ms / 1000)} s for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
};

// Three test attestors; 2-of-3, the third never signs.
const attestorKeys = [0, 1, 2].map(() => {
  const sk = sampleJubjubSchnorrSk();
  return { sk, pk: jubjubSchnorrVerifyingKey(sk) };
});
const UNSIGNED: JubjubSchnorrSignature = { announcement: { x: 0n, y: 1n }, response: 0n };

const sign = (claim: Claim): Attestation => {
  const message = claimToMessage(claim);
  const type = new CompactTypeVector(message.length, CompactTypeField);
  return {
    claim,
    signatures: attestorKeys.map((key, i) =>
      i < 2 ? jubjubSchnorrSign(type, [...message], key.sk) : UNSIGNED,
    ),
    commitRand: randomBytes(32),
  };
};

/** The agent ID after `user-agent-` as the five `bytes8` slots the policies read. */
const agentSlots = (agentId: string): bigint[] => {
  const id = agentId.replace(/^user-agent-/, '');
  return [0, 1, 2, 3, 4].map(
    (i) => parseDisclosedValue(id.slice(i * 8, i * 8 + 8), 'bytes8') ?? 0n,
  );
};

const main = async (): Promise<void> => {
  step(`artifacts: ${artifacts}`);
  const bounty = (await import(path.join(artifacts, 'contract/index.js'))) as typeof Bounty;

  const claimFor = (
    policy: Uint8Array,
    agentId: string,
    xp: bigint | null,
    at: bigint,
    secret: Uint8Array,
  ): Claim => ({
    version: 1n,
    appId: new Uint8Array(32).fill(0xa1),
    policyHash: policy,
    windowStart: at,
    windowEnd: at + 1n,
    subjectHash: randomBytes(32),
    holder: bounty.pureCircuits.holderCommitment(secret),
    present: [xp !== null, true, true, true, true, true],
    values: [xp ?? 0n, ...agentSlots(agentId)],
  });

  step('building the wallet (Sponsor and both Controllers)');
  const walletContext = await buildWallet(LOCAL_ENDPOINTS, GENESIS_SEED);
  const wallet = walletProviders(walletContext);
  const self: UserAddress = {
    bytes: Buffer.from(walletContext.unshieldedKeystore.getAddress(), 'hex'),
  };
  const nightBalance = async (): Promise<bigint> =>
    (await Rx.firstValueFrom(walletContext.wallet.state())).unshielded.balances[Token.night] ?? 0n;
  console.log(`  address ${hex(self.bytes)}, ${await nightBalance()} NIGHT`);

  // Node 2.1.0 rejects a transaction whose cost to dismiss exceeds max(15 ms, 2 µs per byte)
  // (`OutsideTimeToDismiss`, custom error 231). A long TTL makes balancing add DUST inputs and
  // their proofs, which a small call like `fund` can't afford, so calls use a short TTL. The
  // large deploy can, and needs the long one on a young chain whose DUST is still generating.
  const config = { networkId: 'undeployed', ttlSeconds: 3_600 };
  const zkConfigProvider = new NodeZkConfigProvider<Circuit>(artifacts);
  const providers: MidnightProviders<Circuit, typeof PRIVATE_STATE_ID, PrivateState> =
    createMidnightProviders({
      privateStateProvider: levelPrivateStateProvider<typeof PRIVATE_STATE_ID, PrivateState>({
        midnightDbName: path.join(here, '../.state/midnight-level-db'),
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
        ledger.qualifiedPayees.findPathForLeaf(leaf) ??
          ledger.qualifiedPayees.pathForLeaf(0n, leaf),
      ] as const,
  };
  const compiledContract = CompiledContract.make<Bounty.Contract<PrivateState>>(
    'Bounty',
    bounty.Contract<PrivateState>,
  ).pipe(
    CompiledContract.withWitnesses(witnesses as never),
    CompiledContract.withCompiledFileAssets(artifacts),
  );

  const opensAt = now() + 30n;
  const deadline = opensAt + 600n;
  const payoutEnd = deadline + 120n;
  step('deploying the Bounty: opens +30 s, deadline +10.5 min, Payout period ends +12.5 min');
  const deployed = await deployContract(providers, {
    compiledContract,
    privateStateId: PRIVATE_STATE_ID,
    initialPrivateState: { attestations: [], holderSecret: new Uint8Array(32) },
    args: [
      attestorKeys.map((key) => key.pk),
      CONTROL_POLICY,
      READING_POLICY,
      THRESHOLD,
      opensAt,
      deadline,
      payoutEnd,
      self,
      3_600n,
      300n,
    ],
  } as never);
  const deployTx = deployed.deployTxData;
  if (!('public' in deployTx)) {
    throw new Error('expected a ledger-9 deploy');
  }
  // shortcut: the `as never` deploy options erase the contract's types; type them if this outlives the spike.
  const address = (deployTx.public as { contractAddress: string }).contractAddress;
  config.ttlSeconds = Number(process.env.TX_TTL_SECONDS ?? 120);
  console.log(`  contract ${address}`);
  const ledger = async () => {
    const state = await providers.publicDataProvider.queryContractState(address);
    if (!state) {
      throw new Error(`no contract state at ${address}`);
    }
    return bounty.ledger(state.data);
  };
  // biome-ignore lint/suspicious/noExplicitAny: callTx is typed by the generated contract.
  const call = async (as: PrivateState, circuit: Circuit, ...args: any[]) => {
    await providers.privateStateProvider.set(PRIVATE_STATE_ID, as);
    const started = Date.now();
    // biome-ignore lint/suspicious/noExplicitAny: see above.
    const tx = await (deployed.callTx as any)[circuit](...args);
    console.log(
      `  ${circuit}: block ${tx.public.blockHeight}, ${((Date.now() - started) / 1000).toFixed(1)} s`,
    );
  };

  step(`funding the pot with ${POT} NIGHT`);
  const beforeFund = await nightBalance();
  // Random bytes the contract writes in `fund`'s fallible phase, to clear node 2.1.0's fee wall.
  await call(
    { attestations: [], holderSecret: new Uint8Array(32) },
    'fund',
    POT,
    randomBytes(2048),
  );
  console.log(
    `  pot ${(await ledger()).pot}, wallet NIGHT ${beforeFund} → ${await nightBalance()}`,
  );

  // Both Controllers' Start readings are observed before the Bounty opens; Registration
  // itself may come later, within the freshness window.
  const controllers = [AGENT_A, AGENT_B].map((agentId) => {
    const secret = randomBytes(32);
    const t = opensAt - 20n;
    return {
      agentId,
      secret,
      control: sign(claimFor(CONTROL_POLICY, agentId, null, t, secret)),
      start: sign(claimFor(READING_POLICY, agentId, 5_000n, t + 2n, secret)),
    };
  });
  for (const c of controllers) {
    step(`registering ${c.agentId}`);
    const as = (attestations: Attestation[]) => ({ attestations, holderSecret: c.secret });
    await call(as([c.control]), 'verifyAttestation');
    await call(as([c.start]), 'verifyAttestation');
    await call(
      as([c.control, c.start]),
      'register',
      bounty.pureCircuits.computeId(c.control.claim, c.control.commitRand),
      bounty.pureCircuits.computeId(c.start.claim, c.start.commitRand),
      self,
    );
  }

  await waitUntil(opensAt, 'the Bounty to open');
  for (const c of controllers) {
    step(`qualifying ${c.agentId} with a Reading of 15,000 XP`);
    const reading = sign(claimFor(READING_POLICY, c.agentId, 15_000n, now() - 5n, c.secret));
    const as = (attestations: Attestation[]) => ({ attestations, holderSecret: c.secret });
    await call(as([reading]), 'verifyAttestation');
    await call(
      as([reading]),
      'qualify',
      bounty.pureCircuits.computeId(reading.claim, reading.commitRand),
    );
  }
  console.log(`  qualifiers ${(await ledger()).qualifiers}`);

  await waitUntil(deadline, 'the deadline');
  const [alice] = controllers;
  if (alice === undefined) {
    throw new Error('no Controllers');
  }
  const share = POT / 2n;
  step(`Payout of ${share} NIGHT to ${alice.agentId}'s address, naming no agent`);
  const beforePayout = await nightBalance();
  await call({ attestations: [], holderSecret: alice.secret }, 'payout', self, share);
  await walletContext.wallet.waitForSyncedState();
  console.log(`  wallet NIGHT ${beforePayout} → ${await nightBalance()}`);

  await waitUntil(payoutEnd, 'the end of the Payout period');
  step(`Refund of what's left to the Sponsor`);
  const beforeRefund = await nightBalance();
  await call({ attestations: [], holderSecret: new Uint8Array(32) }, 'refund');
  await walletContext.wallet.waitForSyncedState();
  const after = await ledger();
  console.log(`  paidOut ${after.paidOut}, refunded ${after.refunded}`);
  console.log(`  wallet NIGHT ${beforeRefund} → ${await nightBalance()}`);

  await walletContext.wallet.stop();
  console.log('\n✓ Bounty ran on the devnet');
};

// Sockets keep the process alive; exit explicitly, as main.ts does.
await main();
process.exit(0);
