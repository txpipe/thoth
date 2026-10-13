// Deploy Thoth's MockAttestation to the local ledger-9 devnet and record one
// accepted 2-of-3 attestment: build and fund the deployer's wallet, deploy the
// contract sealing two attestor keys (plus an unqueried third) and the policy
// they enforce, call `verifyAttestation` with the collected signatures, and
// read the claims vault back from the indexer.
//
// ARTIFACTS selects the compiled contract: by default this app's own build
// (`npm run compact`, compiler 0.35.0). The repo's 0.34.0 build does not run
// under midnight-js 5; see README "Runtime 0.19 versus 0.20".
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { CompiledContract } from '@midnight-ntwrk/midnight-js-protocol/compact-js';
import type { MidnightProviders } from '@midnight-ntwrk/midnight-js-types';
import { createMidnightProviders } from '@midnight-ntwrk/midnight-js-utils';
import {
  createPrivateState,
  type PrivateState,
} from '../../../../packages/contracts/test/helpers/private-state.js';
import { makeWitnesses } from '../../../../packages/contracts/test/helpers/witnesses.js';
import type * as Mock from '../artifacts/mock_attestation/contract/index.js';
import { collectAttestment } from './attestment.js';
import {
  buildWallet,
  LOCAL_ENDPOINTS as endpoints,
  GENESIS_SEED,
  walletProviders,
} from './wallet.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const artifacts = path.resolve(
  process.env.ARTIFACTS ?? path.join(here, '../artifacts/mock_attestation'),
);

const PRIVATE_STATE_ID = 'mockAttestation';

type Circuit = 'verifyAttestation' | 'openAndRead' | 'openAndReadPresence';

const step = (message: string): void => console.log(`\n▸ ${message}`);

const main = async (): Promise<void> => {
  step(`artifacts: ${artifacts}`);
  const mock = (await import(path.join(artifacts, 'contract/index.js'))) as typeof Mock;

  step('collecting a 2-of-3 attestment');
  const observedAt = Math.floor(Date.now() / 1000) - 30;
  const { registryKeys, policyHashes, submission } = await collectAttestment(
    observedAt,
    mock.pureCircuits.holderCommitment,
  );

  step('building the deployer wallet');
  const walletContext = await buildWallet(endpoints, GENESIS_SEED);
  const wallet = walletProviders(walletContext);

  const zkConfigProvider = new NodeZkConfigProvider<Circuit>(artifacts);
  const providers: MidnightProviders<Circuit, typeof PRIVATE_STATE_ID, PrivateState> =
    createMidnightProviders({
      privateStateProvider: levelPrivateStateProvider<typeof PRIVATE_STATE_ID, PrivateState>({
        midnightDbName: path.join(here, '../.state/midnight-level-db'),
        privateStateStoreName: 'mock-attestation-private-state',
        signingKeyStoreName: 'mock-attestation-signing-keys',
        privateStoragePasswordProvider: () => 'Thoth-devnet-only-Passw0rd!',
        accountId: Buffer.from(wallet.getCoinPublicKey()).toString('hex'),
      }),
      publicDataProvider: indexerPublicDataProvider(endpoints.indexer, endpoints.indexerWS),
      zkConfigProvider,
      proofProvider: httpClientProofProvider(endpoints.proofServer, zkConfigProvider),
      walletProvider: wallet,
      midnightProvider: wallet,
      config: { networkId: 'undeployed', ttlSeconds: 3600 },
    });

  const compiledContract = CompiledContract.make<Mock.Contract<PrivateState>>(
    'MockAttestation',
    mock.Contract<PrivateState>,
  ).pipe(
    CompiledContract.withWitnesses(makeWitnesses(registryKeys, { policyHashes })),
    CompiledContract.withCompiledFileAssets(artifacts),
  );

  step('deploying MockAttestation');
  const deployed = await deployContract(providers, {
    compiledContract,
    privateStateId: PRIVATE_STATE_ID,
    initialPrivateState: createPrivateState(submission.holderSecret),
  });
  const address = deployed.deployTxData.public.contractAddress;
  console.log(`  contract ${address}`);
  console.log(`  deploy tx ${deployed.deployTxData.public.txId}`);

  step('submitting the attestment');
  providers.privateStateProvider.setContractAddress(address);
  await providers.privateStateProvider.set(PRIVATE_STATE_ID, submission);
  const call = await deployed.callTx.verifyAttestation();
  console.log(`  tx ${call.public.txId} in block ${call.public.blockHeight}`);

  step('reading the claims vault back');
  const state = await providers.publicDataProvider.queryContractState(address);
  if (!state) {
    throw new Error(`no contract state at ${address}`);
  }
  const id = mock.pureCircuits.computeId(submission.claim, submission.commitRand);
  const recorded = mock.ledger(state.data).A_claimsVault.member(id);
  console.log(`  claim ${Buffer.from(id).toString('hex')} recorded: ${recorded}`);
  if (!recorded) {
    throw new Error('the attestment was not recorded');
  }
  await walletContext.wallet.stop();
  console.log('\n✓ attestment accepted on-chain');
};

// A rejection exits 1 with its stack; success exits explicitly, since the
// wallet's indexer and node sockets would otherwise keep the process alive.
await main();
process.exit(0);
