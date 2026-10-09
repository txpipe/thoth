// The deployer's wallet: the minimum of midnight-reference-app's
// `packages/wallet` (`buildWallet`, `waitForSync`, `registerForDustGeneration`)
// ported to wallet SDK 5, plus the bridge midnight-js 5 balances and submits
// through. SDK 5 starts the three wallets from seeds, not ledger key objects,
// and balancing no longer takes secret keys; the shapes follow the wallet repo's
// docs snippets and midnight-js testkit's `MidnightWalletProvider` at the pinned
// release candidates.
import {
  type FinalizedTransaction,
  ZswapSecretKeys,
} from '@midnight-ntwrk/midnight-js-protocol/ledger';
import {
  createMidnightProviderFromHandlers,
  createWalletProvider,
  type MidnightProvider,
  type WalletProvider,
} from '@midnight-ntwrk/midnight-js-types';
import {
  createKeystore,
  DustWallet,
  type FacadeState,
  type FinalizedTx,
  InMemoryTransactionHistoryStorage,
  mergeWalletEntries,
  ProtocolVersion,
  ShieldedWallet,
  Token,
  type UnshieldedKeystore,
  PublicKey as UnshieldedPublicKey,
  UnshieldedWallet,
  WalletEntrySchema,
  WalletFacade,
  WalletSeeds,
  WalletTransaction,
} from '@midnightntwrk/wallet-sdk';
import { Either } from 'effect';
import * as Rx from 'rxjs';

/** Where the devnet's services listen. */
export interface Endpoints {
  readonly node: string;
  readonly indexer: string;
  readonly indexerWS: string;
  readonly proofServer: string;
}

/** A started wallet and the key material that signs for it. */
export interface WalletContext {
  readonly wallet: WalletFacade;
  readonly seeds: WalletSeeds;
  readonly unshieldedKeystore: UnshieldedKeystore;
  /** Where each ledger version begins on this chain. */
  readonly forks: ProtocolVersion.ForkSchedule;
}

const log = (message: string): void => console.log(`  · ${message}`);

/**
 * Build, start and sync a wallet, waiting for funds and dust.
 *
 * @param endpoints - the devnet's services.
 * @param seed - the hex master seed; a dev-preset genesis seed arrives funded.
 * @returns the synced wallet, ready to pay fees.
 */
export const buildWallet = async (endpoints: Endpoints, seed: string): Promise<WalletContext> => {
  const configuration = WalletFacade.resolveConfiguration({
    networkId: 'undeployed',
    costParameters: { feeBlocksMargin: 5 },
    relayURL: new URL(endpoints.node.replace(/^http/, 'ws')),
    // A devnet born on ledger 9 has no v8 history, so one v9 prover is enough.
    provers: { v9: { kind: 'server', url: new URL(endpoints.proofServer) } },
    indexerClientConnection: {
      indexerHttpUrl: endpoints.indexer,
      indexerWsUrl: endpoints.indexerWS,
    },
    txHistoryStorage: new InMemoryTransactionHistoryStorage(WalletEntrySchema, mergeWalletEntries),
  });
  const seeds = WalletSeeds.fromMasterSeed(Buffer.from(seed, 'hex'));
  const unshieldedKeystore = createKeystore(
    { kind: 'schnorr', secret: seeds.unshielded },
    configuration.networkId,
  );
  const wallet = await WalletFacade.init({
    configuration,
    shielded: (config) => ShieldedWallet(config).startWithSeed(seeds.shielded),
    unshielded: (config) =>
      UnshieldedWallet(config).startWithPublicKey(
        UnshieldedPublicKey.fromKeyStore(unshieldedKeystore),
      ),
    dust: (config) => DustWallet(config).startWithSeed(seeds.dust),
  });
  await wallet.start(seeds);

  log('syncing wallet');
  const synced = await waitForSync(wallet);
  if ((synced.unshielded.balances[Token.night] ?? 0n) === 0n) {
    log('waiting for NIGHT');
    await waitFor(wallet, (s) => (s.unshielded.balances[Token.night] ?? 0n) > 0n);
  }
  const context = { wallet, seeds, unshieldedKeystore, forks: configuration.forks };
  await registerForDustGeneration(context);
  return context;
};

/**
 * Wait until all three wallets have synced.
 *
 * @param wallet - the started facade.
 * @returns the synced state.
 */
export const waitForSync = (wallet: WalletFacade): Promise<FacadeState> =>
  wallet.waitForSyncedState();

const waitFor = (wallet: WalletFacade, ready: (s: FacadeState) => boolean): Promise<FacadeState> =>
  Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.throttleTime(2_000, undefined, { leading: true, trailing: true }),
      Rx.filter((s) => s.isSynced && ready(s)),
    ),
  );

const hasDust = (s: FacadeState): boolean => s.dust.balance(new Date()) > 0n;

/**
 * Designate the wallet's unregistered NIGHT UTXOs for dust generation, the fee
 * token, and wait for dust. A no-op when the wallet already holds dust.
 *
 * @param context - the synced wallet.
 */
export const registerForDustGeneration = async ({
  wallet,
  unshieldedKeystore,
}: WalletContext): Promise<void> => {
  const state = await waitForSync(wallet);
  if (hasDust(state)) {
    log(`dust available: ${state.dust.balance(new Date())}`);
    return;
  }
  const nightUtxos = state.unshielded.availableCoins.filter(
    (coin) => !coin.meta.registeredForDustGeneration,
  );
  if (nightUtxos.length > 0) {
    log(`registering ${nightUtxos.length} NIGHT UTXO(s) for dust generation`);
    // A first registration pays its own fee from the dust its NIGHT has
    // generated so far, so wait for that much before registering.
    const { fee } = await wallet.estimateRegistration(nightUtxos);
    await wallet.waitForGeneratedDust(nightUtxos, fee);
    const recipe = await wallet.registerNightUtxosForDustGeneration(
      nightUtxos,
      unshieldedKeystore.getPublicKey(),
      unshieldedKeystore.signDataAsync,
    );
    await wallet.submitTransaction(await wallet.finalizeRecipe(recipe));
  }
  log('waiting for dust');
  await waitFor(wallet, hasDust);
};

/**
 * The wallet as midnight-js 5's wallet and midnight providers, for the v9 era
 * only. midnight-js hands over live ledger-v9 objects; the facade wants them
 * sealed with the protocol version they were authored at, so each seam adopts
 * the transaction at the wallet's active version and unwraps the result within
 * the same epoch.
 *
 * @param context - the synced wallet.
 * @returns one object serving both provider seams.
 */
export const walletProviders = ({
  wallet,
  seeds,
  unshieldedKeystore,
  forks,
}: WalletContext): WalletProvider & MidnightProvider => {
  const zswapKeys = ZswapSecretKeys.fromSeed(seeds.shielded);
  const active = (): Promise<ProtocolVersion.ProtocolVersion> =>
    Rx.firstValueFrom(wallet.state()).then((s) => s.activeProtocolVersion);
  const unwrap = async (handle: FinalizedTx): Promise<FinalizedTransaction> => {
    const epoch = ProtocolVersion.epochOf(await active(), forks.v9);
    return Either.getOrThrow(WalletTransaction.unwrapWithin<FinalizedTransaction>(handle, epoch));
  };
  const walletProvider = createWalletProvider({
    getCoinPublicKey: () => zswapKeys.coinPublicKey,
    getEncryptionPublicKey: () => zswapKeys.encryptionPublicKey,
    balanceTx: async (tx, ttl) => {
      const recipe = await wallet.balanceUnboundTransaction(
        WalletTransaction.adopt('Unbound', tx, await active()),
        { ttl: ttl ?? new Date(Date.now() + 30 * 60 * 1000) },
      );
      const signed = await wallet.signRecipe(recipe, unshieldedKeystore.signDataAsync);
      return unwrap(await wallet.finalizeRecipe(signed));
    },
  });
  const midnightProvider = createMidnightProviderFromHandlers({
    currentEra: async (tx) =>
      wallet.submitTransaction(WalletTransaction.adopt('Finalized', tx, await active())),
  });
  // One object for both seams; each method forwards to its own provider so
  // neither depends on how the other binds `this`.
  return {
    supportedEras: walletProvider.supportedEras,
    balanceTx: (tx, ttl) => walletProvider.balanceTx(tx, ttl),
    getCoinPublicKey: () => walletProvider.getCoinPublicKey(),
    getEncryptionPublicKey: () => walletProvider.getEncryptionPublicKey(),
    submitTx: (tx) => midnightProvider.submitTx(tx),
  };
};
