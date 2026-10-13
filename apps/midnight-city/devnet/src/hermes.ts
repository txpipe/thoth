// Hermes's own devnet wallet (#128): a seed it keeps in a 0600 file and never prints, and a
// spending cap from a config file that no command writes, so Hermes can't raise its own cap.
// Ledger 9, `undeployed` (the local devnet) only. Files live in $MCITY_HOME (~/.midnight-city-bounty).
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createKeystore, WalletSeeds } from '@midnightntwrk/wallet-sdk';

/** Hermes's wallet directory. */
export const HOME = process.env.MCITY_HOME ?? join(homedir(), '.midnight-city-bounty');
const SEED_FILE = join(HOME, 'seed');
const CONFIG_FILE = join(HOME, 'config.json');

/** The operator's limits on Hermes's wallet. */
export interface HermesConfig {
  network: 'undeployed';
  /** The most NIGHT one transaction may take from the wallet. */
  capNight: bigint;
}

/**
 * Read the operator's config. No command writes it.
 *
 * @returns the config.
 * @throws if it's missing, names another network, or has no whole-number cap.
 */
export const loadConfig = (): HermesConfig => {
  if (!existsSync(CONFIG_FILE)) {
    throw new Error(
      `no config at ${CONFIG_FILE}: the operator writes {"network":"undeployed","capNight":"<NIGHT>"}`,
    );
  }
  const raw = JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) as Record<string, unknown>;
  if (raw.network !== 'undeployed') {
    throw new Error(
      `network ${String(raw.network)} refused: this wallet runs on the local devnet only`,
    );
  }
  if (typeof raw.capNight !== 'string' || !/^\d+$/.test(raw.capNight)) {
    throw new Error('capNight must be a whole number of NIGHT, as a string');
  }
  return { network: 'undeployed', capNight: BigInt(raw.capNight) };
};

/**
 * Create Hermes's seed, once, readable by its owner only.
 *
 * @returns whether it was created now.
 */
export const initSeed = (): boolean => {
  mkdirSync(HOME, { recursive: true, mode: 0o700 });
  if (existsSync(SEED_FILE)) {
    return false;
  }
  writeFileSync(SEED_FILE, randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
  return true;
};

/**
 * Hermes's seed.
 *
 * @returns the hex master seed.
 * @throws if there's none yet, or anyone but its owner can read the file.
 */
export const readSeed = (): string => {
  if (!existsSync(SEED_FILE)) {
    throw new Error(`no seed at ${SEED_FILE}: run init first`);
  }
  if ((statSync(SEED_FILE).mode & 0o077) !== 0) {
    throw new Error(`${SEED_FILE} is readable by others: chmod 600 it`);
  }
  return readFileSync(SEED_FILE, 'utf8').trim();
};

/**
 * The unshielded address a seed receives NIGHT at, without starting a wallet.
 *
 * @param seed - the hex master seed.
 * @returns the address as bech32m and as hex.
 */
export const addressOf = (seed: string): { unshielded: string; unshieldedHex: string } => {
  const keystore = createKeystore(
    { kind: 'schnorr', secret: WalletSeeds.fromMasterSeed(Buffer.from(seed, 'hex')).unshielded },
    'undeployed',
  );
  return {
    unshielded: keystore.getBech32Address().asString(),
    unshieldedHex: keystore.getAddress(),
  };
};
