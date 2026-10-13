// Hermes's wallet CLI (#128): `init`, `address`, `balance`. Each prints one JSON object on
// stdout; progress goes to stderr. The seed is never printed, and no command changes the cap.
import { Token } from '@midnightntwrk/wallet-sdk';
import { addressOf, HOME, initSeed, loadConfig, readSeed } from './hermes.js';
import { LOCAL_ENDPOINTS, startWallet, waitForSync } from './wallet.js';

const json = (value: unknown): string =>
  JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? v.toString() : v));

const run = async (command: string | undefined): Promise<unknown> => {
  switch (command) {
    case 'init':
      return { created: initSeed(), home: HOME };
    case 'address':
      return addressOf(readSeed());
    case 'balance': {
      const { capNight } = loadConfig();
      const context = await startWallet(LOCAL_ENDPOINTS, readSeed());
      const state = await waitForSync(context.wallet);
      await context.wallet.stop();
      return {
        night: state.unshielded.balances[Token.night] ?? 0n,
        dust: state.dust.balance(new Date()),
        capNight,
      };
    }
    default:
      throw new Error('usage: hermes <init | address | balance>');
  }
};

try {
  process.stdout.write(`${json(await run(process.argv[2]))}\n`);
  process.exit(0);
} catch (error) {
  process.stdout.write(
    `${json({ error: error instanceof Error ? error.message : String(error) })}\n`,
  );
  process.exit(1);
}
