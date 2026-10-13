// Hermes's wallet CLI (#128): `init`, `address`, `balance`, `prepare`. Each prints one JSON object on
// stdout; progress goes to stderr. The seed is never printed, and no command changes the cap.
import { Token } from '@midnightntwrk/wallet-sdk';
import { addressOf, HOME, initSeed, loadConfig, readSeed } from './hermes.js';
import { buildWallet, LOCAL_ENDPOINTS, startWallet, waitForSync } from './wallet.js';

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
    case 'prepare': {
      // Waits for NIGHT, registers it for DUST and waits for DUST: ready to pay fees.
      const context = await buildWallet(LOCAL_ENDPOINTS, readSeed());
      const state = await waitForSync(context.wallet);
      await context.wallet.stop();
      return {
        night: state.unshielded.balances[Token.night] ?? 0n,
        dust: state.dust.balance(new Date()),
      };
    }
    default:
      throw new Error('usage: hermes <init | address | balance | prepare>');
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
