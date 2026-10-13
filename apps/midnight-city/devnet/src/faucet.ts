// Devnet faucet: the genesis wallet sends tNIGHT to an unshielded address, standing in for
// the human who funds Hermes. Usage: npm run faucet -- <address hex> <amount>
import { Token } from '@midnightntwrk/wallet-sdk';
import { UnshieldedAddress } from '@midnightntwrk/wallet-sdk/address-format';
import { buildWallet, GENESIS_SEED, LOCAL_ENDPOINTS } from './wallet.js';

const [to, amount] = process.argv.slice(2);
if (
  to === undefined ||
  !/^[0-9a-f]{64}$/.test(to) ||
  amount === undefined ||
  !/^\d+$/.test(amount)
) {
  throw new Error('usage: npm run faucet -- <unshielded address hex> <amount>');
}
const context = await buildWallet(LOCAL_ENDPOINTS, GENESIS_SEED);
const recipe = await context.wallet.transferTransaction(
  [
    {
      type: 'unshielded',
      outputs: [
        {
          type: Token.night,
          amount: BigInt(amount),
          receiverAddress: new UnshieldedAddress(Buffer.from(to, 'hex')),
        },
      ],
    },
  ],
  { ttl: new Date(Date.now() + 120_000) },
);
const signed = await context.wallet.signRecipe(recipe, context.unshieldedKeystore.signDataAsync);
const txId = await context.wallet.submitTransaction(await context.wallet.finalizeRecipe(signed));
console.log(JSON.stringify({ sent: amount, to, txId: String(txId) }));
await context.wallet.stop();
process.exit(0);
