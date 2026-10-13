// Check Hermes's wallet on the devnet (#128): the genesis wallet deploys a Bounty, then Hermes,
// with its own seed and its operator's cap, pays into it twice: once under the cap, which
// must land, and once over it, which its wallet must refuse before submitting.
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { jubjubSchnorrVerifyingKey, sampleJubjubSchnorrSk } from '@midnight-ntwrk/compact-runtime';
import { deployBounty, joinBounty, NO_CLAIMS, userAddressOf } from './bounty-client.js';
import { HOME, loadConfig, readSeed } from './hermes.js';
import { buildWallet, GENESIS_SEED, LOCAL_ENDPOINTS } from './wallet.js';

const report = (line: Record<string, unknown>): void =>
  console.log(JSON.stringify(line, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));

const { capNight } = loadConfig();
const sponsor = await buildWallet(LOCAL_ENDPOINTS, GENESIS_SEED);
const now = BigInt(Math.floor(Date.now() / 1000));
const keys = [0, 1, 2].map(() => jubjubSchnorrVerifyingKey(sampleJubjubSchnorrSk()));
const deployed = await deployBounty(
  sponsor,
  {
    keys,
    controlPolicy: new Uint8Array(32).fill(0xc0),
    readingPolicy: new Uint8Array(32).fill(0xe0),
    threshold: 10_000n,
    opensAt: now + 3_600n,
    deadline: now + 7_200n,
    payoutEnd: now + 10_800n,
    sponsor: userAddressOf(sponsor),
    freshnessWindow: 3_600n,
    maxWindow: 300n,
  },
  { stateDir: join(import.meta.dirname, '../.state/sponsor') },
);
report({ step: 'deployed', address: deployed.address });
await sponsor.wallet.stop();

const hermes = await buildWallet(LOCAL_ENDPOINTS, readSeed());
const bounty = await joinBounty(hermes, deployed.address, {
  stateDir: join(HOME, 'state'),
  capNight,
});
const under = capNight / 2n;
const { blockHeight } = await bounty.call(NO_CLAIMS, 'fund', under, randomBytes(2048));
report({ step: 'under the cap', spent: under, capNight, blockHeight });
try {
  await bounty.call(NO_CLAIMS, 'fund', capNight + 1n, randomBytes(2048));
  report({ step: 'over the cap', refused: false });
  process.exit(1);
} catch (error) {
  report({
    step: 'over the cap',
    refused: true,
    reason: error instanceof Error ? error.message : String(error),
  });
}
report({ step: 'pot', pot: (await bounty.ledger()).pot });
await hermes.wallet.stop();
process.exit(0);
