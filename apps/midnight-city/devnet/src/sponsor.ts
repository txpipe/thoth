// The Sponsor's side of a Bounty on the devnet, with the genesis wallet: deploy one pinned to
// the running attestors' keys and fund it, or take the Refund. One JSON object on stdout.
//   npm run -s sponsor -- deploy --skill mining --threshold 50 --opens-in 480 \
//     --open-for 1200 --payout-for 300 --pot 1000 --attestor http://127.0.0.1:7001 …
//   npm run -s sponsor -- refund <bountyAddress>
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { jubjubSchnorrVerifyingKey, sampleJubjubSchnorrSk } from '@midnight-ntwrk/compact-runtime';
import { zkFetchPolicyHashOf } from '@thoth/zk-tls';
import { deployBounty, joinBounty, NO_CLAIMS, userAddressOf } from './bounty-client.js';
import { CONTROL_POLICY, readingPolicy, SKILLS } from './city.js';
import { buildWallet, GENESIS_SEED, LOCAL_ENDPOINTS } from './wallet.js';
import { decode } from './wire.js';

const stateDir = join(import.meta.dirname, '../.state/sponsor');
const json = (value: unknown): string =>
  JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? v.toString() : v));

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    skill: { type: 'string', default: 'mining' },
    threshold: { type: 'string', default: '50' },
    'opens-in': { type: 'string', default: '480' },
    'open-for': { type: 'string', default: '1200' },
    'payout-for': { type: 'string', default: '300' },
    pot: { type: 'string', default: '1000' },
    attestor: { type: 'string', multiple: true, default: [] },
  },
});
const [command, address] = positionals;
const wallet = await buildWallet(LOCAL_ENDPOINTS, GENESIS_SEED);

if (command === 'deploy') {
  if (!(SKILLS as readonly string[]).includes(values.skill)) {
    throw new Error(`unknown skill ${values.skill}`);
  }
  if (values.attestor.length !== 2) {
    throw new Error('pass the two attestors: --attestor <url> --attestor <url>');
  }
  const pinned = await Promise.all(
    values.attestor.map(
      async (url) =>
        (decode(await (await fetch(`${url}/descriptor`)).text()) as { publicKey: never }).publicKey,
    ),
  );
  const now = BigInt(Math.floor(Date.now() / 1000));
  const opensAt = now + BigInt(values['opens-in']);
  const deadline = opensAt + BigInt(values['open-for']);
  const bounty = await deployBounty(
    wallet,
    {
      // Registry slot 2 holds a key nobody uses: the Bounty takes 2-of-3.
      keys: [...pinned, jubjubSchnorrVerifyingKey(sampleJubjubSchnorrSk())],
      controlPolicy: zkFetchPolicyHashOf(CONTROL_POLICY),
      readingPolicy: zkFetchPolicyHashOf(readingPolicy(values.skill)),
      threshold: BigInt(values.threshold),
      opensAt,
      deadline,
      payoutEnd: deadline + BigInt(values['payout-for']),
      sponsor: userAddressOf(wallet),
      freshnessWindow: 3_600n,
      maxWindow: 300n,
    },
    { stateDir },
  );
  // Random bytes `fund` writes in its fallible phase, to clear node 2.1.0's fee wall.
  await bounty.call(NO_CLAIMS, 'fund', BigInt(values.pot), randomBytes(2048));
  const ledger = await bounty.ledger();
  process.stdout.write(
    `${json({ address: bounty.address, skill: values.skill, threshold: ledger.threshold, pot: ledger.pot, opensAt: new Date(Number(opensAt) * 1000).toISOString(), deadline: new Date(Number(deadline) * 1000).toISOString() })}\n`,
  );
} else if (command === 'refund' && address !== undefined) {
  const bounty = await joinBounty(wallet, address, { stateDir });
  const { blockHeight } = await bounty.call(NO_CLAIMS, 'refund');
  const ledger = await bounty.ledger();
  process.stdout.write(
    `${json({ refunded: ledger.refunded, paidOut: ledger.paidOut, blockHeight })}\n`,
  );
} else {
  throw new Error('usage: sponsor deploy [options] | sponsor refund <bountyAddress>');
}
await wallet.wallet.stop();
process.exit(0);
