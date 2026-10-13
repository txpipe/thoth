// The Bounty skill's CLI (#131): one JSON object on stdout per command, progress on stderr.
// Usage: bounty <status|register|qualify|payout> <bountyAddress> [agentId] [payoutAddressHex]
import { payout, qualify, register, status } from './skill.js';

const json = (value: unknown): string =>
  JSON.stringify(value, (_, v) => (typeof v === 'bigint' ? v.toString() : v));

const run = async ([command, address, agentId, payoutHex]: string[]): Promise<unknown> => {
  if (address === undefined || !/^[0-9a-f]{64}$/.test(address)) {
    throw new Error('usage: bounty <status|register|qualify|payout> <bountyAddress> …');
  }
  switch (command) {
    case 'status':
      return status(address);
    case 'register':
      if (agentId === undefined) {
        throw new Error('usage: bounty register <bountyAddress> <agentId> [payoutAddressHex]');
      }
      return register(address, agentId, payoutHex);
    case 'qualify':
      return qualify(address);
    case 'payout':
      return payout(address);
    default:
      throw new Error('usage: bounty <status|register|qualify|payout> <bountyAddress> …');
  }
};

try {
  process.stdout.write(`${json(await run(process.argv.slice(2)))}\n`);
  process.exit(0);
} catch (error) {
  process.stdout.write(
    `${json({ error: error instanceof Error ? error.message : String(error) })}\n`,
  );
  process.exit(1);
}
