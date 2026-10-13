// The map's verdict cheats (#117), on the devnet: another Controller's agent, a mismatched
// holder, gain before the Start reading, a late reading and a second Payout must each be
// rejected. Claims are signed by test attestor keys, as in bounty.ts. A failing assert can't
// be proved, so each cheat is refused while its transaction is built; nothing invalid reaches
// the node. The honest path runs alongside: Alice qualifies and takes her Share.
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';
import { claimToMessage } from '@thoth/core/claim';
import {
  type Attestation,
  type BountyClient,
  type Claim,
  deployBounty,
  NO_CLAIMS,
  userAddressOf,
} from './bounty-client.js';
import { agentSlots } from './city.js';
import { buildWallet, GENESIS_SEED, LOCAL_ENDPOINTS } from './wallet.js';

const CONTROL_POLICY = new Uint8Array(32).fill(0xc0);
const READING_POLICY = new Uint8Array(32).fill(0xe0);
const AGENT_A = 'user-agent-lhb10ef8yjy1wfc';
const AGENT_B = 'user-agent-dc4ccc6f-53ce-4e17-921c-8f5848590269';

const now = (): bigint => BigInt(Math.floor(Date.now() / 1000));
const report = (line: Record<string, unknown>): void =>
  console.log(JSON.stringify(line, (_, v) => (typeof v === 'bigint' ? v.toString() : v)));
const waitUntil = async (t: bigint): Promise<void> => {
  const ms = Number(t - now() + 10n) * 1000;
  if (ms > 0) {
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
};

const keys = [0, 1, 2].map(() => {
  const sk = sampleJubjubSchnorrSk();
  return { sk, pk: jubjubSchnorrVerifyingKey(sk) };
});
const UNSIGNED: JubjubSchnorrSignature = { announcement: { x: 0n, y: 1n }, response: 0n };

const wallet = await buildWallet(LOCAL_ENDPOINTS, GENESIS_SEED);
const self = userAddressOf(wallet);
const opensAt = now() + 240n;
const deadline = opensAt + 360n;
const bounty: BountyClient = await deployBounty(
  wallet,
  {
    keys: keys.map((key) => key.pk),
    controlPolicy: CONTROL_POLICY,
    readingPolicy: READING_POLICY,
    threshold: 10_000n,
    opensAt,
    deadline,
    payoutEnd: deadline + 600n,
    sponsor: self,
    freshnessWindow: 3_600n,
    maxWindow: 300n,
  },
  { stateDir: join(import.meta.dirname, '../.state/cheats') },
);
report({ step: 'deployed', address: bounty.address });
await bounty.call(NO_CLAIMS, 'fund', 1_000n, randomBytes(2048));

/** A signed claim for `secret`'s holder: a Reading when `xp` is set, else a Control claim. */
const claim = (
  secret: Uint8Array,
  agentId: string,
  xp: bigint | null,
  at: bigint,
  policy = xp === null ? CONTROL_POLICY : READING_POLICY,
): Attestation => {
  const c: Claim = {
    version: 1n,
    appId: new Uint8Array(32).fill(0xa1),
    policyHash: policy,
    windowStart: at,
    windowEnd: at + 1n,
    subjectHash: randomBytes(32),
    holder: bounty.pure.holderCommitment(secret),
    present: [xp !== null, true, true, true, true, true],
    values: [xp ?? 0n, ...agentSlots(agentId)],
  };
  const message = claimToMessage(c);
  const type = new CompactTypeVector(message.length, CompactTypeField);
  return {
    claim: c,
    signatures: keys.map((key, i) =>
      i < 2 ? jubjubSchnorrSign(type, [...message], key.sk) : UNSIGNED,
    ),
    commitRand: randomBytes(32),
  };
};
const as = (secret: Uint8Array, attestations: Attestation[]) => ({
  attestations,
  holderSecret: secret,
});
const id = (a: Attestation) => bounty.pure.computeId(a.claim, a.commitRand);
const vault = (secret: Uint8Array, a: Attestation) =>
  bounty.call(as(secret, [a]), 'verifyAttestation');

/** Run a cheat; it must fail with `expected`. */
const cheat = async (name: string, expected: string, attempt: () => Promise<unknown>) => {
  try {
    await attempt();
    report({ cheat: name, rejected: false });
    process.exitCode = 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    report({ cheat: name, rejected: message.includes(expected), reason: expected });
    if (!message.includes(expected)) {
      report({ cheat: name, unexpected: message.slice(0, 300) });
      process.exitCode = 1;
    }
  }
};

const alice = randomBytes(32);
const bob = randomBytes(32);
const mallory = randomBytes(32);
// Every pre-opening claim is observed now: in the past, so it can be vaulted, and before
// `opensAt`, so it counts as a Start reading. Vaulting and registering can come later.
const beforeOpen = now() - 5n;
if (beforeOpen + 10n > opensAt) {
  throw new Error('deploy took too long: no time left before the Bounty opens');
}
const register = async (secret: Uint8Array, agentId: string) => {
  const control = claim(secret, agentId, null, beforeOpen);
  const start = claim(secret, agentId, 5_000n, beforeOpen + 1n);
  await vault(secret, control);
  await vault(secret, start);
  await bounty.call(as(secret, [control, start]), 'register', id(control), id(start), self);
};
await register(alice, AGENT_A);
await register(bob, AGENT_B);
report({ step: 'registered', agents: [AGENT_A, AGENT_B] });

// Mallory reads agent A's public progression and presents it as control of A.
const fakeControl = claim(mallory, AGENT_A, 5_000n, beforeOpen + 2n, READING_POLICY);
const malloryStart = claim(mallory, AGENT_A, 5_000n, beforeOpen + 3n);
await vault(mallory, fakeControl);
await vault(mallory, malloryStart);
await cheat("another Controller's agent", 'Not a Control claim', () =>
  bounty.call(
    as(mallory, [fakeControl, malloryStart]),
    'register',
    id(fakeControl),
    id(malloryStart),
    self,
  ),
);

await waitUntil(opensAt);
const early = claim(alice, AGENT_A, 15_000n, beforeOpen + 4n);
await vault(alice, early);
await cheat('gain before the Start reading', 'Reading before the Bounty opens', () =>
  bounty.call(as(alice, [early]), 'qualify', id(early)),
);

const mallorysReading = claim(mallory, AGENT_A, 15_000n, now() - 5n);
await vault(mallory, mallorysReading);
await cheat('a mismatched holder', 'Holder mismatch', () =>
  bounty.call(as(mallory, [mallorysReading]), 'qualify', id(mallorysReading)),
);

const honest = claim(alice, AGENT_A, 15_000n, now() - 5n);
await vault(alice, honest);
await bounty.call(as(alice, [honest]), 'qualify', id(honest));
report({ step: 'Alice qualified', qualifiers: (await bounty.ledger()).qualifiers });

await waitUntil(deadline);
const late = claim(bob, AGENT_B, 15_000n, now() - 5n);
await vault(bob, late);
await cheat('a late reading', 'Late reading', () =>
  bounty.call(as(bob, [late]), 'qualify', id(late)),
);

await bounty.call(as(alice, []), 'payout', self, 1_000n);
report({ step: 'Alice paid', paidOut: (await bounty.ledger()).paidOut });
await cheat('a second Payout', 'Already paid', () =>
  bounty.call(as(alice, []), 'payout', self, 1_000n),
);

await wallet.wallet.stop();
process.exit(process.exitCode ?? 0);
