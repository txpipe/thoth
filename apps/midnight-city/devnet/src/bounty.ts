// Run a Bounty (#122) on the local ledger-9 devnet with real tNIGHT: deploy it,
// fund the pot, register and qualify two agents, pay one Qualifier its Share,
// and refund the rest to the Sponsor after the Payout period. The genesis wallet
// plays the Sponsor and both Controllers, each Controller with a fresh secret.
//
// Claims are signed by three test attestor keys pinned at deploy, as in the
// Bounty's simulator tests: this run checks the contract on a chain (proofs,
// block time, tNIGHT moving), not zkFetch, which recorded.test.ts covers.
// Its windows follow the wall clock, because the chain checks them against
// block time.
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CompactTypeField,
  CompactTypeVector,
  type JubjubSchnorrSignature,
  jubjubSchnorrSign,
  jubjubSchnorrVerifyingKey,
  sampleJubjubSchnorrSk,
} from '@midnight-ntwrk/compact-runtime';
import { Token } from '@midnightntwrk/wallet-sdk';
import { claimToMessage } from '@thoth/core/claim';
import { parseDisclosedValue } from '@thoth/zk-tls';
import * as Rx from 'rxjs';
import {
  type Attestation,
  type BountyClient,
  type Circuit,
  type Claim,
  deployBounty,
  NO_CLAIMS,
  type PrivateState,
  userAddressOf,
} from './bounty-client.js';
import { buildWallet, GENESIS_SEED, LOCAL_ENDPOINTS } from './wallet.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const CONTROL_POLICY = new Uint8Array(32).fill(0xc0);
const READING_POLICY = new Uint8Array(32).fill(0xe0);
const THRESHOLD = 10_000n;
const POT = 1_001n;
const AGENT_A = 'user-agent-lhb10ef8yjy1wfc';
const AGENT_B = 'user-agent-dc4ccc6f-53ce-4e17-921c-8f5848590269';

const step = (message: string): void => console.log(`\n▸ ${message}`);
const now = (): bigint => BigInt(Math.floor(Date.now() / 1000));
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Sleep until block time can be past `t` (Unix seconds), with a margin for block lag. */
const waitUntil = async (t: bigint, label: string): Promise<void> => {
  const ms = Number(t - now() + 10n) * 1000;
  if (ms > 0) {
    console.log(`  waiting ${Math.ceil(ms / 1000)} s for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
};

// Three test attestors; 2-of-3, the third never signs.
const attestorKeys = [0, 1, 2].map(() => {
  const sk = sampleJubjubSchnorrSk();
  return { sk, pk: jubjubSchnorrVerifyingKey(sk) };
});
const UNSIGNED: JubjubSchnorrSignature = { announcement: { x: 0n, y: 1n }, response: 0n };

const sign = (claim: Claim): Attestation => {
  const message = claimToMessage(claim);
  const type = new CompactTypeVector(message.length, CompactTypeField);
  return {
    claim,
    signatures: attestorKeys.map((key, i) =>
      i < 2 ? jubjubSchnorrSign(type, [...message], key.sk) : UNSIGNED,
    ),
    commitRand: randomBytes(32),
  };
};

/** The agent ID after `user-agent-` as the five `bytes8` slots the policies read. */
const agentSlots = (agentId: string): bigint[] => {
  const id = agentId.replace(/^user-agent-/, '');
  return [0, 1, 2, 3, 4].map(
    (i) => parseDisclosedValue(id.slice(i * 8, i * 8 + 8), 'bytes8') ?? 0n,
  );
};

/** Run `circuit` and log its block and time. */
const call = async (
  bounty: BountyClient,
  as: PrivateState,
  circuit: Circuit,
  ...args: unknown[]
) => {
  const started = Date.now();
  const { blockHeight } = await bounty.call(as, circuit, ...args);
  console.log(
    `  ${circuit}: block ${blockHeight}, ${((Date.now() - started) / 1000).toFixed(1)} s`,
  );
};

const main = async (): Promise<void> => {
  step('building the wallet (Sponsor and both Controllers)');
  const walletContext = await buildWallet(LOCAL_ENDPOINTS, GENESIS_SEED);
  const self = userAddressOf(walletContext);
  const nightBalance = async (): Promise<bigint> =>
    (await Rx.firstValueFrom(walletContext.wallet.state())).unshielded.balances[Token.night] ?? 0n;
  console.log(`  address ${hex(self.bytes)}, ${await nightBalance()} NIGHT`);

  const opensAt = now() + 30n;
  const deadline = opensAt + 600n;
  const payoutEnd = deadline + 120n;
  step('deploying the Bounty: opens +30 s, deadline +10.5 min, Payout period ends +12.5 min');
  const bounty = await deployBounty(
    walletContext,
    {
      keys: attestorKeys.map((key) => key.pk),
      controlPolicy: CONTROL_POLICY,
      readingPolicy: READING_POLICY,
      threshold: THRESHOLD,
      opensAt,
      deadline,
      payoutEnd,
      sponsor: self,
      freshnessWindow: 3_600n,
      maxWindow: 300n,
    },
    { stateDir: path.join(here, '../.state') },
  );
  console.log(`  contract ${bounty.address}`);

  const claimFor = (
    policy: Uint8Array,
    agentId: string,
    xp: bigint | null,
    at: bigint,
    secret: Uint8Array,
  ): Claim => ({
    version: 1n,
    appId: new Uint8Array(32).fill(0xa1),
    policyHash: policy,
    windowStart: at,
    windowEnd: at + 1n,
    subjectHash: randomBytes(32),
    holder: bounty.pure.holderCommitment(secret),
    present: [xp !== null, true, true, true, true, true],
    values: [xp ?? 0n, ...agentSlots(agentId)],
  });

  step(`funding the pot with ${POT} NIGHT`);
  const beforeFund = await nightBalance();
  // Random bytes the contract writes in `fund`'s fallible phase, to clear node 2.1.0's fee wall.
  await call(bounty, NO_CLAIMS, 'fund', POT, randomBytes(2048));
  console.log(
    `  pot ${(await bounty.ledger()).pot}, wallet NIGHT ${beforeFund} → ${await nightBalance()}`,
  );

  // Both Controllers' Start readings are observed before the Bounty opens; Registration
  // itself may come later, within the freshness window.
  const controllers = [AGENT_A, AGENT_B].map((agentId) => {
    const secret = randomBytes(32);
    const t = opensAt - 20n;
    return {
      agentId,
      secret,
      control: sign(claimFor(CONTROL_POLICY, agentId, null, t, secret)),
      start: sign(claimFor(READING_POLICY, agentId, 5_000n, t + 2n, secret)),
    };
  });
  for (const c of controllers) {
    step(`registering ${c.agentId}`);
    const as = (attestations: Attestation[]) => ({ attestations, holderSecret: c.secret });
    await call(bounty, as([c.control]), 'verifyAttestation');
    await call(bounty, as([c.start]), 'verifyAttestation');
    await call(
      bounty,
      as([c.control, c.start]),
      'register',
      bounty.pure.computeId(c.control.claim, c.control.commitRand),
      bounty.pure.computeId(c.start.claim, c.start.commitRand),
      self,
    );
  }

  await waitUntil(opensAt, 'the Bounty to open');
  for (const c of controllers) {
    step(`qualifying ${c.agentId} with a Reading of 15,000 XP`);
    const reading = sign(claimFor(READING_POLICY, c.agentId, 15_000n, now() - 5n, c.secret));
    const as = (attestations: Attestation[]) => ({ attestations, holderSecret: c.secret });
    await call(bounty, as([reading]), 'verifyAttestation');
    await call(
      bounty,
      as([reading]),
      'qualify',
      bounty.pure.computeId(reading.claim, reading.commitRand),
    );
  }
  console.log(`  qualifiers ${(await bounty.ledger()).qualifiers}`);

  await waitUntil(deadline, 'the deadline');
  const [alice] = controllers;
  if (alice === undefined) {
    throw new Error('no Controllers');
  }
  const share = POT / 2n;
  step(`Payout of ${share} NIGHT to ${alice.agentId}'s address, naming no agent`);
  const beforePayout = await nightBalance();
  await call(bounty, { attestations: [], holderSecret: alice.secret }, 'payout', self, share);
  await walletContext.wallet.waitForSyncedState();
  console.log(`  wallet NIGHT ${beforePayout} → ${await nightBalance()}`);

  await waitUntil(payoutEnd, 'the end of the Payout period');
  step(`Refund of what's left to the Sponsor`);
  const beforeRefund = await nightBalance();
  await call(bounty, NO_CLAIMS, 'refund');
  await walletContext.wallet.waitForSyncedState();
  const after = await bounty.ledger();
  console.log(`  paidOut ${after.paidOut}, refunded ${after.refunded}`);
  console.log(`  wallet NIGHT ${beforeRefund} → ${await nightBalance()}`);

  await walletContext.wallet.stop();
  console.log('\n✓ Bounty ran on the devnet');
};

// Sockets keep the process alive; exit explicitly, as main.ts does.
await main();
process.exit(0);
