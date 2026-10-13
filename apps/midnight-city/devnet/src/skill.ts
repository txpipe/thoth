// Hermes's Bounty operations (#131): status, register, qualify and payout, given only a
// Bounty address. Plain functions returning plain objects, so a CLI or an MCP server can wrap
// them. Each Bounty's state, its holder secret included, lives in $MCITY_HOME/bounties/ (0600)
// and survives restarts: a lost secret means a lost Share. Nothing here prints the secret or
// the City API token.
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseEnv } from 'node:util';
import { zkFetchPolicyHashOf } from '@thoth/zk-tls';
import { collectClaim, resolveAttestors } from './attest.js';
import {
  type Attestation,
  type BountyClient,
  joinBounty,
  loadBounty,
  readBounty,
  userAddressOf,
} from './bounty-client.js';
import {
  agentSlots,
  CONTROL_POLICY,
  controlRequest,
  currentXp,
  readingPolicy,
  readingRequest,
  SKILLS,
} from './city.js';
import { HOME, loadConfig, readSeed } from './hermes.js';
import { buildWallet, LOCAL_ENDPOINTS, type WalletContext } from './wallet.js';

/** Hermes's Midnight City skill keeps the City API token here. Read in-process only. */
const TOKEN_ENV = join(homedir(), '.hermes', 'skills', 'midnight-city-direct-control', '.env');

/** What Hermes remembers about one Bounty. */
interface BountyState {
  agentId: string;
  skill: string;
  /** Hex holder secret: one per agent per Bounty. Never printed. */
  secret: string;
  /** Hex address the Share is paid to, fixed at Registration. */
  payout: string;
  registered: boolean;
  /** Set by our own Payout: the chain can't say, since a Payout names no agent. */
  paid?: boolean;
}

const stateFile = (address: string): string => join(HOME, 'bounties', `${address}.json`);
const loadState = (address: string): BountyState | undefined =>
  existsSync(stateFile(address))
    ? (JSON.parse(readFileSync(stateFile(address), 'utf8')) as BountyState)
    : undefined;
const saveState = (address: string, state: BountyState): void => {
  mkdirSync(join(HOME, 'bounties'), { recursive: true, mode: 0o700 });
  writeFileSync(stateFile(address), JSON.stringify(state), { mode: 0o600 });
};
const registeredState = (address: string): BountyState => {
  const state = loadState(address);
  if (!state?.registered) {
    throw new Error(`not registered in ${address}: run register first`);
  }
  return state;
};

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const now = (): bigint => BigInt(Math.floor(Date.now() / 1000));
const iso = (seconds: bigint): string => new Date(Number(seconds) * 1000).toISOString();
/** A claim window around now: room for two witnesses to prove, well under maxWindow. */
const liveWindow = (): readonly [bigint, bigint] => [now() - 10n, now() + 90n];

/** The Bounty's skill: the one whose Reading policy hash it sealed. */
const skillOf = (sealed: Uint8Array): string => {
  const skill = SKILLS.find((s) => hex(zkFetchPolicyHashOf(readingPolicy(s))) === hex(sealed));
  if (skill === undefined) {
    throw new Error('this Bounty sealed a Reading policy for no City skill this client knows');
  }
  return skill;
};

/** The ID a claim's five `bytes8` slots spell, for error messages. */
const agentIdOf = (values: readonly bigint[]): string =>
  `user-agent-${values
    .slice(1, 6)
    .map((v) => (v === 0n ? '' : Buffer.from(v.toString(16).padStart(2, '0'), 'hex').toString()))
    .join('')}`;

const sameAgent = (values: readonly bigint[], agentId: string): boolean =>
  agentSlots(agentId).every((slot, i) => values[i + 1] === slot);

const agentKeyOf = async (agentId: string): Promise<Uint8Array> =>
  (await loadBounty()).pureCircuits.agentKey(agentSlots(agentId));

/** Hermes's funded wallet and the Bounty, joined under the operator's cap. */
const connect = async (
  address: string,
): Promise<{ wallet: WalletContext; bounty: BountyClient }> => {
  const { capNight } = loadConfig();
  const wallet = await buildWallet(LOCAL_ENDPOINTS, readSeed());
  const bounty = await joinBounty(wallet, address, { stateDir: join(HOME, 'state'), capNight });
  return { wallet, bounty };
};

/**
 * The Bounty's terms, and where Hermes's agent stands in it.
 *
 * @param address - the Bounty.
 */
export const status = async (address: string) => {
  const ledger = await readBounty(address);
  const skill = skillOf(ledger.readingPolicy);
  const state = loadState(address);
  const mine = state === undefined ? undefined : await agentKeyOf(state.agentId);
  const registration =
    mine !== undefined && ledger.registrations.member(mine)
      ? ledger.registrations.lookup(mine)
      : undefined;
  const xp = state === undefined ? undefined : await currentXp(state.agentId, skill);
  return {
    skill,
    threshold: ledger.threshold,
    opensAt: iso(ledger.opensAt),
    deadline: iso(ledger.deadline),
    payoutEnd: iso(ledger.payoutEnd),
    pot: ledger.pot,
    qualifiers: ledger.qualifiers,
    agent: state?.agentId,
    registered: registration !== undefined,
    qualified: registration?.qualified ?? false,
    paid: state?.paid ?? false,
    startXp: registration?.startXp,
    xp: xp ?? (state === undefined ? undefined : 'agent offline'),
    gain: registration !== undefined && xp !== undefined ? xp - registration.startXp : undefined,
  };
};

/**
 * Register `agentId` in the Bounty: a Control claim that Hermes's token controls it, and a
 * Start reading, both observed before the Bounty opens.
 *
 * @param address - the Bounty.
 * @param agentId - the first agent the token controls.
 * @param payoutHex - where the Share goes; Hermes's own address when omitted. Fixed for good.
 */
export const register = async (address: string, agentId: string, payoutHex?: string) => {
  const { attestors: endpoints } = loadConfig();
  const ledger = await readBounty(address);
  const skill = skillOf(ledger.readingPolicy);
  if (hex(zkFetchPolicyHashOf(CONTROL_POLICY)) !== hex(ledger.controlPolicy)) {
    throw new Error("this Bounty sealed a Control policy this client doesn't produce");
  }
  if ((await currentXp(agentId, skill)) === undefined) {
    throw new Error('agent offline: a Start reading needs it online, so bring it online first');
  }
  const attestors = await resolveAttestors(endpoints, ledger.R_keys);
  const token = parseEnv(readFileSync(TOKEN_ENV, 'utf8')).MCITY_API_TOKEN;
  if (!token) {
    throw new Error(`MCITY_API_TOKEN is not set in ${TOKEN_ENV}`);
  }

  const { wallet, bounty } = await connect(address);
  // Saved before it's first used, so a crash can't lose it.
  const state: BountyState = loadState(address) ?? {
    agentId,
    skill,
    secret: randomBytes(32).toString('hex'),
    payout: payoutHex ?? hex(userAddressOf(wallet).bytes),
    registered: false,
  };
  saveState(address, state);
  // Stamped once the wallet is ready, since waiting for DUST can take minutes.
  const window = liveWindow();
  if (window[1] > ledger.opensAt) {
    await wallet.wallet.stop();
    throw new Error(`too late: the Start reading must be observed before ${iso(ledger.opensAt)}`);
  }
  const secret = Buffer.from(state.secret, 'hex');
  const holder = bounty.pure.holderCommitment(secret);
  const claim = (
    request: Parameters<typeof collectClaim>[0]['request'],
    policy: Parameters<typeof collectClaim>[0]['policy'],
  ) => collectClaim({ request, policy, holder, window, attestors, registryKeys: ledger.R_keys });

  const control = await claim(controlRequest(token), CONTROL_POLICY);
  if (!sameAgent(control.claim.values, agentId)) {
    throw new Error(
      `the first agent this token controls is ${agentIdOf(control.claim.values)}, not ${agentId}: only the first can register`,
    );
  }
  const start = await claim(readingRequest(agentId, skill), readingPolicy(skill));
  const as = (attestations: Attestation[]) => ({ attestations, holderSecret: secret });
  await bounty.call(as([control]), 'verifyAttestation');
  await bounty.call(as([start]), 'verifyAttestation');
  const { blockHeight } = await bounty.call(
    as([control, start]),
    'register',
    bounty.pure.computeId(control.claim, control.commitRand),
    bounty.pure.computeId(start.claim, start.commitRand),
    { bytes: Buffer.from(state.payout, 'hex') },
  );
  saveState(address, { ...state, registered: true });
  await wallet.wallet.stop();
  return { registered: true, agent: agentId, skill, startXp: start.claim.values[0], blockHeight };
};

/**
 * Qualify with a Reading showing the gain reached the threshold. When it hasn't yet, report
 * the progress without paying for any proof.
 *
 * @param address - the Bounty.
 */
export const qualify = async (address: string) => {
  const { attestors: endpoints } = loadConfig();
  const state = registeredState(address);
  const ledger = await readBounty(address);
  const registration = ledger.registrations.lookup(await agentKeyOf(state.agentId));
  if (registration.qualified) {
    return { qualified: true, already: true };
  }
  const xp = await currentXp(state.agentId, state.skill);
  if (xp === undefined) {
    return { qualified: false, reason: 'agent offline: a Reading needs it online' };
  }
  const gain = xp - registration.startXp;
  if (gain < ledger.threshold) {
    return { qualified: false, gain, threshold: ledger.threshold, reason: 'gain below threshold' };
  }
  if (now() - 10n < ledger.opensAt) {
    return { qualified: false, reason: `wait until ${iso(ledger.opensAt)}: the Bounty isn't open` };
  }
  const attestors = await resolveAttestors(endpoints, ledger.R_keys);
  const { wallet, bounty } = await connect(address);
  // Stamped once the wallet is ready, since waiting for DUST can take minutes.
  const window = liveWindow();
  if (window[1] > ledger.deadline) {
    await wallet.wallet.stop();
    throw new Error(
      `too late: a Qualifying reading must be observed before ${iso(ledger.deadline)}`,
    );
  }
  const secret = Buffer.from(state.secret, 'hex');
  const reading = await collectClaim({
    request: readingRequest(state.agentId, state.skill),
    policy: readingPolicy(state.skill),
    holder: bounty.pure.holderCommitment(secret),
    window,
    attestors,
    registryKeys: ledger.R_keys,
  });
  const as = { attestations: [reading], holderSecret: secret };
  await bounty.call(as, 'verifyAttestation');
  const { blockHeight } = await bounty.call(
    as,
    'qualify',
    bounty.pure.computeId(reading.claim, reading.commitRand),
  );
  await wallet.wallet.stop();
  return {
    qualified: true,
    gain: (reading.claim.values[0] ?? 0n) - registration.startXp,
    blockHeight,
  };
};

/**
 * Take the Share: the pot split equally between the Qualifiers, paid to the address fixed
 * at Registration. The transaction names no agent.
 *
 * @param address - the Bounty.
 */
export const payout = async (address: string) => {
  const state = registeredState(address);
  const ledger = await readBounty(address);
  if (now() < ledger.deadline) {
    return {
      paid: false,
      reason: `wait until ${iso(ledger.deadline)}: Payouts start at the deadline`,
    };
  }
  const share = ledger.pot / ledger.qualifiers;
  const { wallet, bounty } = await connect(address);
  const { blockHeight } = await bounty.call(
    { attestations: [], holderSecret: Buffer.from(state.secret, 'hex') },
    'payout',
    { bytes: Buffer.from(state.payout, 'hex') },
    share,
  );
  saveState(address, { ...state, paid: true });
  await wallet.wallet.stop();
  return { paid: true, share, to: state.payout, blockHeight };
};
