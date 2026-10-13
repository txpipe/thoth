// The Bounty (#122) in the simulator: Registration, qualifying, Payout and Refund,
// and each cheat in #117's verdict rule. Claims are signed fixtures; the agent ID
// rides in five bytes8 slots, a stand-in for #26's byte slots.
import { randomBytes } from 'node:crypto';
import type { Effects } from '@midnight-ntwrk/compact-runtime';
import { beforeEach, describe, expect, it } from 'vitest';
import type { A_Claim } from '../artifacts/bounty/contract/index.js';
import {
  type Attestation,
  agentKey,
  BountySim,
  claimFor,
  idOf,
  makeNotaryKey,
  payoutLeaf,
  sign,
  type UserAddress,
} from './sim.js';

const T0 = 1_800_000_000n;
const OPENS_AT = T0 + 1_000n;
const DEADLINE = T0 + 2_000n;
const PAYOUT_END = T0 + 3_000n;
const THRESHOLD = 10_000n;
const CONTROL_POLICY = new Uint8Array(32).fill(0xc0);
const READING_POLICY = new Uint8Array(32).fill(0xe0);
const START_WINDOW = [T0 + 100n, T0 + 101n] as const;
const QUALIFY_WINDOW = [T0 + 1_500n, T0 + 1_501n] as const;

const AGENT_A = 'user-agent-lhb10ef8yjy1wfc';
const AGENT_B = 'user-agent-dc4ccc6f-53ce-4e17-921c-8f5848590269';

const address = (byte: number): UserAddress => ({ bytes: new Uint8Array(32).fill(byte) });
const SPONSOR = address(0x5a);

const keys = [makeNotaryKey(), makeNotaryKey(), makeNotaryKey()];
/** 2-of-3: the third attestor doesn't sign. */
const SIGNERS = [keys[0] ?? null, keys[1] ?? null, null];

/** A Controller's agent, with the one fresh secret its Registration uses. */
type Controller = { agentId: string; secret: Uint8Array; payout: UserAddress };
const controller = (agentId: string, payoutByte: number): Controller => ({
  agentId,
  secret: randomBytes(32),
  payout: address(payoutByte),
});

const controlOf = (c: Controller, agentId = c.agentId): A_Claim =>
  claimFor({ policy: CONTROL_POLICY, agentId, xp: null, window: START_WINDOW, secret: c.secret });

const readingOf = (
  c: Controller,
  xp: bigint,
  window: readonly [bigint, bigint],
  agentId = c.agentId,
): A_Claim => claimFor({ policy: READING_POLICY, agentId, xp, window, secret: c.secret });

let sim: BountySim;

/** Vault `claim` as `c`, just after its window. */
const attest = async (c: Controller, claim: A_Claim): Promise<Attestation> => {
  const attestation = sign(claim, SIGNERS);
  sim.now = claim.windowEnd + 1n;
  await sim.call('verifyAttestation', { attestations: [attestation], holderSecret: c.secret });
  return attestation;
};

const registerWith = async (
  c: Controller,
  control: Attestation,
  start: Attestation,
  at = T0 + 200n,
) => {
  sim.now = at;
  await sim.call(
    'register',
    { attestations: [control, start], holderSecret: c.secret },
    idOf(control),
    idOf(start),
    c.payout,
  );
};

const qualify = async (c: Controller, reading: Attestation, at = reading.claim.windowEnd + 10n) => {
  sim.now = at;
  await sim.call('qualify', { attestations: [reading], holderSecret: c.secret }, idOf(reading));
};

const fund = async (amount: bigint) => {
  sim.now = T0;
  await sim.call(
    'fund',
    { attestations: [], holderSecret: new Uint8Array(32) },
    amount,
    randomBytes(2048),
  );
};

/** A Payout names only the address and the Share; `pathFor` stages a forged Merkle path. */
const payout = async (
  c: Controller,
  share: bigint,
  {
    at = DEADLINE + 10n,
    to = c.payout,
    pathFor,
  }: { at?: bigint; to?: UserAddress; pathFor?: Uint8Array } = {},
): Promise<Effects> => {
  sim.now = at;
  return sim.call('payout', { attestations: [], holderSecret: c.secret, pathFor }, to, share);
};

const refund = async (at: bigint): Promise<Effects> => {
  sim.now = at;
  return sim.call('refund', { attestations: [], holderSecret: new Uint8Array(32) });
};

/** What an effect pays: `[recipient address hex, amount]` per unshielded payment. */
const payments = (effects: Effects): [string, bigint][] =>
  [...effects.claimedUnshieldedSpends].map(([[, to], amount]) => [to.address, amount]);
const hex = (address: UserAddress): string => Buffer.from(address.bytes).toString('hex');

/** Every Registration as public text, byte arrays in hex. */
const publicRegistrations = (): string =>
  JSON.stringify([...sim.ledger().registrations], (_, value) =>
    value instanceof Uint8Array
      ? Buffer.from(value).toString('hex')
      : typeof value === 'bigint'
        ? value.toString()
        : value,
  );

const register = async (c: Controller, startXp = 5_000n) =>
  registerWith(
    c,
    await attest(c, controlOf(c)),
    await attest(c, readingOf(c, startXp, START_WINDOW)),
  );

beforeEach(async () => {
  sim = await BountySim.deploy({
    keys: keys.map((key) => key.pk),
    controlPolicy: CONTROL_POLICY,
    readingPolicy: READING_POLICY,
    threshold: THRESHOLD,
    opensAt: OPENS_AT,
    deadline: DEADLINE,
    payoutEnd: PAYOUT_END,
    sponsor: SPONSOR,
    freshnessWindow: 3_600n,
    maxWindow: 300n,
  });
});

describe('Registration', () => {
  it('registers an agent with a Control claim and a Start reading', async () => {
    const alice = controller(AGENT_A, 0x11);
    await register(alice, 5_000n);
    const registration = sim.ledger().registrations.lookup(agentKey(AGENT_A));
    expect(registration.startXp).toBe(5_000n);
    expect(registration.qualified).toBe(false);
  });

  it('keeps the payout address out of the public Registration', async () => {
    const alice = controller(AGENT_A, 0x11);
    await register(alice);
    expect(publicRegistrations()).not.toContain(hex(alice.payout));
  });
});

describe('qualifying', () => {
  it('qualifies an agent whose gain reaches the threshold', async () => {
    const alice = controller(AGENT_A, 0x11);
    await register(alice, 5_000n);
    await qualify(alice, await attest(alice, readingOf(alice, 15_000n, QUALIFY_WINDOW)));
    expect(sim.ledger().registrations.lookup(agentKey(AGENT_A)).qualified).toBe(true);
    expect(sim.ledger().qualifiers).toBe(1n);
  });
});

/** A 1,001 pot with Alice and Bob both qualified. */
const twoQualifiers = async () => {
  await fund(1_001n);
  const alice = controller(AGENT_A, 0x11);
  const bob = controller(AGENT_B, 0x22);
  await register(alice);
  await register(bob);
  await qualify(alice, await attest(alice, readingOf(alice, 15_000n, QUALIFY_WINDOW)));
  await qualify(bob, await attest(bob, readingOf(bob, 20_000n, QUALIFY_WINDOW)));
  return { alice, bob };
};

describe('Payout', () => {
  it('splits the pot equally between two Qualifiers, each paid at its Registration address', async () => {
    await fund(1_001n);
    const alice = controller(AGENT_A, 0x11);
    const bob = controller(AGENT_B, 0x22);
    await register(alice);
    await register(bob);
    await qualify(alice, await attest(alice, readingOf(alice, 15_000n, QUALIFY_WINDOW)));
    await qualify(bob, await attest(bob, readingOf(bob, 20_000n, QUALIFY_WINDOW)));

    // 1,001 / 2 rounds down to 500 each; the odd unit goes back in the Refund.
    expect(payments(await payout(alice, 500n))).toEqual([[hex(alice.payout), 500n]]);
    expect(payments(await payout(bob, 500n))).toEqual([[hex(bob.payout), 500n]]);
  });

  it('names no agent and changes nothing stored under one', async () => {
    const { alice } = await twoQualifiers();
    const before = publicRegistrations();
    await payout(alice, 500n);
    expect(publicRegistrations()).toEqual(before);
  });
});

describe('Refund', () => {
  it('returns the whole pot to the Sponsor after the deadline when nobody qualified', async () => {
    await fund(1_001n);
    await register(controller(AGENT_A, 0x11));
    expect(payments(await refund(DEADLINE + 10n))).toEqual([[hex(SPONSOR), 1_001n]]);
  });

  it("returns what's left to the Sponsor after the Payout period", async () => {
    await fund(1_001n);
    const alice = controller(AGENT_A, 0x11);
    const bob = controller(AGENT_B, 0x22);
    await register(alice);
    await register(bob);
    await qualify(alice, await attest(alice, readingOf(alice, 15_000n, QUALIFY_WINDOW)));
    await qualify(bob, await attest(bob, readingOf(bob, 20_000n, QUALIFY_WINDOW)));
    await payout(alice, 500n);
    // Bob never takes his Share: 1,001 - 500 goes back.
    expect(payments(await refund(PAYOUT_END + 10n))).toEqual([[hex(SPONSOR), 501n]]);
  });
});

describe('Registration rejects', () => {
  it("another Controller's agent: a public Reading passed off as a Control claim", async () => {
    // Anyone can take a Reading of any agent, so only the Control policy proves control.
    const mallory = controller(AGENT_A, 0x66);
    const fakeControl = await attest(mallory, readingOf(mallory, 5_000n, START_WINDOW));
    const start = await attest(mallory, readingOf(mallory, 5_000n, [T0 + 120n, T0 + 121n]));
    await expect(registerWith(mallory, fakeControl, start)).rejects.toThrow('Not a Control claim');
  });

  it('a Control claim passed off as the Start reading', async () => {
    const alice = controller(AGENT_A, 0x11);
    const control = await attest(alice, controlOf(alice));
    const fakeStart = await attest(
      alice,
      claimFor({
        policy: CONTROL_POLICY,
        agentId: AGENT_A,
        xp: null,
        window: [T0 + 120n, T0 + 121n],
        secret: alice.secret,
      }),
    );
    await expect(registerWith(alice, control, fakeStart)).rejects.toThrow('Not a Reading');
  });

  it('a Control claim for a different agent than the Start reading', async () => {
    const alice = controller(AGENT_A, 0x11);
    const control = await attest(alice, controlOf(alice, AGENT_B));
    const start = await attest(alice, readingOf(alice, 5_000n, START_WINDOW));
    await expect(registerWith(alice, control, start)).rejects.toThrow('Agent mismatch');
  });

  it('a Start reading observed after the Bounty opens', async () => {
    const alice = controller(AGENT_A, 0x11);
    const control = await attest(alice, controlOf(alice));
    const start = await attest(alice, readingOf(alice, 5_000n, [OPENS_AT + 10n, OPENS_AT + 11n]));
    await expect(registerWith(alice, control, start, OPENS_AT + 20n)).rejects.toThrow(
      'Start reading after the Bounty opens',
    );
  });

  it('a second Registration of the same agent, which would move its payout address', async () => {
    await register(controller(AGENT_A, 0x11));
    await expect(register(controller(AGENT_A, 0x66))).rejects.toThrow('Agent already registered');
  });
});

describe('qualifying rejects', () => {
  let alice: Controller;
  beforeEach(async () => {
    alice = controller(AGENT_A, 0x11);
    await register(alice, 5_000n);
  });

  it('a gain below the threshold', async () => {
    const reading = await attest(alice, readingOf(alice, 14_999n, QUALIFY_WINDOW));
    await expect(qualify(alice, reading)).rejects.toThrow('Gain below threshold');
  });

  it('gain before the Start reading: a Reading observed before the Bounty opens', async () => {
    const reading = await attest(alice, readingOf(alice, 15_000n, [T0 + 500n, T0 + 501n]));
    await expect(qualify(alice, reading)).rejects.toThrow('Reading before the Bounty opens');
  });

  it('a late reading, observed after the deadline', async () => {
    const reading = await attest(alice, readingOf(alice, 15_000n, [DEADLINE + 5n, DEADLINE + 6n]));
    await expect(qualify(alice, reading)).rejects.toThrow('Late reading');
  });

  it('a Reading submitted after the deadline, once Shares are fixed', async () => {
    const reading = await attest(alice, readingOf(alice, 15_000n, QUALIFY_WINDOW));
    await expect(qualify(alice, reading, DEADLINE + 1n)).rejects.toThrow('Qualifying closed');
  });

  it("another agent's Reading", async () => {
    const reading = await attest(alice, readingOf(alice, 15_000n, QUALIFY_WINDOW, AGENT_B));
    await expect(qualify(alice, reading)).rejects.toThrow('Agent not registered');
  });

  it("a mismatched holder: someone else's Reading of a registered agent", async () => {
    const mallory = controller(AGENT_A, 0x66);
    const reading = await attest(mallory, readingOf(mallory, 15_000n, QUALIFY_WINDOW));
    await expect(qualify(mallory, reading)).rejects.toThrow('Holder mismatch');
  });

  it('a Control claim passed off as a Reading', async () => {
    const fake = await attest(
      alice,
      claimFor({
        policy: CONTROL_POLICY,
        agentId: AGENT_A,
        xp: null,
        window: QUALIFY_WINDOW,
        secret: alice.secret,
      }),
    );
    await expect(qualify(alice, fake)).rejects.toThrow('Not a Reading');
  });

  it('qualifying twice, which would shrink every Share', async () => {
    await qualify(alice, await attest(alice, readingOf(alice, 15_000n, QUALIFY_WINDOW)));
    const again = await attest(alice, readingOf(alice, 16_000n, [T0 + 1_600n, T0 + 1_601n]));
    await expect(qualify(alice, again)).rejects.toThrow('Already qualified');
  });
});

describe('Payout rejects', () => {
  it('a second Payout', async () => {
    const { alice } = await twoQualifiers();
    await payout(alice, 500n);
    await expect(payout(alice, 500n)).rejects.toThrow('Already paid');
  });

  it('a Payout before the deadline', async () => {
    const { alice } = await twoQualifiers();
    await expect(payout(alice, 500n, { at: DEADLINE - 1n })).rejects.toThrow(
      'Payout period not open',
    );
  });

  it('a Payout after the Payout period', async () => {
    const { alice } = await twoQualifiers();
    await expect(payout(alice, 500n, { at: PAYOUT_END })).rejects.toThrow('Payout period over');
  });

  it('a Payout by someone who never qualified', async () => {
    await twoQualifiers();
    const mallory = controller(AGENT_A, 0x66);
    await expect(payout(mallory, 500n)).rejects.toThrow('Not a Qualifier');
  });

  it('a stolen secret redirecting a Share to another address', async () => {
    const { alice } = await twoQualifiers();
    await expect(payout(alice, 500n, { to: address(0x66) })).rejects.toThrow('Not a Qualifier');
  });

  it("another Qualifier's Merkle path, presented with your own secret and address", async () => {
    const { alice } = await twoQualifiers();
    const mallory = controller(AGENT_A, 0x66);
    const alicesLeaf = payoutLeaf(alice.secret, alice.payout);
    await expect(payout(mallory, 500n, { pathFor: alicesLeaf })).rejects.toThrow('Not a Qualifier');
  });

  it('a Share larger than the pot split equally', async () => {
    const { alice } = await twoQualifiers();
    await expect(payout(alice, 501n)).rejects.toThrow('Wrong Share');
  });

  it("a Payout to an agent that didn't qualify", async () => {
    const { alice } = await twoQualifiers();
    const carol = controller('user-agent-f47a6c144f90ba7ba841', 0x33);
    await register(carol);
    await payout(alice, 500n);
    await expect(payout(carol, 333n)).rejects.toThrow('Not a Qualifier');
  });
});

describe('Refund rejects', () => {
  it('a Refund before the Payout period ends, when someone qualified', async () => {
    await twoQualifiers();
    await expect(refund(DEADLINE + 10n)).rejects.toThrow('Too early for a Refund');
  });

  it('a Refund before the deadline, when nobody qualified', async () => {
    await fund(1_001n);
    await expect(refund(DEADLINE - 1n)).rejects.toThrow('Too early for a Refund');
  });

  it('a second Refund', async () => {
    await fund(1_001n);
    await refund(DEADLINE + 10n);
    await expect(refund(DEADLINE + 20n)).rejects.toThrow('Already refunded');
  });
});

describe('the pot and observations', () => {
  it('rejects funding after the deadline, so Shares stay fixed', async () => {
    sim.now = DEADLINE;
    await expect(
      sim.call(
        'fund',
        { attestations: [], holderSecret: new Uint8Array(32) },
        10n,
        randomBytes(2048),
      ),
    ).rejects.toThrow('Bounty closed');
  });

  it('rejects the same observation vaulted twice (the module nullifier)', async () => {
    const alice = controller(AGENT_A, 0x11);
    const reading = sign(readingOf(alice, 5_000n, START_WINDOW), SIGNERS);
    sim.now = START_WINDOW[1] + 1n;
    await sim.call('verifyAttestation', { attestations: [reading], holderSecret: alice.secret });
    await expect(
      sim.call('verifyAttestation', { attestations: [reading], holderSecret: alice.secret }),
    ).rejects.toThrow('Observation replay');
  });
});
