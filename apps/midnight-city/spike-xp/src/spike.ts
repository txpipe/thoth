// Spike for #118: attest one agent's XP in one skill (a Reading) from the City's public
// progression read, through two zkFetch witnesses, and check that both derive one claim.
// Public and read-only: no token, no cookies, no /local-control, no actions.
import { writeFileSync } from 'node:fs';
import { claimToMessage } from '@thoth/core/claim';
import {
  assertEvidenceMatchesPolicy,
  claimRequestOf,
  deriveClaimFromEvidence,
  type VerifiedEvidence,
  type ZkFetchEvidence,
  type ZkFetchPolicy,
  zkFetchSubjectOf,
} from '@thoth/zk-tls';
import { verifyZkFetchProof } from '@thoth/zk-tls/attestor';
import type { ZkFetchRequest } from '@thoth/zk-tls/client';
import { zkFetchProver } from '@thoth/zk-tls/prover';

const API = 'https://midnight.city/observer/api';
// #120: Mining first, Woodcutting second.
const SKILL = process.env.MCITY_SKILL ?? 'mining';
const WITNESS_URLS = (process.env.WITNESS_URLS ?? 'ws://localhost:8001/ws,ws://localhost:8002/ws')
  .split(',')
  .map((url) => url.trim());
const FIXTURE_PATH = new URL(`../../fixtures/reading-${SKILL}.json`, import.meta.url);

/**
 * The agent ID after `user-agent-` as five 8-character groups, one per `bytes8`
 * claim slot (a proof-of-concept stand-in for #26). IDs run up to 36 characters.
 */
const AGENT_ID_GROUPS = `(?<id1>[0-9a-z-]{1,8})${[2, 3, 4, 5]
  .map((n) => `(?<id${n}>[0-9a-z-]{0,8})`)
  .join('')}`;

/** The agent ID a match's five groups spell, or undefined without one. */
const agentFrom = (
  groups: Readonly<Record<string, string | undefined>> | undefined,
): string | undefined =>
  groups?.id1 === undefined
    ? undefined
    : `user-agent-${[1, 2, 3, 4, 5].map((n) => groups[`id${n}`] ?? '').join('')}`;

/** The skill's XP. Keys come sorted and compact, so the object's shape is fixed. */
const xpMatch = (skill: string): string =>
  `"${skill}":\\{"level":\\d+,"nextLevelXp":\\d+,"xp":(?<xp>\\d+)\\}`;
// agent.id, pinned by the key sorted just before it inside `agent`.
const AGENT_MATCH = `"canStartConversation":(?:true|false),"id":"user-agent-${AGENT_ID_GROUPS}"`;
/** The slice a match reads, which is all the witness gets to see. */
const reveal = (match: string): string => match.replace(/\(\?<\w+>([^()]*)\)/g, '$1');

/** Only the XP is a value today; the agent ID waits on #26's 'bytes' rule. */
const policy: ZkFetchPolicy = {
  allowedHosts: ['midnight.city'],
  slots: [{ slot: 0, name: 'xp', parse: 'int' }],
};

const progressionUrl = (agentId: string): string => `${API}/skill/agents/${agentId}/progression`;
const hex = (bytes: Uint8Array): string => `0x${Buffer.from(bytes).toString('hex')}`;
const ms = (start: number): number => Math.round(performance.now() - start);

/** One plain read of an agent's progression. */
const read = async (agentId: string) => {
  const start = performance.now();
  const response = await fetch(progressionUrl(agentId));
  const body = await response.text();
  const result = {
    agentId,
    status: response.status,
    bytes: Buffer.byteLength(body),
    ms: ms(start),
  };
  console.log(`read ${agentId}: HTTP ${result.status}, ${result.bytes} bytes, ${result.ms} ms`);
  if (result.status !== 200) {
    console.log(`  body: ${body.slice(0, 120)}`);
  }
  return { ...result, body };
};

/** The request a Reading proves: the skill's XP and the agent ID, nothing else revealed. */
const readingRequest = (agentId: string, skill: string) =>
  ({
    url: progressionUrl(agentId),
    method: 'GET',
    responseMatches: [xpMatch(skill), AGENT_MATCH].map((value) => ({ type: 'regex', value })),
    responseRedactions: [xpMatch(skill), AGENT_MATCH].map((match) => ({ regex: reveal(match) })),
  }) satisfies ZkFetchRequest;

/** Prove `request` through `witnessUrl`, then verify the evidence and check it against the policy. */
const prove = async (witnessUrl: string, request: ZkFetchRequest) => {
  const start = performance.now();
  const evidence = await zkFetchProver({ witnessUrl }).prove(request);
  console.log(`proof via ${witnessUrl}: ${ms(start)} ms`);
  const verified = await verifyZkFetchProof(evidence);
  assertEvidenceMatchesPolicy(verified, policy);
  return { evidence, verified };
};

/** The claim an attestor would sign for `verified`, with placeholder app and holder. */
const claimOf = (verified: VerifiedEvidence, windowStart: bigint, windowEnd: bigint) =>
  deriveClaimFromEvidence({
    verified,
    policy,
    appId: new Uint8Array(32).fill(0xa1),
    holder: new Uint8Array(32).fill(0xc1),
    valueSlots: 1,
    windowStart,
    windowEnd,
  });

// Liveness: walk the board until one agent answers and one doesn't, spaced like the research.
const board = (await (await fetch(`${API}/leaderboards?board=${SKILL}`)).json()) as {
  entries: { agentId: string }[];
};
const reads = [];
for (const { agentId } of board.entries) {
  reads.push(await read(agentId));
  if (reads.some((r) => r.status === 200) && reads.some((r) => r.status !== 200)) {
    break;
  }
  await new Promise((resolve) => setTimeout(resolve, 1000));
}
const pick =
  process.env.MCITY_AGENT_ID === undefined
    ? reads.find((r) => r.status === 200)
    : await read(process.env.MCITY_AGENT_ID);
if (pick === undefined || pick.status !== 200) {
  throw new Error(`no online agent among the first ${reads.length} on the ${SKILL} board`);
}

// Check both regexes on a plain read before paying for proofs.
const plainXp = new RegExp(xpMatch(SKILL)).exec(pick.body)?.groups?.xp;
const plainAgent = agentFrom(new RegExp(AGENT_MATCH).exec(pick.body)?.groups);
console.log(`plain read of ${pick.agentId}: ${SKILL} xp ${plainXp}, agent.id ${plainAgent}`);
if (plainXp === undefined || plainAgent !== pick.agentId) {
  throw new Error('the XP or agent regex does not bind the plain progression read');
}

// Both witnesses at once, as a client would: the XP of a working agent moves every few seconds.
const request = readingRequest(pick.agentId, SKILL);
const proofs = await Promise.all(WITNESS_URLS.map((witnessUrl) => prove(witnessUrl, request)));
const observedAt = proofs.map(({ verified }) => BigInt(verified.claim.timestampS));
const windowStart = observedAt.reduce((a, b) => (a < b ? a : b));
const windowEnd = observedAt.reduce((a, b) => (a > b ? a : b));
const claims = proofs.map(({ verified }) => claimOf(verified, windowStart, windowEnd));
const messages = claims.map((claim) =>
  claimToMessage(claim).map((field) => `0x${field.toString(16)}`),
);

for (const { verified } of proofs) {
  const { xp } = verified.disclosedValues;
  const agent = agentFrom(verified.disclosedValues);
  console.log(`witness ${verified.attestorAddress}: ${SKILL} xp ${xp}, agent ${agent}`);
}
const agree = new Set(messages.map((message) => message.join())).size === 1;
console.log(`witnesses derive one claim: ${agree}`);

const [first] = proofs;
const [claim] = claims;
const [message] = messages;
if (first === undefined || claim === undefined || message === undefined) {
  throw new Error('no witnesses configured');
}
const iso = (seconds: bigint) => new Date(Number(seconds) * 1000).toISOString();
console.log(
  `\nclaim: agent ${agentFrom(first.verified.disclosedValues)} had ${SKILL} XP ${claim.values[0]}, observed between ${iso(windowStart)} and ${iso(windowEnd)}`,
);
const subjectRequest = claimRequestOf(first.verified.claim);
const subject = zkFetchSubjectOf(subjectRequest);
console.log(`subject: ${subjectRequest.method} ${subjectRequest.url}`);
for (const [field, hash] of Object.entries(subject)) {
  console.log(`  ${field}: ${hex(hash)}`);
}
console.log(`  subjectHash: ${hex(claim.subjectHash)}`);
console.log(`policyHash: ${hex(claim.policyHash)}`);
console.log(`message: ${message.join(' ')}`);

// #113: the same policy over a regex that reads another skill's XP into the `xp` slot.
const swapped = await prove(WITNESS_URLS[0] ?? '', readingRequest(pick.agentId, 'fishing'));
const swappedClaim = claimOf(swapped.verified, windowStart, windowEnd);
const samePolicy = hex(swappedClaim.policyHash) === hex(claim.policyHash);
const sameSubject = hex(swappedClaim.subjectHash) === hex(claim.subjectHash);
console.log(
  `\n#113: a fishing request passes the ${SKILL} policy; same policyHash ${samePolicy}, same subjectHash ${sameSubject}, xp ${swappedClaim.values[0]} (fishing) vs ${claim.values[0]} (${SKILL})`,
);

if (agree) {
  const evidences: ZkFetchEvidence[] = proofs.map(({ evidence }) => evidence);
  const fixture = { generatedAt: new Date().toISOString(), skill: SKILL, request, evidences };
  writeFileSync(FIXTURE_PATH, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(`\nfixture written to ${FIXTURE_PATH.pathname}`);
}
// The Reclaim client pools its witness websockets and never closes them.
process.exit(agree ? 0 : 1);
