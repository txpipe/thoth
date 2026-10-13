// What a Midnight City claim proves: the zkFetch requests and policies for a Control claim
// (`/local-control/claimable`, #129) and a Reading (`/progression`, #118). The agent ID after
// `user-agent-` rides in five `bytes8` slots, a stand-in for #26's byte slots.
import { parseDisclosedValue, type ZkFetchPolicy } from '@thoth/zk-tls';
import type { ZkFetchRequest } from '@thoth/zk-tls/client';

const API = 'https://midnight.city/observer/api';

/** The City's skills, as progression names them. */
export const SKILLS = [
  'agility',
  'bounty_hunting',
  'chemistry',
  'combat',
  'cooking',
  'crafting',
  'defence',
  'energy',
  'engineering',
  'farming',
  'fishing',
  'hacking',
  'infiltration',
  'mining',
  'ranged',
  'scavenging',
  'smithing',
  'vitality',
  'woodcutting',
] as const;

/** The agent ID after `user-agent-` in five 8-character groups, `id1`…`id5`. */
const AGENT_ID_GROUPS = `(?<id1>[0-9a-z-]{1,8})${[2, 3, 4, 5]
  .map((n) => `(?<id${n}>[0-9a-z-]{0,8})`)
  .join('')}`;

const ID_SLOTS = [1, 2, 3, 4, 5].map((n) => ({
  slot: n,
  name: `id${n}`,
  parse: 'bytes8' as const,
  optional: n > 1,
}));

export const CONTROL_POLICY: ZkFetchPolicy = { allowedHosts: ['midnight.city'], slots: ID_SLOTS };

/**
 * The Reading policy for one skill. Its XP slot is named after the skill, so the policy
 * hash a Bounty seals names its skill. shortcut: the regex itself isn't in the hash until
 * #113, so this is a label, not a binding.
 *
 * @param skill - the skill whose XP slot 0 holds.
 * @returns the policy.
 */
export const readingPolicy = (skill: string): ZkFetchPolicy => ({
  allowedHosts: ['midnight.city'],
  slots: [{ slot: 0, name: `${skill}_xp`, parse: 'int' }, ...ID_SLOTS],
});

/** The regex reveal slice for a match: its named groups replaced by their patterns. */
const reveal = (match: string): string => match.replace(/\(\?<\w+>([^()]*)\)/g, '$1');

/**
 * The Control claim's request: the first agent the City API token controls.
 *
 * @param token - the City API token, sent as a secret header the witnesses never see.
 * @returns the request.
 */
export const controlRequest = (token: string): ZkFetchRequest => {
  const firstAgent = `"agentIds":\\["user-agent-${AGENT_ID_GROUPS}"`;
  return {
    url: `${API}/local-control/claimable`,
    method: 'GET',
    secretHeaders: { authorization: `Bearer ${token}` },
    responseMatches: [{ type: 'regex', value: firstAgent }],
    responseRedactions: [{ regex: reveal(firstAgent) }],
  };
};

/**
 * A Reading's request: one agent's XP in one skill, and its ID from the response body.
 *
 * @param agentId - the agent.
 * @param skill - the skill.
 * @returns the request.
 */
export const readingRequest = (agentId: string, skill: string): ZkFetchRequest => {
  const xp = `"${skill}":\\{"level":\\d+,"nextLevelXp":\\d+,"xp":(?<${skill}_xp>\\d+)\\}`;
  // agent.id, pinned by the key sorted just before it inside `agent`.
  const agent = `"canStartConversation":(?:true|false),"id":"user-agent-${AGENT_ID_GROUPS}"`;
  return {
    url: `${API}/skill/agents/${agentId}/progression`,
    method: 'GET',
    responseMatches: [xp, agent].map((value) => ({ type: 'regex', value })),
    responseRedactions: [xp, agent].map((match) => ({ regex: reveal(match) })),
  };
};

/**
 * An agent ID as the five `bytes8` slot values its claims carry.
 *
 * @param agentId - `user-agent-…`.
 * @returns the five values.
 */
export const agentSlots = (agentId: string): bigint[] => {
  const id = agentId.replace(/^user-agent-/, '');
  return [0, 1, 2, 3, 4].map((i) => {
    const value = parseDisclosedValue(id.slice(i * 8, i * 8 + 8), 'bytes8');
    if (value === null) {
      throw new Error(`agent ID ${agentId} doesn't fit five bytes8 slots`);
    }
    return value;
  });
};

/**
 * An agent's current XP in a skill, from a plain public read (no proof).
 *
 * @param agentId - the agent.
 * @param skill - the skill.
 * @returns its XP, or undefined while the agent is offline (404).
 */
export const currentXp = async (agentId: string, skill: string): Promise<bigint | undefined> => {
  const response = await fetch(`${API}/skill/agents/${agentId}/progression`);
  if (response.status === 404) {
    return undefined;
  }
  const body = (await response.json()) as { skills?: Record<string, { xp?: number }> };
  const xp = body.skills?.[skill]?.xp;
  if (xp === undefined) {
    throw new Error(`progression has no ${skill} XP`);
  }
  return BigInt(xp);
};
