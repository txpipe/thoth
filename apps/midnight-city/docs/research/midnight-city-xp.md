# Midnight City: which skills' XP can't be bought

Research for [#120](https://github.com/txpipe-shop/thoth/issues/120), part of
the map [#117](https://github.com/txpipe-shop/thoth/issues/117).

**Question.** Which skills' XP can only come from an agent's own work, rather
than from bought or traded items? What threshold and deadline make a fair
first Bounty?

**Method.** Read-only HTTP GETs of public observer routes and docs on
**2026-10-09** (UTC, 00:50–01:07). No sign-in, no API token, no
`POST /observer/api/actions`, no `/local-control/*`. Requests were spaced by
about 3 seconds. Sources:

- the direct-control skill,
  [`SKILL.md`](https://midnight.city/observer/api/skill/SKILL.md) (version
  `2026-10-07T01:51:50Z`), and its published
  [bundle](https://midnight.city/observer/api/skill/midnight-city-direct-control.zip),
  which holds `references/progression.md` (the links in `SKILL.md` are
  relative to the bundle and 404 on the observer);
- the gameplay docs:
  [Skills and Professions](https://midnight.city/docs/gameplay/skills-and-professions/),
  [Gathering and Resources](https://midnight.city/docs/gameplay/gathering-and-resources/),
  [Items and Equipment](https://midnight.city/docs/gameplay/items-and-equipment/),
  [Crafting and Workstations](https://midnight.city/docs/gameplay/crafting-and-workstations/),
  [Combat and Enemies](https://midnight.city/docs/gameplay/combat-and-enemies/),
  [Contracts and Construction](https://midnight.city/docs/gameplay/contracts-and-construction/),
  [Economy and Needs](https://midnight.city/docs/gameplay/economy-and-needs/);
- [`/observer/api/spectator/bootstrap`](https://midnight.city/observer/api/spectator/bootstrap)
  (`staticVersion` `15572500041115259144`, `tickRateMs` 500, 734 agents in
  the dynamic world, 534 resource nodes), and
  `/observer/api/static-world/15572500041115259144` (game content version
  `d3344aed…99ad2b`: 19 skills, 90 sources, 728 recipes, 200 contracts,
  30 enemies, 969 items, 99 XP thresholds);
- [`/observer/api/skill/merchants`](https://midnight.city/observer/api/skill/merchants)
  (tick 19,155,956);
- `/observer/api/leaderboards?board=<skill>` for woodcutting, mining,
  hacking, fishing, farming and scavenging, sampled twice (plus cooking once);
- `/observer/api/skill/agents/{id}/progression` for 24 agents picked from
  those boards (ranks 1, 31, 61 and 91 of each; when a pick returned 404,
  meaning offline, or repeated an agent, the next rank), sampled twice:
  00:55:28–00:56:43 and 01:05:28–01:06:37 UTC, so each agent's two readings
  are 9.9–10.0 minutes apart. 2 of the 26 agents probed returned 404.

The trimmed samples are in [`data/`](data/): `data/picks.json`, and per
round `progression.json` (skills, profession, active action, equipment; the
`capabilities` block is dropped) and the leaderboard responses.

Text marked **[inferred]** is our reading, not a statement from the source.

## Answer

- **Gathering XP is own work.** A gather grants a fixed XP per completed
  action. A bought tool only shortens the work time; it never raises the XP
  of one action. Items can't move between agents at all, so nobody can hand an
  agent the outputs of someone else's work.
- **Cooking is the one skill whose XP can be bought outright.** The L1 recipe
  `cook_fish` takes one `fish`, and a merchant sells `fish` for 58 crystals.
  Crystals *can* move between agents (`send-crystal`).
- **Recommended first Bounty: Mining, a gain of 10,000 XP within 24 hours of
  the Start reading.** Woodcutting with the same numbers is the second choice.
  Mining has no merchant tool below level 31, so a new agent has nothing to
  buy that speeds it up; it is a profession skill, so `work` automates it.

## What can cross between agents

This bounds what "bought or traded" can mean.

- **Items: nothing.** The action list in `SKILL.md` has merchant `trade`,
  `send-crystal`, and no item gift or transfer. Graves are "owner-only"
  ([Combat and Enemies](https://midnight.city/docs/gameplay/combat-and-enemies/)).
- **Crystals: yes, capped.** `send-crystal` moves crystals between two online
  agents. The default limit is 100 crystals per agent per 7 days; the owner can
  raise it to 4,294,967,295 with human approval
  ([Economy and Needs](https://midnight.city/docs/gameplay/economy-and-needs/)).
  **[inferred]** So crystals are the only channel through which one agent's
  work, or a Controller's other agents, can fund another agent.
- **City Shop items** are bound cosmetics; none of the 28 cosmetic items has
  tool, equipment or consumable stats (static world).
- **Merchant trades and admin inventory changes award no XP**
  ([`progression.md`](https://midnight.city/observer/api/skill/midnight-city-direct-control.zip),
  [Skills and Professions](https://midnight.city/docs/gameplay/skills-and-professions/)).

What crystals buy (merchants, tick 19,155,956):

| Offer | Effect on XP |
|---|---|
| `fish` (58), `meat` (58), `to_go_food` (58), `matcha_smoothie` (20) | Food. Hunger lengthens work, so food keeps an agent at normal speed. `fish` is also the `cook_fish` input. |
| `aegis_reagent_salve` (29) | Heals 24. Keeps an agent fighting. |
| `cinder_axe` (16): Woodcutting tool, L2, −10% work time | ≤ +11% Woodcutting XP/h |
| `basalt_axe` (12): Woodcutting tool, L21, −15% | ≤ +18% Woodcutting XP/h |
| `obsidian_pickaxe` (20): Mining tool, L31, −18% | ≤ +22% Mining XP/h |
| `cinder_decoder` (16): Hacking tool, L21, −10% | ≤ +11% Hacking XP/h |
| `geothermal_gloves` (15): Energy tool, L41, −10% | ≤ +11% Energy XP/h |

The "≤" bounds are **[inferred]**: XP per action is fixed, so the best case is
an agent that never waits, and XP/h scales by `1 / (1 − workBonus)`. In
practice travel and node waits dilute it. Tools also break (wear chance per
use) and are not equipped; the best carried tool applies
([Gathering and Resources](https://midnight.city/docs/gameplay/gathering-and-resources/)).
No consumable grants XP or a speed buff: all 150 consumables only restore
health or hunger (static world).

Other crystal sinks that touch XP (static world):

- `cook_fish` (Cooking L1): 1 `fish` → 39 Cooking XP in 4 ticks. That is
  about 1.5 crystals per Cooking XP, with no other input.
- Recipes at L61, L81 and L91 in Smithing, Crafting and Engineering also
  consume 50, 125 or 300 crystals, beside self-gathered inputs.
- `install-building` costs 1,000,000 crystals and grants 49 Engineering XP.
  A leased plot gives a 5% work-time bonus in the Construction Yard area only.
- Two contracts take purchasable items: `greenway_trust_canal_provision_fish`
  (1 `fish` → 83 Fishing XP) and `signal_bureau_recovery_claim_crystal`
  (1 crystal → 183 Scavenging XP). Each contract completes once per agent.

## Per skill

XP sources are from the static world and `progression.md`. "Ceiling" is the
best source's XP per work time at 500 ms per tick, with no tool and no
waiting: L1 sources give 29 XP per 3 ticks, which is **69,600 XP/h**. Observed
XP/h is from the two readings, for agents whose skill moved; the level is that
agent's level in the skill.

| Skill | What grants XP | Bought/traded speed-up | Observed XP/h (level) | Own work only? |
|---|---|---|---|---|
| Woodcutting | Gather (12 sources) | `cinder_axe` from L2 (≤ +11%), `basalt_axe` from L21 (≤ +18%) | 34.8k (36), 47.3k (32), 47.9k (30), 39.6k (27), 7.3k (15) | Yes; tool speeds it up a little |
| Mining | Gather (12 sources) | Nothing below L31; `obsidian_pickaxe` from L31 (≤ +22%) | 44.8k (27), 89.4k (25), 20.3k (18), 31.2k (17), 37.6k (16), 0.5k (7) | **Yes** |
| Hacking | Gather terminals (8); 14 recipes | `cinder_decoder` from L21 (≤ +11%) | 41.2k (28), 40.4k (24), 16.2k (18), 9.1k (9), 1.0k (5) | Yes; the base terminal *earns* crystals (`meme_coin` → 4 crystals) |
| Fishing | Gather (12); 9 recipes | None sold; 83 XP once via the fish contract | 105.5k (46) | Yes |
| Farming | Gather (12); 9 recipes | None sold | 103.7k (44) | Yes |
| Scavenging | Gather (12); 14 recipes | None sold; 183 XP once via the crystal contract | 112.6k (43), 71.6k (29) | Yes |
| Energy | Gather (8); 9 recipes | `geothermal_gloves` from L41 | not sampled | Yes |
| Agility | Traverse obstacles (7) | None sold | not sampled | Yes |
| Infiltration | Breach caches (7) | None sold | 107.8k (37) | Yes |
| Smithing | 119 recipes | Inputs self-gathered; crystals as an extra input from L61 | not sampled | Yes below L61 **[inferred]** |
| Crafting | 129 recipes | Same as Smithing | not sampled | Yes below L61 **[inferred]** |
| Chemistry | 64 recipes | None | not sampled | Yes |
| Engineering | 254 recipes; `install-building` | 49 XP per 1M crystals; crystals from L61 | not sampled | Mostly; 64,000 XP of one-time contracts |
| Cooking | 107 recipes | **`cook_fish` from merchant `fish`: 39 XP per 58 crystals** | not sampled | **No** |
| Combat, Ranged | Damage share of each kill's `damageXp` pool | Salves sustain fights; weapons are crafted, not sold | not sampled | Yes, but contested |
| Defence, Vitality | Health lost to retaliation | Salves | not sampled | Yes, but contested |
| Bounty Hunting | Damage share of `bountyXp` on a kill; 30 contracts | Salves | not sampled | Yes, but contested |

Notes:

- **Conflict skills are contested.** Each kill has fixed XP pools split by the
  damage each attacker dealt. L1 enemies (6 hounds) have 30 HP, an 8-XP attack
  pool and a 57-XP bounty pool, and respawn after 480 ticks (4 min)
  ([Combat and Enemies](https://midnight.city/docs/gameplay/combat-and-enemies/),
  static world). **[inferred]** Other agents near the same enemies directly cut
  an agent's XP, so they are poor Bounty skills.
- **Contracts are bounded.** Each completes once per agent. All contracts for
  Mining total 2,860 XP, and only 246 XP of it needs level 10 or less. Their
  delivery items are mostly rare outputs of the agent's own gathering
  (static world).
- **Rates.** 21 of 24 agents gained XP in the window. Gathering agents ran at
  about 25–60% of their best source's ceiling. Agents whose action was
  `linger`, or none, gained 0–1.5k XP/h.

## Surprise: the docs' XP curve is not the live one

[Skills and Professions](https://midnight.city/docs/gameplay/skills-and-professions/)
gives level 11 at 69,600 XP, level 21 at 442,200 and level 99 at 201,678,960,
with "720 active hours" to level 99 (also in `progression.md`). The live
`xpThresholds` are about **6× higher**: level 11 at 417,600, level 21 at
2,653,200, level 99 at 1,226,893,140. Level 2 is at 250 XP, then level 3 jumps
to 16,704. The docs' level-11 figure equals exactly one hour at the L1
ceiling (69,600 XP/h). **[inferred]** The docs are stale or the curve changed;
either way a Bounty threshold should be set in XP from live data, never in
levels from the docs.

## Recommendation for the first devnet Bounty

**Skill: Mining.** **Threshold: a gain of 10,000 XP over the Start reading.**
**Deadline: 24 hours after the Start reading.**

- **Not buyable.** Below level 31 no merchant sells a Mining tool, and no
  item can reach the agent from another agent. Mining contracts that a new
  agent can deliver total 246 XP, far below the threshold.
- **Reachable for a new agent.** A level-1 agent mines the L1 ore source
  (29 XP per 1.5 s, 69,600 XP/h ceiling). At the observed 25–60% of ceiling,
  that is about 17k–42k XP/h, so 10,000 XP is roughly 15–35 minutes of
  focused mining **[inferred]**. Miners can use `work`, so the agent needs no
  per-action steering.
- **Not met by idling.** Agents that lingered gained 0–1.5k XP/h, so an agent
  that doesn't work won't qualify by accident in a short window.
- **24 hours** absorbs offline periods, busy nodes and hunger, and is still
  short enough to run and demo in a day. For a live demo, a 2-hour deadline
  with the same threshold also fits **[inferred]**.
- **Levels.** Sampled miners at levels 16–27 would clear 10,000 XP in about
  7–30 minutes. With an equal
  split that only makes the Bounty easy for them, not unfair to others.

**Second choice: Woodcutting**, same numbers. The `cinder_axe` (16 crystals,
from L2) can make it up to ~11% faster, which is a small, bounded edge.

**Avoid:** Cooking (buyable), Engineering (crystal-fed, and dominated by
one-time contract XP), and the five conflict skills (contested pools).

**Readings.** Skill boards use persisted XP and include offline agents, and
refresh about once a minute (`progression.md`). The per-agent `progression`
route 404s while an agent is offline (2 of 26 probed here). **[inferred]** A
Start reading or a qualifying reading through `progression` needs the agent
online at that moment.
