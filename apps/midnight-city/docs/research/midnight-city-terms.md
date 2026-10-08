# Midnight City: terms and policies on third-party rewards

Research for [#119](https://github.com/txpipe-shop/thoth/issues/119), part of
the map [#117](https://github.com/txpipe-shop/thoth/issues/117).

**Question.** What do Midnight City's terms, docs and public statements say
about automated reads of the observer API, and about third parties paying
rewards for in-game progress?

**Method.** Read-only HTTP GETs of public pages, on **2026-10-08**. No sign-in,
no posts, no contact, no write routes. Sources are first-party: the
midnight.city site and its JavaScript bundle, `/robots.txt`, `/llms.txt`, the
`/docs` pages, the direct-control skill (`SKILL.md` and its published bundle),
and the legal pages that the City's footer links to. Quotes are verbatim.
Text marked **[inferred]** is our reading, not a statement from the source.

## Verdict

**Unclear. Leaning to "allowed for reads, risky for rewards".**

- Nothing in any City source mentions third-party rewards, bounties, sponsors
  or real-money trading. Nothing permits them and nothing forbids them.
- Automated reads of the observer are the documented use. The City publishes a
  skill and an HTTP endpoint for scripts. But two general documents pull the
  other way. `robots.txt` disallows `/observer/`. The IOG Terms of Use (the
  City's linked "Terms and conditions") ban "data mining, robots or similar
  data gathering and extraction tools", and they limit use to "personal,
  non-commercial use" unless another agreement says otherwise.
- The City states no off-game value for crystals: "crystal is City inventory,
  not NIGHT or a blockchain-wallet balance". It offers no cash-out.

## 1. Which terms apply

The site footer's "Terms and conditions" and "Privacy Policy" links point to
Input Output Global's generic documents. There is no City-specific ToS, FAQ
page or privacy policy. `/terms`, `/tos`, `/privacy` and `/faq` all return the
SPA shell.

- Bundle `https://midnight.city/assets/index-DHL20p3Z.js` (read 2026-10-08):
  ``ZR=`https://www.iog.io/terms-and-conditions` `` and
  ``QR=`https://www.iog.io/privacy-policy` ``, used as
  `{label:R(`Terms and conditions`),href:ZR,external:!0},{label:R(`Privacy Policy`),href:QR,external:!0}`.
- Skill reference `references/account-and-agent-setup.md` in
  [the skill bundle](https://midnight.city/observer/api/skill/midnight-city-direct-control.zip)
  (read 2026-10-08): "Have authority from the account owner to accept the
  [terms](https://www.iog.io/terms-and-conditions) and
  [privacy policy](https://www.iog.io/privacy-policy). Read them before signup."
- [Create an Agent](https://midnight.city/docs/create-your-agent) (read
  2026-10-08): "Read the terms and privacy policy before registration."
- [IOG Terms of Use](https://www.iog.io/terms-and-conditions), "Last Updated:
  January 30, 2025" (read 2026-10-08). Its scope covers "all of the related
  websites, mobile apps, products and services offered by IOG and its
  affiliated entities … (collectively, the "Products")". It also allows that
  "Specific terms and conditions may apply to specific content, products …
  such specific terms will supersede these Terms."
- **[inferred]** Midnight City is presented as an IOG product. The talks list
  IOG staff, for example "JJ Siler, VP of Commercial, IOG"
  ([Consensus Miami: AI Agents Unleashed](https://midnight.city/docs/media/consensus-miami-ai-agents-unleashed)).
  So the IOG Terms are the operative terms. Where the City docs and skill are
  more specific, they may count as the "specific terms" that supersede them.

## 2. Automated access, rate limits and scraping

### Against

- [`https://midnight.city/robots.txt`](https://midnight.city/robots.txt) (read
  2026-10-08):

  ```
  User-agent: *
  Allow: /

  Disallow: /api/
  Disallow: /observer/
  Disallow: /coordinator/
  Disallow: /admin/
  ```

  **[inferred]** robots.txt addresses crawlers, not API clients the site
  invites. It still signals that the operator does not want `/observer/`
  crawled.
- [IOG Terms of Use](https://www.iog.io/terms-and-conditions) §3(c)
  "Restrictions" (read 2026-10-08): "You are expressly prohibited from (i) any
  use of data mining, robots or similar data gathering and extraction tools in
  your use of the Products and (ii) using the Products or Our Content and
  Materials to train any artificial intelligence, machine learning, large
  language models or other similar neural networks, algorithms or systems."
- Same document, §3(b): "Except as expressly agreed to otherwise by us (such
  as your entering into another other agreement with us), your use of the
  Products must be limited to personal, non-commercial use. We may terminate
  this license at any time for any reason."
- Same document, §1: "We reserve the right to terminate or restrict access to
  the Products (including any accounts you may have created through your use
  of the Products) for any reason whatsoever at our sole discretion."

### For: scripted reads are the documented use

- [`SKILL.md`](https://midnight.city/observer/api/skill/SKILL.md), version
  `2026-10-07T01:51:50Z` (read 2026-10-08): "This skill uses the public
  observer API. The observer serves read-only world context directly and
  forwards control/actions internally to the private coordinator".
- [Hermes or OpenClaw guide](https://midnight.city/docs/connect-to-midnight-city/hermes-openclaw)
  (read 2026-10-08), "Public toplists": "The leaderboard read needs only
  MCITY_OBSERVER_URL. It does not need an API token or a control session …
  The public HTTP endpoint is:
  `GET https://midnight.city/observer/api/leaderboards?board=combat&agentIds=<agentId>`".
  It also says: "Rankings refresh in the background about once a minute; new
  XP may not appear immediately."
- Same guide: "Custom clients use these public endpoints. Prefix each path
  with /observer on the production site."
- [Local Model](https://midnight.city/docs/connect-to-midnight-city/local-ai)
  (read 2026-10-08) lists "observer world-state reads" among the data that
  crosses the network for a self-hosted agent.
- [Overview](https://midnight.city/docs/overview) (read 2026-10-08): "Use live
  capability data when you control an agent."

### Rate limits and polling etiquette

There is no published numeric rate limit for observer reads. The stated limits
are per-action or per-flow:

- `SKILL.md` §Messaging: "If rate limited, read `retryAfterMs` in the matching
  `recent-events` entry and wait at least that many milliseconds … Do not
  retry in a loop, switch recipients, or reconnect to evade the wait."
- `SKILL.md` §Rules: "Never discover routes by guessing production URLs." Also:
  "do not probe guessed routes such as `/api/agents` on the site root."
- [First Night](https://midnight.city/docs/connect-to-midnight-city/first-night)
  (read 2026-10-08), on email activation: the AI "must not repeatedly
  register, poll, or ask the human to copy a code."
- `references/account-and-agent-setup.md`: activation "protects the City from
  automated account farms".
- [Hosted](https://midnight.city/docs/connect-to-midnight-city/hosted) (read
  2026-10-08): "An agent can create one group per hour."
- [Economy and Needs](https://midnight.city/docs/gameplay/economy-and-needs)
  (read 2026-10-08): "City rules allow one outgoing crystal transfer from a
  sender in one tick."

**[inferred]** A low-rate script that reads the public observer endpoints is
consistent with the docs. It follows the skill's no-route-guessing rule if it
uses only documented routes, and the leaderboard snapshots refresh about once
a minute anyway. A bulk crawler is what robots.txt and the IOG §3(c) clause
target. The IOG clause is broad enough to cover a scripted reader too, so it
is the main residual risk.

## 3. Real-money trading, cash-outs and third-party rewards

No source mentions third parties paying rewards for in-game progress. That
covers bounties, sponsors, prizes, tournaments, real-money trading (RMT) and
cash-out. We searched the docs (every page in the `/docs/sitemap.xml`), the
skill bundle, the site bundle's UI strings and the five media transcripts.
Nothing allows or forbids it.

What the sources do say:

- Crystal transfers between agents are a first-party feature, capped per
  owner. [Economy and Needs](https://midnight.city/docs/gameplay/economy-and-needs):
  "The default send limit is 100 crystals per agent over the last seven
  days … Unlimited transfers are not supported." `SKILL.md`: "Each crystal
  send limit change requires direct human approval of the exact agent and new
  numeric limit. Never change this limit autonomously."
- The IOG Terms §2(e) let IOG remove user content that "Reproduces,
  duplicates, copies, sells, resells or otherwise exploits for any commercial
  purposes any portion of, use of or access to the Products". §3(b) limits use
  to "personal, non-commercial use" unless agreed otherwise.
- The IOG Terms §4 cover "Third-Party Services". IOG "assume[s] no
  responsibility for, nor do[es] [it] endorse or verify the content, offerings
  or conduct of, Third-Party Services or any third parties".
- The marketing promises earning, but only inside the game. The bundle
  `index-DHL20p3Z.js` has "A persistent world where AI heroes live, work,
  fight, and earn 24/7. Soon, your agent holds its own wallet to trade, pay,
  and earn on your behalf." It also has "Love a good challenge? Your agents
  can earn achievements, compete in wood cutting skills or become the richest
  agent."
- The home-page leaderboard mock-up in the bundle gives the top three ranks
  crystal rewards: `{rank:1,…,reward:150},{rank:2,…,reward:100},{rank:3,…,reward:50}`,
  with the asset `leaderboardRewardCrystal`. **[inferred]** This is
  illustrative marketing data: the names "Aelion", "Lysante" and "Cypher" are
  hard-coded. It hints that the City may run first-party leaderboard rewards
  in crystals. No doc describes such a programme.
- The bundle has a "Founders pack" section: Settler, Pioneer and Founder
  packs, "BUY SETTLER", "for in-game purchases", "Governance voting rights".
  [Create an Agent](https://midnight.city/docs/create-your-agent): "Paid
  activation exists, but payment setup is outside this guide." **[inferred]**
  Money flows from players to the City. No source describes money flowing
  back out.

**[inferred]** A third-party Bounty paying real tNIGHT is not addressed
anywhere. Two things could catch it. First, IOG's "personal, non-commercial
use" licence, if the Bounty is commercial; a testnet-token experiment is
arguably not. Second, the robots/data-mining clause, for the reads that
measure progress. A Bounty also never moves in-game items or crystals out of
the City, so the in-game economy rules above do not bind it.

## 4. Agent data: ownership and public chats

- [IOG Terms](https://www.iog.io/terms-and-conditions) §2(c): "you or your
  licensors … retain ownership of any and all copyrights in Your Content". §2(b)
  grants IOG "a non-exclusive, perpetual, irrevocable, transferable,
  royalty-free … worldwide license … to use, reproduce … publicly display …
  Your Content".
- §3(e): "You acknowledge that you do not acquire any ownership rights by
  using or interacting with the Products." **[inferred]** That covers in-game
  state such as XP, items and crystals.
- [Hosted](https://midnight.city/docs/connect-to-midnight-city/hosted):
  "You own this document and can read its contents" (the agent's SOUL.md). Also
  "USER and MEMORY bodies stay out of prompts that produce public speech." And
  "'Discuss dogs and cats' starts a conversation in the city … To keep the
  conversation private, say 'Explain dogs and cats to me' or 'Talk with me
  here in this chat.'" So in-city conversations are public, and owner chat is
  private.
- [What Is Midnight City?](https://midnight.city/docs/whats-midnight-city)
  (read 2026-10-08): "The project makes agent activity visible as a city. You
  can observe agents, read their public activity, and inspect the state of the
  world."
- [Create an Agent](https://midnight.city/docs/create-your-agent): "Review
  the public profile … Do not put passwords, private keys, or sensitive
  personal data in the public agent profile."
- [Local Model](https://midnight.city/docs/connect-to-midnight-city/local-ai):
  "Do not put secrets in agent speech or public action fields."
- Group names and descriptions "are public"
  ([Hosted](https://midnight.city/docs/connect-to-midnight-city/hosted)).
- [Release notes](https://midnight.city/docs/release-notes), July 27-29, 2026:
  "Improved agent pages, public message access".
- The site FAQ (bundle strings): "Your agent's economic activity stays private
  unless you choose to share it." **[inferred]** This refers to on-chain
  transactions, not to City world state. Leaderboards, including `richest`,
  are public.
- The skill's `threads` and `thread` reads send the API token
  (`mcity-control.mjs`, `authHeaders(config.apiToken)`). We did not check
  whether those routes also answer without a token.

## 5. Stated off-game value of crystals and items

There is none. Every statement keeps crystals inside the game:

- [What Is Midnight City?](https://midnight.city/docs/whats-midnight-city):
  "The game inventory and a blockchain wallet are different systems. For
  example, crystal is an in-game item. A crystal transfer does not send NIGHT
  and does not use DUST."
- [First Night](https://midnight.city/docs/connect-to-midnight-city/first-night):
  "crystal is City inventory, not NIGHT or a blockchain-wallet balance."
- [Economy and Needs](https://midnight.city/docs/gameplay/economy-and-needs):
  "`crystal` is an in-game inventory item. Agents can earn or spend it through
  merchant offers and other game content." Also: "Some merchant actions use a
  wallet-backed settlement service. These actions are not the same as an
  in-city item trade."
- `SKILL.md` §Agent-to-Agent Crystal Transfers: "This command moves the
  virtual `crystal` item. It does not send NIGHT, use a wallet, use DUST, or
  trade with a merchant." §Resource Work: a crypto terminal "grants virtual
  `meme_coin`".
- [Release notes](https://midnight.city/docs/release-notes), September 7,
  2026: "USDM ATM … The ATM does not connect a wallet or execute withdrawals,
  swaps, or bridging." September 1-2, 2026: "Moved agent-wallet integrations
  to the Midnight Preview and Cardano Preprod test networks."
- [Consensus Miami: AI Agents Unleashed](https://midnight.city/docs/media/consensus-miami-ai-agents-unleashed)
  (May 6, 2026, JJ Siler of IOG): "crystals are a way, in the near term, to
  reward these agents for doing some amount of work. They go out, they
  participate in the economy. All that information is represented as
  transactions on Midnight in this L2 environment." The docs also warn: "Media
  transcripts describe the project direction at the time of each recording"
  ([What Is Midnight City?](https://midnight.city/docs/whats-midnight-city)).

## 6. Developer, partner or API programme, and contact routes

- There is no formal developer or partner programme. The API offer is the
  Own-AI path: an account API key plus the direct-control skill
  ([Create an Agent](https://midnight.city/docs/create-your-agent):
  "Direct control needs an approved, spawned agent and an active account API
  key"). The May 6, 2026 talk said: "We'll give you an API key and we'll give
  you the necessary skills to spawn your own computation inference into the
  city."
- [`llms.txt`](https://midnight.city/llms.txt) (read 2026-10-08): the
  "documentation explains how to create agents, connect external AI
  frameworks, and use city APIs."
- "Partner Plaza" appears as a place name in the bundle. No programme is
  attached to it.
- Contact routes, which we did not use: the site FAQ's "hop into our community
  Discord — usually answered in under five minutes", linked as
  `https://discord.com/invite/midnightnetwork` in the bundle. The IOG Terms
  route disputes and feedback to `https://iohk.io/en/contact`. The Hosted
  guide says "ask the project team to pause supervision" but gives no address.

## Open points

- Whether the City considers a scripted, low-rate observer reader (for
  example, attestors' zkFetch of the leaderboard or `claimable`) a "robot"
  under IOG §3(c). Only the City team could settle that, and the map decided
  not to ask ([#124](https://github.com/txpipe-shop/thoth/issues/124)).
- Whether "Specific terms" (the City docs and skill) supersede IOG §3(c) for
  documented observer routes. This is a legal reading, not a fact.
- Whether `threads` and `thread` transcripts are readable without a token.

## Sources (all read 2026-10-08)

- https://midnight.city/ and bundle https://midnight.city/assets/index-DHL20p3Z.js
- https://midnight.city/robots.txt
- https://midnight.city/llms.txt
- https://midnight.city/observer/api/skill/SKILL.md (version `2026-10-07T01:51:50Z`)
- https://midnight.city/observer/api/skill/midnight-city-direct-control.zip (`references/*.md`, `scripts/mcity-control.mjs`)
- https://midnight.city/docs/overview
- https://midnight.city/docs/whats-midnight-city
- https://midnight.city/docs/create-your-agent
- https://midnight.city/docs/connect-to-midnight-city/ , `/first-night`, `/hosted`, `/local-ai`, `/hermes-openclaw`
- https://midnight.city/docs/gameplay/economy-and-needs
- https://midnight.city/docs/release-notes
- https://midnight.city/docs/media/ (five transcripts)
- https://www.iog.io/terms-and-conditions (Last Updated January 30, 2025)
- https://www.iog.io/privacy-policy (Last updated September 6, 2023)
