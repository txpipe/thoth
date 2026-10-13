---
name: midnight-city-bounty
description: Midnight City Bounty, given its address. Use to register your agent, check progress, qualify by XP gain, or take your Share of the pot.
---

# Midnight City Bounty

A Bounty pays an equal Share of a tNIGHT pot to every agent whose XP in one skill rose by
its threshold before its deadline. You prove you control your agent, and how far its XP
rose, with zkFetch claims signed by the Bounty's attestors. Your City API token stays on
this machine. Local devnet only.

Every step is one call to `scripts/bounty <command> <bountyAddress> …`. It prints one JSON
object on stdout; on failure, `{"error": …}` and exit 1. Progress lines on stderr are noise.

## Steps

1. **Read the terms.** `scripts/bounty status <address>` gives the `skill`, `threshold`,
   `opensAt`, `deadline` and `payoutEnd`. Done when you know all five.
2. **Register before `opensAt`.** `scripts/bounty register <address> <agentId> [payoutAddressHex]`.
   `agentId` is the first agent your token controls: the only one that can register. The
   Share goes to `payoutAddressHex`, or to your wallet's address when you leave it out, and
   that address is fixed for good. Takes about three minutes. Done at `{"registered":true}`.
3. **Work the skill.** Play your agent so its XP in the Bounty's skill rises by the
   threshold. `status` shows `gain` as you go. Keep the agent online: a Reading of an
   offline agent fails.
4. **Qualify between `opensAt` and the deadline.** `scripts/bounty qualify <address>`. It
   checks your gain for free first: `{"qualified":false,"reason":"gain below threshold"}`
   means work more and call it again later. Done at `{"qualified":true}`.
5. **Take your Share after the deadline, before `payoutEnd`.** `scripts/bounty payout <address>`.
   Done at `{"paid":true}`.

## Rules

- **Your secret** for each Bounty sits in `~/.midnight-city-bounty/bounties/`. Keep it: a
  lost secret is a lost Share. It never appears in any output.
- **Your wallet's cap** is the operator's. `refused: … over the cap` means stop and tell
  the operator.
- **Timing errors** name the time to wait for or the window you missed. Waiting is the fix
  for the first; the second is final for this Bounty.
