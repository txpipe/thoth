# Midnight City Bounty (prototype)

A Bounty as a Compact contract on the Thoth modules, run in the simulator, for
[#122](https://github.com/txpipe-shop/thoth/issues/122). It's a proof of concept
and won't be merged. The terms are in [`../CONTEXT.md`](../CONTEXT.md).

```sh
npm test   # compiles src/bounty.compact with compact +0.34.0 --skip-zk, then runs vitest
```

## Flow

```text
deploy     Sponsor seals: attestor keys, Control and Reading policies, threshold,
           opensAt, deadline, end of the Payout period, Sponsor address
fund       anyone adds tNIGHT to the pot, until the deadline
verifyAttestation   a holder vaults each claim (Thoth's module entry point)
register   Control claim + Start reading, same agent, same holder; commits to the payout
             address as a leaf, hash(secret, address) · Start reading observed by opensAt
             · one Registration per agent
qualify    a Reading under the Registration's holder, observed between opensAt and the
             deadline and submitted before it, with XP ≥ Start reading + threshold;
             adds the Registration's payout leaf to the Qualifiers' Merkle tree
payout     the holder, during the Payout period, naming only an address and the Share:
             proves its leaf is in the tree without saying which, spends a nullifier
             from its secret, and gets the pot split equally, rounded down
refund     after the Payout period, or after the deadline if nobody qualified:
             what's left goes to the Sponsor, once
```

## Payout privacy

Which agents registered and qualified is public. Who gets paid isn't linked to
them: the Registration holds only a leaf that hides the address, and a Payout
proves *some* leaf in the Qualifiers' tree is the caller's. It reveals the
address and a nullifier, and neither links to a leaf without the secret. The
address is bound into the leaf, so a stolen secret can't redirect a Share, and
the circuit checks that the Merkle path proves the caller's own leaf, or another
Qualifier's path would pay anyone.

Shares are equal and the tree is closed at the deadline, before the first
Payout, so neither the amount nor the timing points back to an agent. What's
left:

- **The anonymity set is the Qualifiers.** With two, a guess is right half the
  time; with one, nothing is hidden.
- **The address must be fresh.** A reused address, or one funded from the
  Controller's other addresses, links back through its own history.
- **The fee payer** of a Payout transaction might link it to the Controller's
  wallet. That's not checked yet.
- **The Share is unshielded tNIGHT**, so the address and amount are visible.
  Hiding them too would need a shielded token.

## Rules

Each claim must be under its own policy. The Control claim and Readings both
carry the agent ID, and anyone can take a Reading of any agent, so only the
Control policy proves control.

## Proof-of-concept choices

- **Agent ID.** The claim slots are numeric until #26 lands, so the ID after
  `user-agent-` (up to 36 characters) goes in slots 1–5, 8 characters each,
  through zk-tls's `bytes8` parse rule. Slot 0 is a Reading's XP.
  `agentKeyOf` is the only circuit that reads the ID; #26's byte slots change
  only that circuit.
- **The pot** is unshielded tNIGHT (`receiveUnshielded` and `sendUnshielded`
  with `nativeToken()`). The simulator doesn't enforce the contract's balance,
  so the contract keeps its own accounting (`pot`, `paidOut`).
- **Shares.** Compact has no division. The caller names the Share, and the
  circuit checks `share × qualifiers ≤ pot < (share + 1) × qualifiers`.
  Qualifying closes at the deadline and funding stops then, so every Payout
  splits the same pot between the same count.
- **The Qualifiers' tree** is a `HistoricMerkleTree` of depth 10, so a Bounty
  takes at most 1,024 Qualifiers.
- **One witness, several claims.** `openClaim` reads the module's single claim
  witness, so the test driver queues claims in private state, and each call
  takes the next one. Registration opens two.

## Recorded data

`test/recorded.test.ts` runs the Controller's agent's real Control claim and
Reading, from `../fixtures/`, through two zkFetch attestors and the client into
the Bounty: the agent registers, linked across the two claims by its recorded
ID, and the recorded Reading is refused as a Control claim. Each attestor trusts
the witness that recorded its evidence. Re-record with the two spikes
(`../spike-ownership`, `../spike-xp`); their regexes split the ID into the five
groups the policies read.

## Open gaps

- **#112.** A claim's window is chosen by the client, so one observation can be
  vaulted again under another window. That doesn't help here, because each
  agent registers once and qualifies once.
- **#134** (the holder isn't bound to the evidence) and **#113** (the disclosure
  regex isn't bound to the policy) are assumed fixed.
- **Late Registration** isn't blocked: an agent can register after `opensAt`
  with a Start reading taken before it. It only shortens its own time.
