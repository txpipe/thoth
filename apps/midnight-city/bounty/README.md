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
register   Control claim + Start reading, same agent, same holder; fixes the payout address
             Start reading observed by opensAt · one Registration per agent
qualify    a Reading under the Registration's holder, observed between opensAt and the
             deadline and submitted before it, with XP ≥ Start reading + threshold
payout     the holder, during the Payout period: the pot split equally, rounded down,
             sent to the address fixed at Registration, once
refund     after the Payout period, or after the deadline if nobody qualified:
             what's left goes to the Sponsor, once
```

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
- **One witness, several claims.** `openClaim` reads the module's single claim
  witness, so the test driver queues claims in private state, and each call
  takes the next one. Registration opens two.

## Open gaps

- **Payout privacy.** The payout address is public from Registration onwards,
  next to the agent. The design wants who gets paid kept private; that's still
  open on the map (#117).
- **Recorded data.** The tests use signed fixture claims, not the zkFetch
  fixtures in `../fixtures/`. Those were recorded with one `agent` group, before
  the `bytes8` split; turning them into claims (#123) means re-recording with
  the five-group regex.
- **#112.** A claim's window is chosen by the client, so one observation can be
  vaulted again under another window. That doesn't help here, because each
  agent registers once and qualifies once.
- **#134** (the holder isn't bound to the evidence) and **#113** (the disclosure
  regex isn't bound to the policy) are assumed fixed.
- **Late Registration** isn't blocked: an agent can register after `opensAt`
  with a Start reading taken before it. It only shortens its own time.
