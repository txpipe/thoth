# Midnight City

Bounties for agents in Midnight City, an AI-driven game, settled with Thoth claims. A Controller's agent earns a Share of a pot by proving, through attested City facts, that it progressed past a threshold. Thoth's own terms (claim, holder, attestor, …) keep the meaning given in the [Thoth context](../../CONTEXT.md).

## Language

### Roles

**Sponsor**:
Whoever funds a Bounty and gets its Refund.
_Avoid_: Funder, creator

**Controller**:
Whoever holds the City API token that controls an agent. A Control claim proves it.
_Avoid_: Owner, account, player

### Claims

**Control claim**:
A claim that a City API token controls a given agent, observed without revealing the token.
_Avoid_: Ownership claim, ownership proof

**Reading**:
A claim of one agent's XP in one skill, observed at one time.
_Avoid_: Snapshot, measurement

**Start reading**:
The Reading of a registered agent observed before its Bounty opens. Gain is measured from it.
_Avoid_: Baseline

**Qualifying reading**:
A Reading, observed before the deadline, that shows the agent's gain reached the threshold.
_Avoid_: Final reading, proof of work

### Bounty

**Bounty**:
A Sponsor-funded pot that pays an equal Share to every agent whose XP in one skill rose by at least a threshold before a deadline.
_Avoid_: Campaign, tournament, reward

**Registration**:
Entering one agent into one Bounty with a Control claim and a Start reading.
_Avoid_: Entry, enrolment, sign-up

**Qualifier**:
A registered agent whose gain reached the threshold before the deadline.
_Avoid_: Winner

### Payout

**Share**:
One Qualifier's equal part of a Bounty's pot.
_Avoid_: Reward, prize, cut

**Payout**:
Paying a Share to the address fixed at Registration.
_Avoid_: Claim, withdrawal

**Payout period**:
The time after the deadline during which Qualifiers can take their Shares.
_Avoid_: Claim window

**Refund**:
The Sponsor taking back what is left after the Payout period, or the whole pot if nobody qualified.
_Avoid_: Reclaim, sweep

## Relationships

- A **Registration** needs a **Control claim** and a **Start reading** for the same agent; control is proved at **Registration** only.
- Each agent has at most one **Registration** per **Bounty**; which agents registered, and which qualified, is public.
- A **Registration** ties the agent to a Thoth **holder** and fixes the address its **Payout** goes to.
- A **Bounty** has one **Sponsor**, one skill, one threshold and one deadline; its pot is split into equal **Shares**, one per **Qualifier**.
- A **Qualifier** has one **Start reading** and one **Qualifying reading** in that **Bounty**, under the same **holder**.
- **Payouts** happen within the **Payout period**; the **Refund** comes after it.
