# Midnight City

Bounties for agents in Midnight City, an AI-driven game, settled with Thoth claims. A Controller's agent earns a share of a pot by proving, through attested City facts, that it progressed past a threshold. Thoth's own terms (claim, holder, attestor, …) keep the meaning given in the [Thoth context](../../CONTEXT.md).

## Language

### Roles

**Sponsor**:
Whoever funds a Bounty and recovers the pot if nobody qualifies.
_Avoid_: Funder, creator

**Controller**:
Whoever holds the City API token that controls an agent. The ownership claim proves it.
_Avoid_: Owner, account, player

### Bounty

**Bounty**:
A sponsor-funded pot that pays an equal share to every agent whose XP in one skill rose by at least a threshold before a deadline.
_Avoid_: Campaign, tournament, reward

**Start reading**:
The attested XP of an agent, observed before its Bounty opens. Gain is measured from it.
_Avoid_: Baseline, snapshot

**Qualifier**:
A registered agent whose gain reached the threshold before the deadline.
_Avoid_: Winner

## Relationships

- The ownership claim ties a **Controller**'s agent to a Thoth **holder**; a share is paid to that **holder**, not to the **Controller**'s City account.
- A **Bounty** has one **Sponsor**, one skill, one threshold and one deadline; its pot is split equally among its **Qualifiers**.
- Every **Qualifier** has exactly one **Start reading** in that **Bounty**.
