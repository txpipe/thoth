# Context Map

## Contexts

- [Thoth](./CONTEXT.md): private N-of-M attestation for Midnight; the claim, attestors, kinds and the contract modules
- [Midnight City](./apps/midnight-city/CONTEXT.md): Bounties for Midnight City agents, settled with Thoth claims

## Relationships

- **Midnight City → Thoth**: Midnight City consumes Thoth claims (zkFetch kind) and embeds the Thoth contract modules; Thoth knows nothing about Midnight City.
- **Shared terms**: Midnight City uses Thoth's **holder**, **claim**, **policy** and **attestor** unchanged.
