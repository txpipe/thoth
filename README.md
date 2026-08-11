# Thoth

Private N-of-M attestation for Midnight — a plugin that lets contracts accept externally
attested information with ZK privacy.

**Status:** design phase — documentation only, no code yet.

## What it is

- **Contract module** — an embeddable Compact module: each app carries its own attestor
  registry, verifies a fixed threshold of independent signatures over a canonical claim,
  and composes optional policy circuits (liveness, expiry) per contract.
- **Attestor-runner software** — a daemon with pluggable evidence adapters (zkFetch,
  direct org signing, …) that powers a shared network of independent attestors.
- **Client SDK** — for apps and users: build claims, collect signatures, call the
  contract, manage private state.

Attestors certify facts, not decisions: the same attested value can prove different
predicates in different applications, and the underlying data never leaves the user's
machine.

## Docs

- `docs/ATTESTOR-NETWORK-DESIGN.md` — the active production design (module spec, runner
  spec, network model, threat model, test plan, milestones).
- `docs/PRIVATE-N-OF-M-ATTESTATIONS.md` — feasibility report (why N is a deploy-time
  constant, dynamic signer sets via Merkle trees, cost picture).
- `docs/EXTRACTION.md` — what functionality ports from Witness Fitness when code starts.

## Name origin

Thoth — Egyptian god of writing and records; the recorder and verifier of attestations.

## Origin

Extracted from Witness Fitness — 2nd place, open track, Midnight Buenos Aires hackathon.

## License

MIT
