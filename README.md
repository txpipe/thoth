# Thoth

Private N-of-M attestation for Midnight.

Thoth is a plugin layer that lets Midnight contracts accept externally attested
information with ZK privacy: the same attested value can prove different
predicates, and the underlying data never leaves the user's machine.

## What it is

Three pieces:

- **Contract module**: An embeddable Compact module set: each app
  carries its own pinned attestor registry, verifies a fixed threshold of
  independent signatures over a canonical claim, and composes optional policy
  circuits (freshness) per contract.
- **Attestor SDK**: A library that provides the types and functions that
  attestors need to provide the service. Includes different packages to adapt
  for different sources and types of attestation (zkFetch, price band, …)
  It powers a shared network of independent attestors.
- **Client SDK**: For apps and users: build claims, collect
  signatures, call the contract, manage private state.

## How it works

1. The client obtains **evidence** from a data source — e.g. a third-party API
   via Reclaim Protocol's ZkFetch, producing a zero-knowledge proof that the
   connection took place and the data wasn't forged.
2. The client sends that evidence to the attestors in its app's trusted set.
   Each attestor verifies it and **signs a canonical claim** derived from it
   with its own key — its signature is the attestation.
3. The client submits the claim with N signatures to the Midnight contract as
   **private witness data**. The contract verifies, in zero knowledge: each
   signature is valid and from a **distinct** attestor in the app's pinned
   registry; the nonce hasn't been reused (no replay); and optionally that the
   claim is fresh within the app's configured time window.
4. Only if those checks pass does the app's **predicate** run over the claim
   values. Claim values are never stored on-chain — only their commitments and
   the predicate outcome — and, depending on the app's configuration, which
   attestors vouched may be hidden too.

Attestors certify facts: a claim is a canonical statement of what
was observed, and the application defines the predicate over it.

## Repository layout

```
thoth/
├── packages/                   # @thoth/* npm workspace packages
│   ├── attestor/              # @thoth/attestor — host: key boundary, instances, helpers
│   ├── client/                # @thoth/client — dApp-side seam: TrustedSet, transport, primitives
│   ├── contracts/             # @thoth/contracts — Compact on-chain modules
│   │   ├── attestation.compact     # N-of-M verification, replay/freshness control, claims vault
│   │   ├── attestor_registry.compact  # pinned attestor keys + signature counting
│   │   ├── examples/example_app.compact  # 2-of-3 example embedding
│   │   ├── test/                   # simulator tests + helpers
│   │   └── README.md               # how to embed the modules in your own contract
│   ├── core/                  # @thoth/core — keyless claim/envelope types
│   └── zk-tls/                # @thoth/zk-tls — zkFetch kind: shared logic + attestor + client
├── docs/DESIGN.md              # design overview & decisions
├── tsconfig.base.json          # shared TypeScript compiler options for all packages
└── package.json                # repo root: npm workspace + shared scripts, CI
```

The repo is an npm workspace monorepo: the active `@thoth/*` packages — `core`,
`attestor`, `client`, `contracts`, and `zk-tls` — live under `packages/` and are
wired into the root `workspaces`.

## The contracts

Two embeddable Compact modules plus a top-level example (`packages/contracts/README.md`):

| File | Module | Role |
|------|--------|------|
| `attestation.compact` | `attestation<#K, #V, #N, #M>` | Verifies N-of-M signatures over a flat signed message, controls replay (`nullifiers`) and freshness (`freshnessWindow`), stores a `claimsVault` entry keyed by `persistentCommit(claim, rand)` |
| `attestor_registry.compact` | `attestor_registry<#M, #K>` | Pinned attestor public keys (sealed) + `countValidSignatures` via the stdlib `jubjubSchnorrVerify` — counts only, no threshold |
| `examples/example_app.compact` | top-level | Example app embedding `Attestation<13, 3, 2, 3>` (2-of-3) |

## Development

Requirements: Node.js 24 (`.nvmrc`), the Compact CLI (compiler 0.34.0).

```bash
npm install
npm test          # compiles the mock contract, then runs vitest
npm run check     # biome format/lint + compact format check
```

CI (`.github/workflows/`) runs compact compilation, type checks (`npm run types`),
vitest, and biome on every push/PR.

## Docs

- `docs/DESIGN.md` — design overview
- `AGENTS.md` — guide for AI coding agents working in this repo
- `packages/core/README.md` — the keyless internal law (`@thoth/core/claim`)
- `packages/attestor/README.md` — the host: key boundary, instances, helpers
- `packages/client/README.md` — the dApp-side base: trusted set, transport, resolution
- `packages/contracts/README.md` — the on-chain Compact modules: semantics, module parameters, deploy wiring
- `packages/zk-tls/README.md` — the concrete zkFetch kind: shared logic, attestor, client

## Name origin

Thoth — Egyptian god of writing and records; the recorder and verifier of attestations.

## Origin

Extracted from Witness Fitness — 2nd place, open track, Midnight Buenos Aires hackathon.

## License

MIT