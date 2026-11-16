# Contributing to Thoth

## Dev setup

You need:

- Node.js 24 (the version in `.nvmrc`).
- The [Compact CLI](https://github.com/midnightntwrk/compact) with compiler
  `0.36.1` (`compact update 0.36.1`).

Then, from the repo root:

```bash
npm install
npm test
```

`@midnight-ntwrk/compact-runtime` is pinned to `0.21.0` in every workspace.
Off-chain code that mirrors an in-circuit primitive matches the circuit only
at that version, so bump it everywhere at once, together with the compiler.

## Repository layout

```
thoth/
├── packages/                   # npm workspace packages
│   ├── attestor/               # @thoth/attestor: pairs a kind's law with a signing key
│   ├── cardano/                # @thoth/cardano: the cardano@1 chain-event kind (attestor, client, Dolos reader)
│   ├── client/                 # @thoth/client: trusted set, transport, attestation checks
│   ├── contracts/              # @thoth/contracts: Compact modules
│   │   ├── attestation.compact        # N-of-M verification, replay and window checks, claims vault
│   │   ├── attestor_registry.compact  # pinned attestor keys, signature counting
│   │   ├── examples/example_app.compact  # a 2-of-3 embedding
│   │   └── test/                      # simulator tests, mock contracts, helpers
│   ├── core/                   # @thoth/core: keyless claim and law types
│   └── zk-tls/                 # @thoth/zk-tls: the zkFetch kind (attestor, client, prover)
├── docs/
│   ├── DESIGN.md               # architecture, the claim and its wire order
│   ├── kind-author-guide.md    # how to add an attestor kind
│   └── adr/                    # architecture decision records
├── examples/demo-attestation/  # recorded zkFetch evidence fixture
├── CONTEXT.md                  # glossary
├── tsconfig.base.json          # shared TypeScript options
└── package.json                # workspace root and shared scripts
```

Every directory under `packages/` is one package. A package is built and
type-checked only once it is listed in the root `package.json` `workspaces`.

## Commands

Run them from the repo root:

| Command | What it does |
|---------|--------------|
| `npm test` | Compiles the mock contracts and builds the packages (`pretest`), then runs vitest |
| `npm test -- <pattern>` | The same, for the test files matching `<pattern>` |
| `npm run types` | Type-checks every package |
| `npm run check` | Biome format and lint, plus `compact format -c` |
| `npm run check:fix` | Applies the Biome and Compact formatting fixes |
| `npm run build` | Builds every package into its `dist/` |
| `npm run compact` | Compiles the mock contracts with proving keys |
| `npm run compact:no-zk` | Compiles the mock contracts without proving keys (faster) |

For one package: `npm run <script> --workspace=packages/<name>`.

Workspaces import each other through their built `dist/`. The root `build` and
`types` scripts build `core`, `attestor`, `client`, `cardano` and `zk-tls`
first; if you add a package that another workspace imports, add it to that
chain too. A stale `dist/` shows up as confusing type errors such as "Generic
type requires N type argument(s)".

`packages/zk-tls/test/live.test.ts` runs against two real witnesses and skips
unless `WITNESS_URLS` names them; see the attestor guide's
[live check](packages/zk-tls/docs/attestor-guide.md#live-check).
`packages/cardano/test/live.test.ts` runs against one real UTxO-RPC endpoint
and skips unless `DOLOS_URL` names it; see the cardano
[live check](packages/cardano/README.md#live-check).

## CI and commits

CI (`.github/workflows/`) compiles the Compact contracts and runs the type
check, vitest and Biome on every push and pull request. Locally, the
pre-commit hook runs Biome on the staged files and the Compact format check,
and the pre-push hook runs Biome, the contract compilation, the type check,
the build and vitest.

Conventions for code, comments and docs are in [AGENTS.md](AGENTS.md).
