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

CI installs the Compact CLI `0.5.3` and compiler `0.36.1` through
[`.github/actions/setup-compact`](.github/actions/setup-compact/action.yml),
which pins the CLI tarball by its SHA-256. Dependabot can't bump these pins.
To move to a new compiler, update in one change:

- the compiler version in `setup-compact` (and the CLI version and SHA-256,
  if the new compiler needs a newer CLI);
- the `+<version>` in the `compact` scripts of the root and
  `packages/contracts` `package.json`;
- this section, the contracts README and `AGENTS.md`.

## Repository layout

```
thoth/
├── packages/                   # npm workspace packages
│   ├── attestor/               # @txpipe/thoth-attestor: pairs a kind's law with a signing key
│   ├── cardano/                # @txpipe/thoth-cardano: the cardano@1 chain-event kind (attestor, client, Dolos reader)
│   ├── client/                 # @txpipe/thoth-client: trusted set, transport, attestation checks
│   ├── contracts/              # @txpipe/thoth-contracts: Compact modules
│   │   ├── attestation.compact        # N-of-M verification, replay and window checks, claims vault
│   │   ├── attestor_registry.compact  # pinned attestor keys, signature counting
│   │   ├── examples/example_app.compact  # a 2-of-3 embedding
│   │   └── test/                      # simulator tests, mock contracts, helpers
│   ├── core/                   # @txpipe/thoth-core: keyless claim and law types
│   ├── test-utils/             # @txpipe/thoth-test-utils (private): shared cross-package test helpers
│   └── zk-tls/                 # @txpipe/thoth-zk-tls: the zkFetch kind (attestor, client, prover)
├── .changeset/                 # pending changesets and their config
├── .github/                    # CI and release workflows, setup-compact action
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

### Test helpers

`packages/test-utils` (`@txpipe/thoth-test-utils`) is a private workspace
package (`"private": true`) hoisted to root `node_modules/`. Tests in any
workspace import its `.ts` subpath exports directly without listing it in any
published package's `package.json` and without a `dist/` build step.

- **Put in `packages/test-utils`**: cross-package byte and encoding primitives,
  live-suite environment parsers, kind-agnostic SDK harnesses, Jubjub test
  key-pair builders, and dependency-free fixture constants. Keep it free of
  runtime dependencies on `@txpipe/thoth-*`, Compact artifacts, Reclaim, or
  Cardano libraries.
- **Keep in package-local test helpers** (`packages/<name>/test/helpers/` or
  `test/output/fixtures.ts`): helpers tied to compiled Compact artifacts,
  `@reclaimprotocol/attestor-core`, or typed Cardano/zkFetch policies,
  observations, and claim builders.

## Commands

Run them from the repo root:

| Command                    | What it does                                                                      |
| -------------------------- | --------------------------------------------------------------------------------- |
| `npm test`                 | Compiles the mock contracts and builds the packages (`pretest`), then runs vitest |
| `npm test -- <pattern>`    | The same, for the test files matching `<pattern>`                                 |
| `npm run types`            | Type-checks `src/` and `test/` in every package                                   |
| `npm run check`            | Biome format and lint, plus `compact format -c`                                   |
| `npm run check:fix`        | Applies the Biome and Compact formatting fixes                                    |
| `npm run build`            | Builds every package into its `dist/`                                             |
| `npm run compact`          | Compiles the mock contracts with proving keys                                     |
| `npm run compact:no-zk`    | Compiles the mock contracts without proving keys (faster)                         |
| `npm run changeset`        | Adds a changeset for your change                                                  |
| `npm run changeset:status` | Lists the changesets on your branch and the bumps they make                       |

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
and skips unless `DOLOS_URL` names it; see the cardano dApp guide's
[live check](packages/cardano/docs/dapp-integration.md#live-check).

## Adding a changeset

A change that a user of `@txpipe/thoth-core`, `@txpipe/thoth-attestor`,
`@txpipe/thoth-client`, `@txpipe/thoth-zk-tls`, `@txpipe/thoth-cardano` or
`@txpipe/thoth-contracts` would notice needs a changeset, which becomes the
package's version bump and changelog entry. Add one with your pull request:

```bash
npm run changeset
```

Pick the packages you changed and the bump for each, and write the entry for
the people who use the package. While a package is below `1.0.0`, a breaking
change is a `minor` bump. Commit the file it writes to `.changeset/`. Each
package versions on its own; a package that depends on a bumped one gets a
`patch` bump.
A change with no user-facing effect, such as a test or a CI tweak, needs none.

## Releases

The [release workflow](.github/workflows/release.yml) runs on every push to
`main` and on demand from the Actions tab (`workflow_dispatch`). It builds and
tests, then:

- with changesets on `main`, opens or updates the "Version Packages" pull
  request, which bumps the versions and writes each package's `CHANGELOG.md`;
- once that pull request merges, publishes the new versions to npm through
  trusted publishing, with provenance, and tags them.

Publishing runs only from `main` and only when the repository variable
`NPM_PUBLISH` is `true`. It uses no npm token: npm trusts this repository's
`release.yml` workflow in the `npm` environment, which deploys only from
`main`. The Version Packages pull request is opened with the workflow's own
token, so CI doesn't run on it by itself; close and reopen it to run the
checks.

## CI and commits

CI (`.github/workflows/`) compiles the Compact contracts and runs the type
check, vitest and Biome on every push and pull request. Every action is pinned
to a commit SHA, with its version in a comment, and Dependabot bumps both.
Locally, the pre-commit hook runs Biome on the staged files and the Compact
format check, and the pre-push hook runs Biome, the contract compilation, the
type check, the build and vitest.

Conventions for code, comments and docs are in [AGENTS.md](AGENTS.md).
