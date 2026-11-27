# AGENTS.md

Agent-facing guide for the Thoth monorepo. Human-oriented docs live in
[`README.md`](README.md) and [`docs/DESIGN.md`](docs/DESIGN.md).

## Project overview

Thoth is a private N-of-M attestation system for Midnight. Three layers:

- **Contract layer** — `packages/contracts` (`@txpipe/thoth-contracts`):
  embeddable Compact modules that verify N-of-M signatures over a flat signed
  message (`attestation.compact`), count valid signatures against a pinned key
  vector (`attestor_registry.compact`) with the stdlib `jubjubSchnorrVerify`.
- **Attestor SDK** — `packages/attestor` + `packages/core`: the types and
  interfaces attestor kinds implement to provide attestation. Kinds verify
  evidence and sign a canonical claim. `packages/client` holds the dApp side
  (the trusted set and the attestation checks), and `packages/zk-tls` is the
  zkFetch kind. `packages/cardano` is the cardano@1 chain-event kind.

Attestors certify facts, not decisions: a claim is a canonical statement of
what was observed; the application defines the predicate over it.

Use the glossary in [`CONTEXT.md`](CONTEXT.md) for domain terms. The claim's
fields and wire order are in [`docs/DESIGN.md`](docs/DESIGN.md#the-claim). To
add an attestor kind, follow [`docs/kind-author-guide.md`](docs/kind-author-guide.md).

## Commands

Run everything from the repo root (npm workspace). The commands, dev setup
and CI are listed in [`CONTRIBUTING.md`](CONTRIBUTING.md#commands).

## Gotchas

- **Stale `dist/`**: workspaces import each other through their built
  `dist/`, so a new workspace dependency joins the root build-first chain. See
  [`CONTRIBUTING.md`](CONTRIBUTING.md#commands) for the chain and the errors a
  stale `dist/` causes.

## Repository layout

See [`CONTRIBUTING.md`](CONTRIBUTING.md#repository-layout). In addition,
`docs/agents/` holds the agent skill configuration and `AGENTS.md` is this
file.

## Package invariants

- **One package per directory** under `packages/`. A new package you want
  built goes into the root `workspaces` array; a directory left out of it is a
  placeholder and is not compiled
  ([`CONTRIBUTING.md`](CONTRIBUTING.md#repository-layout)).
- **`@midnight-ntwrk/compact-runtime` stays pinned to `0.21.0`** in every
  workspace, with Compact compiler `0.36.1`. Never bump one workspace alone;
  [`CONTRIBUTING.md`](CONTRIBUTING.md#dev-setup) says why and lists every
  place the compiler is pinned.
- **Claim types are keyless.** `@txpipe/thoth-core` carries no signing key;
  anything that commits to a message delegates to the kind's `message()`. Keep
  it that way.
- **Published packages carry a changeset.** A user-facing change to `core`,
  `attestor`, `client`, `zk-tls`, `cardano` or `contracts` adds one
  (`npm run changeset`); internal dependencies between them use a `^` range,
  never `*`, which changesets would publish as is
  ([`CONTRIBUTING.md`](CONTRIBUTING.md#adding-a-changeset)).
- **`registryIndex` is positional and app-owned.** `attestor_registry.compact`
  verifies signatures positionally (`signatures[i]` against `keys[i]`). The slot
  lives only on the client's `TrustedSet` member (`{ attestor, registryIndex }`,
  bounded by the registry's `registrySize`), never on `Attestor` or
  `AttestorDescriptor`. Never order signatures by anything other than that slot.

## Code conventions

- **TypeScript**: strict mode, `module: nodenext` + `moduleResolution:
  nodenext`, `verbatimModuleSyntax` (use `import type` for type-only imports),
  `erasableSyntaxOnly`, `noUncheckedIndexedAccess`, `rewriteRelativeImportExtensions`
  (import from `./claim.js`, not `./claim`). Shared config in
  `tsconfig.base.json`.
- **Biome** is the formatter/linter (`biome.json`). Notable rules:
  - `noBarrelFile` / `noReExportAll` are errors (except `*.config.*`). Never add
    `export *` barrels; use subpath exports instead (see
    `@txpipe/thoth-core/claim`).
  - `noUnusedImports`, `noUnusedVariables`, `useErrorMessage` are errors.
  - 100-column line width, single quotes, semicolons.
- **Compact**: `pragma language_version >= 0.22`; follow the style in
  `packages/contracts/*.compact`; module params are uppercase (`<#K, #V, #N, #M>`).
  A module header (`attestation.compact`, `attestor_registry.compact`) covers
  purpose, the wire layout (`attestation.compact` only) and the module
  parameters, and skips prose that restates the asserts below it. A top-level
  Compact file (examples, mocks) gets a 1–2 line `//` header.
  The claim's `version` stays `1` until a layout is deployed; pre-launch,
  change the wire layout freely and keep `version = 1`.
- **The wire layout is written out in exactly two places**: the
  `attestation.compact` header (canonical, next to `buildMessage`) and the
  table in `docs/DESIGN.md` (the reader's view). `claimToMessage`, the `#K`
  doc, `buildMessage`'s doc and `CONTEXT.md` link to them instead of restating
  it. A layout change edits both places in the same PR.
- **JSDoc is the API reference** (there is no generated site): it is what
  callers see on hover and in the shipped `.d.ts`. Every export gets a summary
  sentence; interface fields and simple types can stop there. `@throws` on
  every function that can throw, naming the error type when there is one.
  `@param` only when it adds what the type can't: units (claim windows are
  Unix seconds), ranges, valid values, ownership. `@returns` and `@typeParam`
  only when not obvious from the name and signature. `@example` on each
  package's main entry points (`defineAttestor`, `buildAttestor`,
  `buildTrustedSet`, `zkFetchProver`). Block comments `/** … */`; a TypeScript
  file header is 1–2 `//` lines.
- **Comments explain why**: invariants, security reasons, non-obvious
  constraints. The code says what. History, ticket and PR numbers stay out of
  source, and so do ADR citations: a comment states the reason itself, and
  docs link the ADR.

## Docs conventions

Who reads what:

| Doc                                                   | Reader                                              | Contains                                                                                           |
| ----------------------------------------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `README.md`                                           | someone evaluating Thoth                            | what it is, status, how it works, which package to use, the demo, roadmap links                    |
| `packages/*/README.md`                                | a developer using that package (it is the npm page) | the package README template below                                                                  |
| `docs/kind-author-guide.md`, `packages/zk-tls/docs/*` | a developer building a kind or integrating a dApp   | step-by-step guides                                                                                |
| `docs/DESIGN.md`                                      | anyone who wants the architecture                   | overview, the claim and its wire order, flow, out of scope; links the ADRs and never restates them |
| `docs/adr/`                                           | maintainers                                         | one decision each with its full reasoning; the only place for history and ticket references        |
| `CONTEXT.md`                                          | everyone                                            | the glossary                                                                                       |
| `CONTRIBUTING.md`                                     | contributors                                        | dev setup, repo layout, commands                                                                   |
| `AGENTS.md`                                           | coding agents                                       | the rules agents follow here; links to the docs above for everything else                          |
| source comments                                       | someone reading the code                            | why: invariants, security reasons, non-obvious constraints                                         |

Voice, for every doc and comment:

- Write to the reader as "you", in the present tense, one idea per sentence.
  Prefer a code example to a paragraph.
- Say what the code does today. History ("previously", "no longer", "we
  changed"), review notes and issue/PR numbers belong only in ADRs. A check or
  feature is documented once it lands.
- One term per concept, from `CONTEXT.md`; define or link a domain term on its
  first use in each README. Internal shorthand that is not in the glossary
  becomes plain words or a glossary entry.
- Spellings: `dApp`, `zkFetch`; `zk-tls` only as the package name.
- Bold only as the lead-in of a list item; no emphasis mid-sentence.
- One explanation, one place: explain a concept where it is owned and link to
  it from everywhere else.

Package README template, headings in this order (skip a section only if it
would be empty):

1. `# @txpipe/thoth-<name>`, then one sentence saying what it is and who it's
   for.
2. The status line, identical in every README and the root:
   > **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.
3. `## Install`: how to install or use it today. A package with an npm name
   gives it (`@txpipe/thoth-<name>`), plus one line saying whether it is
   published yet; a private package skips both.
4. `## Usage`: the shortest working example of the main task. For `core`,
   `attestor` and `client` the reader is a kind author, so the example is from
   their side.
5. `## Concepts`: only the terms needed to use the package, each linked to
   `CONTEXT.md`.
6. `## Guarantees and limits`: what the package checks, what it doesn't, and
   what the app must do itself.
7. `## Design decisions`: each entry is a bold one-line decision, then 1–3
   sentences on what it means for the reader, then the ADR link when there is
   one. Open questions become issues, not README text.
8. `## Links`

Where decisions live: a decision that changes how you use a package goes in
that package's "Design decisions", written as its consequence for the reader.
A decision that spans packages is an ADR in `docs/adr/`, linked from every
README it affects. A decision that is local to one package and has no ADR
lives only in that package's README. `docs/kind-author-guide.md` spans packages:
update it when an interface a kind implements changes (`@txpipe/thoth-core`,
`@txpipe/thoth-attestor`, `@txpipe/thoth-client`, or the claim).

The roadmap lives in GitHub: the `v0` and `Next` milestones and the `frozen`
label. The root README's Roadmap section only links those three; package
READMEs don't repeat it.

## Testing

- Contract logic is tested with the simulator via vitest in
  `packages/contracts/test/`. The mock top-level shells
  (`packages/contracts/test/mocks/MockAttestation.compact` — V=3, K=20, M=3,
  N=2 — and `MockAttestationBytes.compact` — V=3, B=2, K=24) specialize the
  modules so tests run against real artifacts. `MockAddressHash.compact` is the
  compiled oracle for the cardano address hash. `MockRegistryDoubleInit.compact`
  calls `initRegistry` twice in its constructor to reach the double-init guard.
- `packages/contracts/test/helpers/fixtures.ts` builds signed claims with the
  compiled pure circuits — never hand-roll the message encoding; use
  `pureCircuits.message` or `@txpipe/thoth-core/claim`'s `claimToMessage`.
- After changing Compact sources, recompile before running tests:
  `npm run compact:no-zk` (the `pretest` hook does this automatically).
- `packages/contracts/test/acceptance.test.ts` is the end-to-end check (zkFetch
  witnesses → attestors → client → simulator); its header explains the setup.
- `packages/zk-tls/test/live.test.ts` is an opt-in live check against two real
  witnesses; it skips unless `WITNESS_URLS` names them, so `npm test` and CI
  stay offline. See "Live check" in `packages/zk-tls/docs/attestor-guide.md`.
- `packages/cardano/test/live.test.ts` is the same kind of check for one real
  UTxO-RPC endpoint; it skips unless `DOLOS_URL` names it. See "Live check" in
  `packages/cardano/docs/dapp-integration.md`.
- `npm run bench` is the only check that proves: a circuit can pass every
  simulator test and still fail in the prover. Run it after a circuit change
  and update the "Proving cost" table in `packages/contracts/README.md` from
  its output. It needs Docker and stays out of `npm test` and CI; its options
  are in [`CONTRIBUTING.md`](CONTRIBUTING.md#proving-benchmark).
- Never skip the `present` mask semantics: `present[i] = true` means slot `i`
  was measured (value may still be `0`).

## Agent skills

### Issue tracker

Issues live in GitHub Issues (txpipe-shop/thoth), via the `gh` CLI. See
`docs/agents/issue-tracker.md`.

### Triage labels

Default label vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at the repo root. See
`docs/agents/domain.md`.
