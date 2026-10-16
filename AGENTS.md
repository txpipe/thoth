# AGENTS.md

Agent-facing guide for the Thoth monorepo. Human-oriented docs live in
[`README.md`](README.md) and [`docs/DESIGN.md`](docs/DESIGN.md).

## Project overview

Thoth is a private N-of-M attestation system for Midnight. Three layers:

- **Contract layer** — `packages/contracts` (`@thoth/contracts`): embeddable
  Compact modules that verify N-of-M signatures over a flat signed message
  (`attestation.compact`), count valid signatures against a pinned key vector
  (`attestor_registry.compact`) with the stdlib `jubjubSchnorrVerify`.
- **Attestor SDK** — `packages/attestor` + `packages/core`: the types and
  interfaces attestor *kinds* implement to provide attestation. Kinds verify
  evidence and sign a canonical claim. (`packages/client` — the dApp-side
  `TrustedSet` seam — and `packages/zk-tls` — the zkFetch kind — are active
  workspaces.)

Attestors certify facts, not decisions: a claim is a canonical statement of
what was observed; the application defines the predicate over it.

Use the glossary in [`CONTEXT.md`](CONTEXT.md) for domain terms. The claim's
fields and wire order are in [`docs/DESIGN.md`](docs/DESIGN.md#the-claim). To
add an attestor kind, follow [`docs/kind-author-guide.md`](docs/kind-author-guide.md).

## Commands

Run everything from the repo root (npm workspace):

- `npm install` — install all workspaces
- `npm run types` — typecheck every package (`tsc --noEmit` per workspace)
- `npm test` — compiles the mock contracts and builds the packages (via
  `pretest`), then runs vitest (contract simulator, core, and zk-tls kind tests)
- `npm run check` — biome format/lint + `compact format -c` check
- `npm run check:fix` — auto-fix biome + compact formatting
- `npm run build` — build all packages that have a `build` script (`tsc`),
  producing `dist/`
- `npm run compact` / `npm run compact:no-zk` — compile the mock top-level
  contracts (with/without PLONK key generation)

Per-package: `npm run <script> --workspace=packages/<name>`.

CI (`.github/workflows/`) runs compact compilation, type checks, vitest, and
biome on every push/PR.

## Gotchas

- **Stale `dist/` footgun** — workspaces resolve each other through
  `node_modules/@thoth/*` ⇒ `exports` ⇒ `dist/`. The root `build`/`types`
  scripts rebuild the dependency-producing packages first (`core`, `attestor`,
  `client`, `zk-tls`), so consumers — e.g. `zk-tls`, which depends on the first
  three, and the `contracts` tests, which depend on all four — see fresh
  types; if a *new* workspace dependency appears, add its package to the
  build-first chain. A stale `dist/index.d.ts` still produces confusing errors
  like "Generic type requires N type argument(s)".

## Repository layout

```
thoth/
├── packages/
│   ├── attestor/       # @thoth/attestor  — host: key boundary, instances, helpers
│   ├── client/         # @thoth/client    — dApp-side seam: TrustedSet, transport, primitives
│   ├── contracts/      # @thoth/contracts — Compact modules (+ tests)
│   ├── core/           # @thoth/core      — keyless claim/envelope types
│   │   ├── src/claim.ts                   — claim types served at @thoth/core/claim
│   │   └── src/claim-context.ts           — claim-context hashes at @thoth/core/claim-context
│   └── zk-tls/         # @thoth/zk-tls    — zkFetch kind: attestor law + client (fixture-backed tests)
├── docs/
│   ├── DESIGN.md       # design overview, the claim and its wire order
│   ├── kind-author-guide.md  # how to add an attestor kind
│   ├── adr/            # architecture decision records
│   └── agents/         # agent skill configuration
├── CONTRIBUTING.md     # dev setup, repo layout, commands
├── examples/demo-attestation/  # recorded zkFetch evidence fixture
├── CONTEXT.md          # domain glossary
├── README.md           # human-oriented overview
└── AGENTS.md           # this file
```

## Package invariants

- **One package per directory** under `packages/`. *Active* packages must be
  added to the root `package.json` `workspaces` array or they are silently
  skipped by the root `types`/`build` scripts. Dirs present on disk but absent
  from `workspaces` are **placeholders** — intentionally not compiled.
- **`@midnight-ntwrk/compact-runtime` is pinned to `0.19.0`** everywhere
  (root, contracts, core). Off-chain code that mirrors an in-circuit primitive
  (e.g. `convertBytesToUint`, `jubjubSchnorrSign`) only matches the circuit at
  the **same pinned version** — do not bump one workspace in isolation. The
  matching Compact compiler is `0.34.0` (README + both CI workflows).
- **Claim types are keyless.** `@thoth/core` carries no signing key; anything
  that commits to a message delegates to the kind's `message()`. Keep it that
  way.
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
  - `noBarrelFile` / `noReExportAll` are **errors** (except `*.config.*`). Do
    NOT add `export *` barrels; use subpath exports instead (see `@thoth/core/claim`).
  - `noUnusedImports`, `noUnusedVariables`, `useErrorMessage` are errors.
  - 100-column line width, single quotes, semicolons.
- **Compact**: `pragma language_version >= 0.22`; follow the style in
  `packages/contracts/*.compact`; module params are uppercase (`<#K, #V, #N, #M>`).
  A module header covers purpose, wire layout and module parameters, and skips
  prose that restates the asserts below it.
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
  `buildTrustedSet`, `zkFetchProver`). Block comments `/** … */`; file headers
  are 1–2 `//` lines (plus the wire layout in `attestation.compact`).
- **Comments explain why**: invariants, security reasons, non-obvious
  constraints. The code says what. History, ticket and PR numbers stay out of
  source; cite decisions as `ADR 000N`.

## Docs conventions

Who reads what:

| Doc | Reader | Contains |
|-----|--------|----------|
| `README.md` | someone evaluating Thoth | what it is, status, how it works, which package to use, the demo, roadmap links |
| `packages/*/README.md` | a developer using that package (it is the npm page) | the package README template below |
| `docs/kind-author-guide.md`, `packages/zk-tls/docs/*` | a developer building a kind or integrating a dApp | step-by-step guides |
| `docs/DESIGN.md` | anyone who wants the architecture | overview, the claim and its wire order, flow, out of scope; links the ADRs and never restates them |
| `docs/adr/` | maintainers | one decision each with its full reasoning; the only place for history and ticket references |
| `CONTEXT.md` | everyone | the glossary |
| `CONTRIBUTING.md` | contributors | dev setup, repo layout, commands |

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

1. `# @thoth/<name>`, then one sentence saying what it is and who it's for.
2. The status line, identical in every README and the root:
   > **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.
3. `## Install`: the current npm name, plus one line saying it may change until
   the npm scope is settled.
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
README it affects. `docs/kind-author-guide.md` spans packages: update it when
an interface a kind implements changes (`@thoth/core`, `@thoth/attestor`,
`@thoth/client`, or the claim).

The roadmap lives in GitHub: the `v0` and `Next` milestones and the `frozen`
label. The root README's Roadmap section only links those three; package
READMEs don't repeat it.

## Testing

- Contract logic is tested with the **simulator** via vitest in
  `packages/contracts/test/`. The mock top-level shells
  (`packages/contracts/test/mocks/MockAttestation.compact` — V=3, K=18, M=3,
  N=2 — and `MockAttestationBytes.compact` — V=3, B=2, K=22) specialize the
  modules so tests run against real artifacts.
- `packages/contracts/test/helpers/fixtures.ts` builds signed claims with the
  compiled pure circuits — never hand-roll the message encoding; use
  `pureCircuits.message` or `@thoth/core/claim`'s `claimToMessage`.
- After changing Compact sources, recompile before running tests:
  `npm run compact:no-zk` (the `pretest` hook does this automatically).
- `packages/contracts/test/acceptance.test.ts` is the cross-seam check (zk-tls
  witnesses → attestors → client → simulator); its header explains the setup.
- `packages/zk-tls/test/live.test.ts` is an opt-in live check against two real
  witnesses; it skips unless `WITNESS_URLS` names them, so `npm test` and CI
  stay offline. See the package README's "Live check".
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