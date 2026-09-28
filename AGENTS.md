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

## Commands

Run everything from the repo root (npm workspace):

- `npm install` — install all workspaces
- `npm run types` — typecheck every package (`tsc --noEmit` per workspace)
- `npm test` — compiles the mock contract and builds the packages (via
  `pretest`), then runs vitest (contract simulator, core, and zk-tls kind tests)
- `npm run check` — biome format/lint + `compact format -c` check
- `npm run check:fix` — auto-fix biome + compact formatting
- `npm run build` — build all packages that have a `build` script (`tsc`),
  producing `dist/`
- `npm run compact` / `npm run compact:no-zk` — compile the mock top-level
  contract (with/without PLONK key generation)

Per-package: `npm run <script> --workspace=packages/<name>`.

CI (`.github/workflows/`) runs compact compilation, type checks, vitest, and
biome on every push/PR.

## Gotchas

- **Stale `dist/` footgun** — workspaces resolve each other through
  `node_modules/@thoth/*` ⇒ `exports` ⇒ `dist/`. The root `build`/`types`
  scripts rebuild the dependency-producing packages first (`core`, `attestor`,
  `client`), so consumers — e.g. `zk-tls`, which depends on all three — see
  fresh types; if a *new* workspace dependency appears, add its package to the
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
├── docs/DESIGN.md      # design overview & decisions
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
- **`registryIndex` is positional.** `attestor_registry.compact` verifies
  signatures positionally (`signatures[i]` against `keys[i]`). Never reorder
  descriptors by anything other than registry slot.

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
  Metadata in `attestation.compact`'s header comment is load-bearing — keep the
  wire-layout doc synchronized with `buildMessage`. The claim’s `version` stays `1` until a layout is deployed; pre-launch, change the wire layout freely and keep `version = 1`.
- **Public API style**: every export is documented with JSDoc (block-comment
  `/** … */`) — `@param`, `@returns`, `@typeParam`, `@see` where relevant.
  The file header line uses `//` for file-level notes.

## Docs conventions

- Per-package `README.md` (npm convention): what it is, install, types/concepts,
  and links. A `usage` section belongs when the package is consumed directly;
  the packages that exist as a **base for kind-specific implementations**
  (`core`, `attestor`, `client`) document the *implementer* seam instead — e.g.
  `packages/client/README.md` "For kind SDK authors" — and may drop a usage
  section entirely (`core` does). Written for humans; do not dump APIs (JSDoc
  covers that).
- Design decisions and their rationale live in the **package README that owns
  them** (e.g. `packages/attestor/README.md` "Design rationale"). If a decision
  changes the public surface, update the affected package READMEs together.
  `docs/DESIGN.md` keeps only the architecture overview, flow, and out-of-scope.
- JSDoc lives inline in source; there is no generated API doc site (TypeDoc
  intentionally deferred — packages are small).

## Testing

- Contract logic is tested with the **simulator** via vitest in
  `packages/contracts/test/`. The mock top-level shell
  (`packages/contracts/test/mocks/MockAttestation.compact`) specializes the
  modules (V=3, K=11, M=3, N=2) so tests run against real artifacts.
- `packages/contracts/test/helpers/fixtures.ts` builds signed claims with the
  compiled pure circuits — never hand-roll the message encoding; use
  `pureCircuits.message` or `@thoth/core/claim`'s `claimToMessage`.
- After changing Compact sources, recompile before running tests:
  `npm run compact:no-zk` (the `pretest` hook does this automatically).
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