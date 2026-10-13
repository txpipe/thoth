---
name: verify-thoth
description: "Drive thoth the way its users do — a dApp developer, an attestor operator and a contract embedder consuming the built @thoth/* packages through their package exports, and the example app compiled from the Compact modules on the Compact runtime's simulator — offline, with recorded witness evidence, capturing proof under .evidence/<issue>/. Use to prove a change to thoth's public behaviour, not only `npm test`; the feature map in features/ is the maintained list of what to drive."
---

# Verify thoth

thoth is a library monorepo with no server and no UI: its users are developers. This skill
drives the seams they touch, through what an installed package exposes and nothing else:

- **The packages' entry points**: the eleven `exports` subpaths of `@thoth/core`,
  `@thoth/attestor`, `@thoth/client` and `@thoth/zk-tls`, imported by name, so Node resolves
  them through `node_modules/@thoth/*` and each package's `exports` map to its built `dist/`.
- **The Compact modules**: `packages/contracts/examples/example_app.compact`, the documented
  embedding, compiled with the repo's pinned compiler and deployed on the simulator of
  `@midnight-ntwrk/compact-runtime`, the runtime the repo pins.

Each recipe is a small Node script in `drive/` that plays one user: an operator's zkFetch
attestor signing, a dApp collecting a 2-of-3 attestment, an app's contract accepting it. The
witness side is the recorded Reclaim evidence in `examples/demo-attestation/fixtures/`, a
genuine fetch whose signature verifies offline; no step of a recipe reaches a network.

Decisions this skill was generated from (the interview of the repo):

- **Surface:** the public exports of the four TypeScript packages and the Compact modules
  (`README.md`, `docs/kind-author-guide.md`, the package READMEs). The users: a dApp
  developer (`@thoth/zk-tls/client`, `@thoth/client`), an attestor operator
  (`@thoth/zk-tls/attestor`), a kind author (`@thoth/core`, `@thoth/attestor`), a contract
  embedder (`@thoth/contracts`). `@thoth/zk-tls/prover` needs live Reclaim witnesses: opt-in
  only (features/README.md, "Not mapped by default").
- **Run:** `npm ci`, `npm run build` (each package's `tsc` into `dist/`, core first), and
  `compact compile +<pin> --skip-zk` of the example app; the pin is the one in the root
  `package.json` scripts (`0.34.0`).
- **Drive:** `node .agents/skills/verify-thoth/drive/<feature>.mjs <step>` from the repo root.
  The scripts import only `@thoth/*` subpaths, `@midnight-ntwrk/compact-runtime` and the
  compiled example app; never `packages/*/src` or a test helper.
- **Observe:** each step prints one JSON object (bigints as decimal strings, bytes as
  `0x`-hex) and exits `0` when the library accepted, `1` with `{ refused: { error, message,
  reason?, failures?, code? } }` when it threw, `2` for an unknown step. The contract steps
  print the ledger after the call, which is the contract's side effect.
- **Isolate:** the run dir is per `VERIFY_RUN_ID`, under
  `${VERIFY_RUN_ROOT:-${TMPDIR:-/tmp}/verify-thoth}`. `dist/` and `node_modules/` belong to
  the worktree, so two runs in different worktrees drive side by side, and two in one
  worktree do not: `launch` refuses while another run is registered for the same worktree.

## Helpers

`control-thoth` (bash; needs `git`, `node`, `npm`, `compact`; `mise` to reach `.nvmrc`'s Node
when the current one differs; `unshare` for `--offline`). Every subcommand reads
`VERIFY_RUN_ID`; pick one per verification run, normally the issue number:

```sh
export VERIFY_RUN_ID=<issue>
C=.agents/skills/verify-thoth/control-thoth   # from the repo root
D=.agents/skills/verify-thoth/drive

$C launch                       # npm ci if node_modules is older than the lockfile, build dist/, compile the example app
$C doctor                       # read-only: is this run worth driving?
. "$($C env)"                   # this run's REPO, RUN_DIR, NODE_BIN, COMPACT and HEAD
$C run [--evidence PREFIX] [--offline] -- <cmd...>   # from the repo root, with the run's node first on PATH
$C cleanup                      # remove the run dir; never .evidence/, dist/ or node_modules/
```

`run` exports `VERIFY_THOTH_RUN_DIR` (the drives find the compiled example app there) and
exits with the command's code. `--evidence PREFIX` writes `PREFIX.cmd`, `.stdout`, `.stderr`
and `.exit`, and still prints the output. `--offline` runs the command in a new network
namespace (`unshare --map-root-user --net`), so a step that tried to reach a network would
fail; doctor says whether this machine allows it.

## Launch

From the repo root:

```sh
export VERIFY_RUN_ID=<issue>
.agents/skills/verify-thoth/control-thoth launch
```

It picks Node: the current `node` when its major is `.nvmrc`'s (`24`), else `mise where
node@24`'s, else the current one with a warning. The packages' `engines` say `>=24`; on the
machine this skill was written on, Node 26.8.1 also built, typechecked and passed `npx vitest
run`, but CI runs `.nvmrc`'s. Then, with that Node first on `PATH`: `npm ci --prefer-offline`
when `node_modules/.package-lock.json` is missing or older than `package-lock.json`, `npm run
build`, and `compact compile +0.34.0 --skip-zk packages/contracts/examples/example_app.compact
$RUN_DIR/example_app`, linking `$RUN_DIR/node_modules` to the worktree's so the compiled
contract imports the Compact runtime as an app's build does. `npm ci` needs the registry or a
warm npm cache; nothing after it does. Under Node 24's npm it warns that the install scripts
of `cbor-extract`, `koffi` and `re2` were not run (`allow-scripts`); every recipe passed
without them.

Ready signal: `launch: ready, run dir <dir>`, then `doctor` passes. A failing `npm run build`
or compile is a broken checkout: report it with its output, do not verify against it.
`launch` refuses a `VERIFY_RUN_ID` whose run dir exists, and a second run in the same
worktree; run `cleanup` first. Teardown is `cleanup`.

## Doctor

```sh
.agents/skills/verify-thoth/control-thoth doctor
```

Read-only. Passes only when: the run was launched from this worktree; `HEAD` is the commit
launched; the run's Node runs (and says whether it is `.nvmrc`'s); `compact compile +0.34.0
--version` prints `0.34.0`; no `.ts`, `.compact` or `package.json` under `packages/` changed
since the build (a stale `dist/` is the repo's known footgun, AGENTS.md); each of
`@thoth/core`, `@thoth/attestor`, `@thoth/client` and `@thoth/zk-tls` resolves to this
worktree's `packages/<name>/dist/index.js`; the example app is compiled in the run dir; the
recorded evidence file exists. It also says whether `--offline` works here. Run it first, and
again whenever anything looks off; a failing doctor means "do not drive this run": `cleanup`,
`launch`, `doctor`.

## Drive

Every recipe runs a drive script through `run`, from the repo root:

```sh
C=.agents/skills/verify-thoth/control-thoth; D=.agents/skills/verify-thoth/drive
. "$($C env)"                                   # $RUN_DIR, for the contract recipe's compile
E=.evidence/$VERIFY_RUN_ID/attest
$C run --evidence "$E/02-sign" --offline -- node "$D/attest.mjs" sign
```

What the drives hold (`drive/common.mjs`), the same in every step:

- **Evidence**: `examples/demo-attestation/fixtures/fixture-github-attestor-core-x-0m.json`,
  a `GET https://api.github.com/repos/reclaimprotocol/attestor-core` witnessed at
  `1786122944` by witness `0xc340fc267cacbb9e3101adced0c7728f7e63b63d`. It discloses the
  whole response as `data`, which no numeric rule parses, so every honest claim from it has
  `present: [false, false, false]` and `values: [0, 0, 0]`.
- **Policy**: `allowedHosts: ['api.github.com']`, slot 0 `data` parsed as `float`,
  `optional`. Its `zkFetchPolicyHashOf` is
  `0x8da8bf6a39d629bdd7a669515223ec5c8d32e08b0523e78895dfa44083058321`.
- **App and holder**: app id 32 bytes of `0xa1`; holder secret 32 bytes of `0xc1`, holder
  `holderCommitmentOf(secret)` =
  `0x9acf97bbb544fa9b39f8bb70036418f9e6cc1d2bad398095c9b4cf0586fcc5a0`.
- **Operators**: `operator-a` and `operator-b`, zkFetch attestors with fresh Jubjub keys
  each run, both trusting the recorded witness, pinned by the dApp at registry slots `0` and
  `2` of 3; slot `1` holds a third operator's key the dApp never queries. Each operator's
  prover replays the recorded evidence; the transport calls the operator in process. Keys,
  signatures and vault ids differ per run; hashes, windows and messages do not.
- **The example app**: `#V = 3`, `#K = 17`, `#M = 3`, `#N = 2`; it seals
  `freshnessWindow = 3600` and `maxWindow = 300` in its constructor, and the drive seeds
  the three registry keys and the policy hash through its `seedKeys` and `seedPolicies`
  witnesses.

Stable handles are the step names (`node <script> <step>`; an unknown step prints the
list), the exported names, the JSON field names, the error class names and `reason` values,
and the contract's assert texts (`failed assert: <text>`). Recipes per feature are in
[`features/`](features/README.md); drive the ones the change touches, every bullet.

## Evidence

Record into `.evidence/<issue>/<feature>/` in the worktree, one folder per feature driven,
each invocation as `NN-<step>.{cmd,stdout,stderr,exit}` through `run --evidence`; nico-agent
copies `.evidence/<issue>/` to the Bucket at each PR head, Verdict and Close, and the PR
body's Evidence section links there and quotes what it shows. Never commit `.evidence/`
(until thoth's `.gitignore` names it, `git add -A` would).

Proof standards:

- Exercise the real user path: package specifiers resolved through `exports` to `dist/`,
  the compiled example app, the documented calls. Never import `packages/*/src`, a test
  helper or the mock contract.
- Capture the action and the resulting state: the honest call and what it returned (the
  claim, the slots, the ledger after the call), and each refusal with its error and reason.
- Verify side effects alongside the answer: a contract call is proven by the ledger it left
  (`nullifiers`, `claimsVault`), not by not throwing.
- Mocks only at the seams the packages already isolate: `ZkFetchProver` (a prover replaying
  recorded witness evidence) and `AttestorTransport` (in process). Signing, verification,
  hashing and the contract run for real.
- Prove offline: run every drive with `--offline` where doctor says it is available.
- Tests prove the code, Evidence the behaviour: `npm test` passing is not Evidence by itself.
  When the change touches behaviour the map lacks, drive it with a new step in its drive
  script and a bullet in its feature file, in the same change.

## Cleanup

```sh
.agents/skills/verify-thoth/control-thoth cleanup
```

Removes the run dir (the compiled example app, the `node_modules` link, `run.env`) after
checking it is under the run root, which also releases the worktree for another run. The
drives start no processes, so there is nothing to stop; it kills nothing. It never touches
`.evidence/`, where the proof lives after cleanup, nor `dist/`, `node_modules/` or
`packages/contracts/artifacts/`, the worktree's own gitignored build output. Run it after every
failed iteration too, so a half-made run does not block the next `launch`.

## The repo's own checks

Not Evidence, but run them before handing over a change (AGENTS.md):
`$C run -- npm run types`, `$C run -- npx vitest run` (after `$C run -- npm run compact:no-zk`,
which compiles the mock the contract tests import into `packages/contracts/artifacts/`), and
`$C run -- npm run check`. The live witness check is opt-in (features/README.md).

## Maintenance

The feature map under `features/` is the maintained source for what this skill verifies.
When an export, a step's output, an error or a contract assert changes, update the matching
feature file and drive script in the same PR; use `/maintain-verification-skill` to re-check
the map against the packages.
