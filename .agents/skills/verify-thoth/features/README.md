# thoth verification map

This directory is the maintained source for verifying the user-facing behaviour of thoth: the
`@thoth/*` packages as a consumer imports them, and the Compact modules as an app embeds them.
Read the index before driving, then use the matching feature file as the recipe.

## Baseline preconditions

- `export VERIFY_RUN_ID=<issue>`, `C=.agents/skills/verify-thoth/control-thoth`,
  `D=.agents/skills/verify-thoth/drive`, from the repo root.
- `$C launch` has built this worktree's `dist/` and compiled the example app, `$C doctor`
  passes, and `. "$($C env)"` gives `$RUN_DIR`.
- One run per worktree at a time; never drive a run another agent launched.

## Driving conventions

- Make the feature's evidence folder variable first: `E=.evidence/$VERIFY_RUN_ID/<feature>`,
  the `<feature>` being the file's name without `.md`; `run --evidence` creates it.
- Run every command through `$C run --evidence "$E/NN-<step>" --offline -- <cmd>`, numbering
  in the order the file lists them. Drop `--offline` only where doctor says it is unavailable,
  and say so in the Evidence.
- Treat every command as literal; keep step names and quoted values unchanged.
- A drive prints one JSON object: exit `0` is what the library returned, exit `1` is
  `{ refused: { error, message, reason?, failures?, code? } }`, exit `2` an unknown step.
- Values a run picks for itself differ per run: Jubjub public keys, signatures, vault ids.
  Every hash, window, message and ledger count below does not.
- Do not remove proof artifacts during cleanup.

## Proof and skip reporting

- Capture the action and the resulting state: `.cmd`, `.stdout`, `.stderr` and `.exit` per
  invocation.
- An accepted call's proof is what it returned and what it left: the signed claim and its
  verified signature, the collected slots, the contract's ledger after the call.
- A refusal's proof is its exit `1`, its error class and its `reason` or assert text.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible
behaviour. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behaviour.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with control-thoth` starts with `Preconditions:` and uses labeled bullets that
   pair each user action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

Keep implementation details out of the map. Name only user paths, stable handles, required
state, commands, and observable proof.

## Features

- [Package entry points](./exports.md) covers the eleven `exports` subpaths resolved to
  `dist/` with the names each exports, a path outside `exports` refused, and what each
  package ships (`npm pack --dry-run`).
- [The claim and its message](./claim.md) covers `@thoth/core/claim`'s `claimSchema` (coercion,
  a short byte field refused) and `claimToMessage` (the 17-field wire order) against the
  compiled example app's `message` circuit, and `@thoth/core/claim-context`'s four hashes.
- [An operator's zkFetch attestor](./attest.md) covers `@thoth/zk-tls/attestor` verifying the
  recorded witness evidence and signing the claim it derives, and refusing tampered evidence,
  another witness, a host outside the policy, a required slot it cannot certify, a window that
  misses the observation, and a proposal that claims more than was disclosed.
- [A dApp collecting an attestment](./collect.md) covers `@thoth/zk-tls/client`'s `collect`
  and `proveReq` + `attest` over a `@thoth/client` trusted set (2-of-3, app-assigned slots),
  a forged signature, evidence for another origin, an expired deadline, a threshold above the
  set, and `buildTrustedSet`'s refusals.
- [The contract accepting an attestment](./contract.md) covers compiling the example app
  embedding the modules, deploying it on the simulator, `verifyAttestation` vaulting a 2-of-3
  attestment, and refusing a replay, too few or misplaced signatures, an unsealed policy, the
  wrong holder secret, a window too long, too old or in the future.

## Not mapped by default

Drive by hand, then add a file or a step, when a change touches them:

- `@thoth/zk-tls/prover` against live Reclaim witnesses. Needs network (it clones
  `reclaimprotocol/attestor-core` and fetches `api.github.com`): `npm run witnesses
  --workspace=packages/zk-tls` in one shell (foreground; Ctrl-C stops both witnesses), then
  `$C run --evidence "$E/NN-live" -- env WITNESS_URLS=ws://localhost:8001/ws,ws://localhost:8002/ws
  npx vitest run packages/zk-tls/test/live.test.ts` (packages/zk-tls/README.md, "Live check").
- A new kind built on `defineAttestor`/`buildAttestor` and `claimSchema`: the zkFetch kind is
  the one driven (docs/kind-author-guide.md).
- The TypeScript declarations (`dist/*.d.ts`) a consumer type-checks against: `npm run types`
  covers the repo's own use.
- App predicates over `openClaim` (the example app exports none) and the asserts an honest
  attestor never lets a claim reach (`Window inverted`, `Claim already accepted`,
  `Unsupported claim version`, `Absent slot has nonzero value`): `npx vitest run` covers them
  on the mock contract with test keys.
- Compiling with proving keys (`npm run compact`, no `--skip-zk`).
