# Thoth on a local ledger-9 devnet

A spike for [#127](https://github.com/txpipe-shop/thoth/issues/127), part of the
Midnight City map ([#117](https://github.com/txpipe-shop/thoth/issues/117)). It
answers one question: does Thoth, as pinned today, deploy and record an
attestment on a local ledger-9 devnet, and with which versions?

**Answer: not as pinned; yes after recompiling with 0.35.0.**

- The repo's **0.34.0** build (runtime 0.19.0) does not run under midnight-js 5
  (see [Runtime 0.19 versus 0.20](#runtime-019-versus-020)).
- The unchanged Compact source compiled with **0.35.0** (runtime 0.20.0) does
  run. Its contract accepts on-chain an attestment signed by Thoth's
  runtime-0.19 packages.

This directory is not an npm workspace and does not touch `packages/`. It
reuses the `MockAttestation` source and the contract test helpers in place.

## Run it

You need Docker, Node 24, and the Compact CLI with compiler 0.35.0
(`compact update 0.35.0 --no-set-default` keeps your default compiler).

```sh
# once, at the repo root: workspace deps and the @thoth/* builds
npm install && npm run build && npm run compact:no-zk

# once, here: the app's deps and the 0.35.0 contract build (with keys, ~5 min)
cd apps/midnight-city/devnet
npm install
npm run compact

docker compose up -d --wait   # the first run builds the indexer (~13 min)
npm start                     # deploys and records one attestment (~1 min)
```

`npm start` builds and syncs the deployer's wallet from the dev preset's
genesis seed, deploys `MockAttestation`, submits one 2-of-3 attestment, then
reads the claims vault back. It ends with `✓ attestment accepted on-chain`.
Reset the chain with `docker compose down -v` and `rm -rf .state`.

The root step compiles the 0.34.0 contract only for its type declarations,
which the reused test helpers import. The run itself uses the 0.35.0 build in
`artifacts/`; set `ARTIFACTS` to try another.

The attestment is built the way `packages/contracts/test/acceptance.test.ts`
builds it: two test-key witnesses, two zkFetch attestors with Jubjub keys, and the
zkFetch client collecting the threshold. Registry slot 2 holds an unqueried key
and a dummy signature. The observation window follows the wall clock, because
the chain checks it against block time.

## The Bounty

`npm run bounty` runs the Midnight City Bounty (`../bounty`) on this devnet with
real tNIGHT: deploy, fund the pot, register and qualify two agents, pay one
Qualifier its Share anonymously, and refund the rest to the Sponsor after the
Payout period. The genesis wallet plays every role. Claims are signed by three
test attestor keys pinned at deploy; zkFetch is covered by
`../bounty/test/recorded.test.ts`, not here.

```sh
npm run compact:bounty                       # 0.35.0, with keys (~5 min)
docker compose down -v && rm -rf .state      # a fresh chain for each run
docker compose up -d --wait && npm run bounty   # ~15 min of real deadlines
```

A run on 2026-10-13 (each line one transaction, all within their time to dismiss):

```text
deploy                16,565 B
fund 1,001 NIGHT       9,444 B   block   8   wallet −1,001
verifyAttestation ×6  ~9,400 B   36–48 s each, including the proof
register ×2            9,335 B   blocks 27, 42
qualify ×2             9,686 B   blocks 51, 60   qualifiers 2
payout 500             9,438 B   block 111       wallet +500, names no agent
refund 501            10,669 B   block 131       wallet +501, back to the start
```

What it took:

- **Node 2.1.0's fee wall** (custom error 231, `OutsideTimeToDismiss`). A
  transaction may take at most max(15 ms, 2 µs per byte) to dismiss.
  `fund` is a small call that also spends the caller's coins: 16.5 ms against
  15 ms. Midnight's passport repo hit the same wall and never got past it.
  `fund` now writes 2 KB of the caller's random bytes in its fallible phase,
  after `kernel.checkpoint()`: that grows the transaction without adding to
  its cost to dismiss. A constant didn't work, because its zero bytes are
  trimmed, and neither did a guaranteed-phase write, because that adds cost.
  `wallet.ts` logs every transaction's size and dismissal check before
  submitting, since the node reports the error without numbers.
- **TTLs.** The deploy uses a 1-hour TTL and every call 120 s
  (`TX_TTL_SECONDS`). The large deploy needs the long TTL on a young chain;
  the short one keeps balancing from adding DUST inputs to small calls.
- **DUST on a young chain.** `balanceTx` waits until the fee estimate stops
  failing with "insufficient funds", the way passport's localnet wallet does,
  restarting the TTL each time.
- **A fresh chain per run.** `docker compose up` reattaches the previous
  chain's volume, so `down -v` first. A run stopped mid-transaction leaves
  spent DUST the next wallet doesn't know about yet (`DustDoubleSpend`).

## Version set

Verified on 2026-10-09 with a fresh chain each time:

| Component | Version |
| --- | --- |
| Node | `midnightntwrk/midnight-node:2.1.0-beta.1` |
| Indexer | `indexer-standalone` `4.4.0-rc.5`, built from the public tag `v4.4.0-rc.5` (commit `7a0b8d1e`) |
| Proof server | `midnightntwrk/proof-server:9.0.0-rc.9` (`9.0.0-rc.7` works too) |
| Compact compiler | `0.35.0`, which targets `compact-runtime` `0.20.0` |
| midnight-js | `5.0.0-rc.4`, which bundles `compact-runtime` `0.20.0` and `ledger-v9` `1.0.0-rc.5` |
| Wallet SDK | `@midnightntwrk/wallet-sdk` `2.0.0-rc.1`, the barrel for `wallet-sdk-facade` `5.0.0-rc.1` |

The [release notes](https://github.com/midnightntwrk/midnight-docs/tree/main/docs/relnotes)
cover only the ledger-8 networks, apart from the compiler notes (0.34.0 targets
runtime 0.19.0, 0.35.0 targets 0.20.0, both for ledger 9). The set was pinned
from the upstream test environments instead, then confirmed by running it:

- midnight-js `v5.0.0-rc.4` tests ledger 9 against node `2.1.0-beta.1`,
  indexer `4.4.0-rc.5` and proof server `9.0.0-rc.7`
  (`testkit-js/env/devnet.env`).
- The indexer `4.4.0-rc.5` release lists node `2.1.0-beta.1`.

### Why not the candidates from 2026-10-08

The issue named node `2.1.0-rc.4`, indexer `4.4.0-rc.2` and proof server
`9.0.0-rc.9`. That set does not work together:

- **No published indexer follows node `2.1.0-rc.*`.** Indexers `4.4.0-rc.2` and
  `4.4.0-rc.5` both exit on start against rc.1 and rc.4 with `cannot find the
  block header for block 0000…0000`. Both index `2.1.0-beta.1`.
- **Wallet SDK 5 needs indexer `4.4.0-rc.5`.** Every wallet SDK 5 prerelease
  (from `2.0.0-beta.2`) queries `protocolVersion` on the progress types, which
  the indexer added in rc.5 (#1463). Against rc.2 the wallet never syncs:
  `Unknown field "protocolVersion" on type "UnshieldedTransactionsProgress"`.
- **Indexer `4.4.0-rc.5` has no public image.** It is on `ghcr.io/midnight-ntwrk`
  only, which needs credentials. Docker Hub's newest 4.4 is rc.2. So
  `compose.yml` builds it from its public source tag. If you have access to
  ghcr, `ghcr.io/midnight-ntwrk/indexer-standalone:4.4.0-rc.5` is the same commit.

## Runtime 0.19 versus 0.20

The 0.34.0 build (runtime 0.19.0) does not run under midnight-js 5 in any
arrangement we tried. It fails at a different layer each time:

1. **Artifacts resolve their own runtime 0.19.** This is the in-place setup:
   the repo's artifacts resolve `compact-runtime` 0.19.0 from the root
   `node_modules`. Deploying fails with `Failed to set the maintenance authority
   on the given contract state: expected instance of
   ContractMaintenanceAuthority`. Two copies of `onchain-runtime-v4` are loaded
   (4.0.0-rc.3 under runtime 0.19, 4.0.0-rc.5 under midnight-js), and an
   `instanceof` check between them fails.
2. **Artifacts resolve midnight-js's runtime 0.20.** The generated module
   refuses to load: `Version mismatch: compiled code expects 0.19.0, runtime is
   0.20.0`.
3. **The same, with that guard stripped by hand.** Contract initialisation
   fails: `'contractState' parameter undefined has unexpected type`. Runtime
   0.20 does not accept the 0.19-generated `initialState`.
4. **Behind all three: era dispatch.** midnight-js 5.0.0-rc.4 picks a pipeline
   from the artifact's `runtime-version` in `compiler/contract-info.json`, and
   it knows only `0.16` (ledger 8) and `0.20` (ledger 9)
   (`RUNTIME_VERSION_TO_ERA` in `midnight-js-contracts`). We read this in the
   source but never reached it at run time, because each failure above comes
   first.

The 0.35.0 build of the same source runs. Thoth's off-chain code still runs on
runtime 0.19, and the 0.20 circuit accepted what it produced:

- the zkFetch attestors' Jubjub signatures, made with 0.19's
  `jubjubSchnorrSign`;
- the message encoding behind those signatures (`@thoth/core`).

That covers one claim shape, not the parity tests. The run also mixes runtimes
in one process, which AGENTS.md's pin rule forbids for anything kept: 0.20 for
the contract and midnight-js, 0.19 for `@thoth/*` and the test helpers. The
on-chain prototype should move the runtime pin and the compiler together, to
0.20.0 and 0.35.0, and rerun the parity suites. This is the input #132 needs.

## Workarounds

- **Indexer built from source**, for the reasons above. The first
  `docker compose up` compiles Rust for about 13 minutes on 16 cores. Cargo
  uses every core, so on a machine with little free RAM, build once with
  `CARGO_BUILD_JOBS` capped through a local Dockerfile copy.
- **Contract compiled with 0.35.0** into this directory's `artifacts/`. The
  repo's build stays on 0.34.0.
- **Indexer SPO subtask kept alive.** The standalone stack has no SPO node, so
  `standalone.env` stretches its reconnect delay to 24h. midnight-js's testkit
  does the same. Without it the indexer exits after about 5 minutes.
- **Wallet port to SDK 5** (`src/wallet.ts`). The SDK changed shape:
  - wallets start from `WalletSeeds`, not ledger key objects;
  - balancing takes no secret keys;
  - signing is `signRecipe(recipe, keystore.signDataAsync)`, which makes the
    reference app's manual intent-signing workaround unnecessary;
  - transactions cross into the facade as `WalletTransaction` handles stamped
    with a protocol version.

  The midnight-js bridge follows the testkit's `MidnightWalletProvider` and
  serves the v9 era only.
- **Unexercised path: `registerForDustGeneration`.** On the dev preset the
  genesis seed already holds dust, so the registration branch never ran. Its
  shape follows the wallet SDK's `designation.ts` docs snippet.
- **Log noise.** The wallet's node client logs `RPC-CORE: chain(): …
  WebSocket is not connected` while it reconnects. It is harmless.
