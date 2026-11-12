# @thoth/cli

The `thoth` command, for dApp developers: it reads one `thoth.config.ts` and
generates the Compact and TypeScript code that embeds Thoth in your Midnight
contract.

> **In development.** Thoth is unaudited and has [known security issues](https://github.com/txpipe-shop/thoth/issues?q=is%3Aissue+is%3Aopen+label%3Asecurity). Don't use it to protect real value. The claim format may still change.

## Install

The package is private. Build it from a checkout of this repo and install it
by path, with the packages the generated code imports:

```bash
git clone https://github.com/txpipe-shop/thoth && cd thoth
npm install && npm run build
cd /path/to/your-app
npm install /path/to/thoth/packages/{cli,core,client,zk-tls} @midnight-ntwrk/compact-runtime@0.21.0
```

`thoth compile` runs the [Compact CLI](https://github.com/midnightntwrk/compact)
with compiler `0.36.1` (`compact update 0.36.1`). Node 24 loads
`thoth.config.ts` directly.

## Usage

Describe the app once, in `thoth.config.ts`. The order of `attestors` is the
[registry slot](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection)
order:

```ts
import { defineConfig } from '@thoth/cli';
import { zkTls } from '@thoth/zk-tls/thoth';

export default defineConfig({
  kind: zkTls,
  policy: {
    allowedHosts: ['www.strava.com'],
    bodyPolicy: 'ignored',
    slots: [
      { slot: 0, name: 'distance', parse: 'int' },
      { slot: 1, name: 'movingTime', parse: 'int', optional: true },
      { slot: 2, name: 'athlete', parse: 'bytes' },
    ],
    responseMatches: [/* … */],
    responseRedactions: [/* … */],
  },
  appId: 'a1'.repeat(32), // 32 bytes of hex
  threshold: 2,
  attestors: [
    { id: 'attestor-a', publicKey: { x: 0x1n, y: 0x2n } }, // registry slot 0
    { id: 'attestor-b', publicKey: { x: 0x3n, y: 0x4n } }, // registry slot 1
    { id: 'attestor-c', publicKey: { x: 0x5n, y: 0x6n } }, // registry slot 2
  ],
  contract: {
    source: 'contract/app.compact', // your top-level contract
    modules: '../thoth/packages/contracts', // attestation.compact and attestor_registry.compact
    freshnessWindow: 86400, // seconds a claim stays submittable after its window
    maxWindow: 300, // longest observation window, in seconds
  },
  out: { compact: 'contract/generated', ts: 'src/generated', artifacts: 'artifacts/app' },
});
```

Write your contract. Include the generated file first, call `thothInit()` from
your constructor, and read the claim through the named accessors:

```compact
include "generated/thoth";

export ledger rewarded: Counter;

constructor() {
  thothInit();
}

export circuit claimReward(id: Bytes<32>, min: Uint<64>, athlete: Bytes<32>): [] {
  const c = Thoth_openClaim(id);
  assert(distanceOf(c) >= min, "Run too short");
  assert(athleteOf(c) == athlete, "Wrong athlete");
  assert(!movingTimePresent(c) || movingTimeOf(c) >= 600, "Too little moving time");
  rewarded.increment(1);
}
```

Then generate and compile:

```bash
npx thoth generate             # writes the three files below
npx thoth compile --skip-zk    # flags go to `compact compile`
```

| File | What it holds |
|------|---------------|
| `<out.compact>/thoth.compact` | The module imports with their parameters, `thothInit()`, `verifyAttestation`, `message`, `claimId`, and per slot a `<name>Of` accessor and a `<name>Present` flag |
| `<out.ts>/thoth.ts` | The client-only entry: `createClient`, `trustedSet`, `privateStateOf` and the Compact `witnesses`, plus `LAYOUT`, `SLOTS`, `POLICY`, `POLICY_HASH`, `APP_ID` and `ATTESTORS` |
| `<out.ts>/thoth.check.ts` | `config`, which refuses to load once `thoth.config.ts` changed since the last `generate` |

On the dApp side, build the client, collect an
[attestment](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection),
and hand it to the contract:

```ts
import { holderCommitmentOf } from '@thoth/core/claim-context';
import { Contract } from '../artifacts/app/contract/index.js';
import { createClient, privateStateOf, witnesses } from './generated/thoth.js';

// You supply what the config can't: the transport and one prover per attestor.
const client = createClient({ transport, provers });
const attestment = await client.collect(request, {
  holder: holderCommitmentOf(holderSecret),
  windowStart,
  windowEnd,
  expiresAt,
  threshold: 2,
  attestorTimeoutMs: 10_000,
});
const privateState = privateStateOf(attestment, holderSecret, commitRand);
const contract = new Contract(witnesses);
```

## Concepts

- [Kind](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#kinds): the CLI knows no kind. It drives the one in `kind` through its kind manifest, the object the kind exports from its `./thoth` entry ([`@thoth/core`](https://github.com/txpipe-shop/thoth/tree/main/packages/core)).
- [Policy](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim) and [slot map](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): the slot names become the accessor names.
- [present](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): whether a slot was measured; `<name>Present` reads it.
- [Registry slot](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection) and [trusted set](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#signing-and-collection): an attestor's position in `attestors`.
- [Holder](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): `privateStateOf` takes the secret behind the claim's holder commitment.
- [Predicate](https://github.com/txpipe-shop/thoth/blob/main/CONTEXT.md#the-claim): your own circuit over the opened claim.

## Guarantees and limits

What `thoth generate` derives and checks:

- The module parameters: `V` and `W` from the kind's `layoutOf`, `B = 2W`, `K` from the wire layout in the [`attestation.compact`](https://github.com/txpipe-shop/thoth/blob/main/packages/contracts/attestation.compact) header, `M` from `attestors` and `N` from `threshold`. The threshold must be from 1 to `M`.
- The config's shape, distinct attestor ids and keys, and a policy that passes the kind's schema and layout and survives a JSON round trip.
- That the kind's client entry loads and is the same kind.
- No clash between the generated names, the generated module prefixes (`Thoth_`, `ThothRegistry_`) and the names `contract.source` declares.
- Before writing, that every file it would overwrite is its own unedited output. It writes nothing otherwise.

What the generated code does:

- `<name>Of` asserts the slot was measured, so a predicate never reads an absent slot as zero.
- `seedKeys` returns the keys in registry slot order, and `privateStateOf` places each signature at its attestor's registry slot. It refuses a claim for another app, policy or layout.
- `thoth.check.ts` refuses a config that changed since the last `generate`. The policy enters its fingerprint through its hash, so an equivalent policy passes.

What you do yourself:

- Write the constructor, call `thothInit()` from it, and keep your predicates in your own files.
- Supply the transport and the provers to `createClient`, and a fresh holder secret and commitment randomness per claim.
- Import `thoth.ts`, not `thoth.check.ts`, in browser code: the check loads the config, and so the kind's attestor side.

Limits:

- One policy per config, so one kind and one trusted set per contract.
- The name check reads `contract.source` only, not the files it includes.
- `createClient` fills the kind's client config fields `trusted`, `verifier`, `policy`, `appId`, `valueSlots` and `byteSlots`; a kind's client must take them under those names.
- The generated `thoth.check.ts` imports the config with a `.js` extension, as TypeScript's `nodenext` resolution expects.

## Design decisions

- **The app owns the top-level contract.** Compact allows a constructor only at the top level, so the generated file is included and exposes `thothInit()` for your constructor to call.
- **The generated file imports the modules by bare name.** An import inside an included file resolves from the including file's directory, so `thoth compile` sets `COMPACT_PATH` to `contract.modules` instead. The CLI never copies the modules into your app.
- **The policy hash reaches the contract through the `seedPolicies` witness.** The generated TypeScript fills it from the config, so the generated Compact keeps its shape when the accepted policies become settable after deploy.
- **The app id is a literal in `thothInit()`.** The config fixes it, so no witness supplies it.
- **Generated files are regenerated, never edited.** Each starts with a header and a hash of its body; change the config and run `thoth generate` again.
- **The client entry loads only the kind's client side.** `thoth.ts` imports the kind's `KindClient` from the module its manifest's `clientEntry` names, so a browser bundle carries no attestor or offline evidence code.

## Links

- [Thoth (repo root)](https://github.com/txpipe-shop/thoth): overall architecture and docs
- [docs/DESIGN.md](https://github.com/txpipe-shop/thoth/blob/main/docs/DESIGN.md): the architecture, the claim and its wire order
- [`@thoth/contracts`](https://github.com/txpipe-shop/thoth/tree/main/packages/contracts): the Compact modules the generated file imports
- [`@thoth/zk-tls`](https://github.com/txpipe-shop/thoth/tree/main/packages/zk-tls): the zkFetch kind and its `./thoth` manifest
- [docs/kind-author-guide.md](https://github.com/txpipe-shop/thoth/blob/main/docs/kind-author-guide.md#10-the-thoth-entry): the `./thoth` entry a kind exports for the CLI
