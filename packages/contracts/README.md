# @thoth/contracts

The Thoth Compact on-chain layer: the embeddable Compact module set that
verifies N-of-M attestations in-circuit. This is the on-chain counterpart to
the TypeScript packages — `@thoth/core` defines the claim law this layer
verifies, `@thoth/attestor` hosts the signing keys, and `@thoth/client` is how
a dApp addresses the attestors. Distributed as an npm package of **Compact
source modules**. There is nothing compiled here — you embed the modules into
your own `.compact` contracts and compile as part of your own DApp build.

| File | Module | Role |
|------|--------|------|
| `attestation.compact` | `attestation<#K, #V, #N, #M>` | Verifies N-of-M signatures over a flat signed message, controls replay (`nullifiers`) and freshness (`freshnessWindow`), stores a `claimsVault` entry keyed by `persistentCommit(claim, rand)`. The claim can be opened at any time to access the values. |
| `attestor_registry.compact` | `attestor_registry<#M, #K>` | Pinned attestor public keys (sealed) + `countValidSignatures` over a `Vector<K, Field>` message, verified with the stdlib `jubjubSchnorrVerify` (compiler ≥ 0.32; developed against 0.34.0). Counts only — no threshold |

The modules form a single import graph (`attestation` → `attestor_registry`), so
they are always installed as one package. Import them by path from your
contract; do not copy them into your project (you would then be forking the
attestation semantics).

## Installation

```bash
npm install --save-dev @thoth/contracts
```

Or, in a workspace monorepo, add `"@thoth/contracts": "*"` to your package's
`dependencies` and `npm install`.

## Embedding

Compact resolves `import "..."` relative to the importing file's directory
first, then through `--compact-path` / `COMPACT_PATH`. The simplest recipe is a
**path import directly into the package**, which resolves transitively because
the modules live as siblings inside the package directory:

```compact
pragma language_version >= 0.22;

import CompactStandardLibrary;

//            K=11 msg fields  V=3 values  N=2 threshold  M=3 signatures
import "node_modules/@thoth/contracts/attestation"<11, 3, 2, 3> prefix A_;

import "node_modules/@thoth/contracts/attestor_registry"<3, 11> prefix R_;
```

If the package is hoisted elsewhere by your package manager, add the package
directory to the compact path instead and import by module name:

```bash
export COMPACT_PATH="$(node -p 'require.resolve("@thoth/contracts/package.json").replace(/package.json$/, "")')"
```

```compact
import "attestation"<11, 3, 2, 3> prefix A_;
import "attestor_registry"<3, 11> prefix R_;
```

See `examples/example_app.compact` for a complete top-level embedding that
pins registry keys and the freshness window in the constructor, re-exports the
module types/ledgers/pure circuits, and exports a `verifyAttestation` entry
point.

## Module parameters

`attestation<#K, #V, #N, #M>` — embed as `import "attestation"<K, V, N, M>`:

- `#K` — signed-message length in fields (`K` must equal `2*V + 5`)
- `#V` — number of claim value slots (`Claim.values: Vector<V, Uint<64>>`)
- `#N` — the app's N-of-M threshold
- `#M` — number of attestor signatures supplied / registry key slots

All are fixed when a contract embeds the module.

## The signed message (contract law)

`buildMessage` (`attestation.compact`) flattens a `Claim` into exactly
`Vector<K, Field>` fields, in this order:

```
[ version, kind, timestamp,
  degradeToTransient(nonce), degradeToTransient(evidenceHash),
  present[0] as Field, ..., present[N-1] as Field,
  values[0] as Field, ..., values[N-1] as Field ]
```

The attestor MUST reproduce this exact flat field vector to sign the same
message (same order, sizes, presence-flag semantics, and the two
`degradeToTransient` transforms). `present` is a `Vector<V, Boolean>`: one flag
per value slot; `present[i] = true` means `values[i]` was populated (its value
may still be `0`). The message length is `K = 5 + 2*V` (5 header fields, V
presence flags, V values) — fixed when a contract embeds the module.

## Design notes

- **The claim is the entire message.** Everything the contract inspects —
  freshness (`timestamp`), replay protection (`nonce`), source binding
  (`evidenceHash`), and kind/version — is inside the signed field vector.
  Kinds must not rely on un-signed side-channels: any data the contract needs
  has to be a field of the message the attestor signs.
- **Registry slots are positional.** `attestor_registry` verifies
  `signatures[i]` against `keys[i]` — a signature is valid *only* in the slot
  holding its signer's public key. The client therefore places each collected
  signature at the index equal to its attestor's registry slot order.

## Reading presence in-circuit

`present` is native `Vector<V, Boolean>`, so an app predicate over a vaulted
claim reads any slot directly:

```compact
const c = A_openClaim(id);
assert(c.present[0], "slot 0 must have been measured");
```

Because presence is part of the signed message, a claim whose `present[i]`
flag disagrees with an asserted predicate can never pass signature verification.

## Deploy wiring

Both `freshnessWindow` (Attestation) and `keys` (Registry) are **sealed** ledgers
set exactly once in the top-level constructor. See `examples/example_app.compact`
for the full wiring.

## Opening a vaulted claim

`attestation.openClaim(id): Claim` proves the caller owns a vaulted claim
(claimsVault membership + holder match + `persistentCommit(claim, commitRand)
== id`) and re-hydrates the `Claim` in-circuit. Apps compose predicates over the
returned `Claim` inside their own circuits — one open, read any subset of
`values[i]` (attestors signed the whole claim).

- **Never re-export `openClaim` as a top-level contract entry point.** Its
  return value is witness/ledger tainted; a top-level export would force a
  `disclose()` that publishes every value on-chain. Compose it in-circuit only.
- **Consumes no nullifier** — opening is repeatable. "Use once" rules (e.g. the
  same claim can mint a given badge at most once) are enforced by the **app's
  own state** (`Set`/`Counter`/map), not by claim nullification.
  Nonce replay (depositing the same attested fact twice) is already prevented by `verifyAttestation`.

## Notes / open questions

- Reusability across apps: the claim shape is positional (`values: Vector<N, Uint<64>>`)
  plus per-slot `present` flags. It is simple enough that any app can parse it, but the
  *meaning* of each slot is app-defined. There is no per-value tag in the signed
  message; the provider is identified by `kind`.

## Development

```bash
npm install                 # from the repo root (workspace)
npm test                    # compiles the mock (--skip-zk), runs vitest
npm run check               # biome + compact format
```

The package's own test suite uses the mock top-level embedding in
`test/mocks/MockAttestation.compact`; it exercises the modules and is not
shipped with the package.